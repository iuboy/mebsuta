package syslog

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/attrutil"
)

const (
	maxRetries        = 5
	writeTimeout      = 3 * time.Second
	dialerTimeout     = 5 * time.Second
	maxHostnameLength = 255
	defaultBufferSize = 1000
	maxBufferSize     = 10000
	maxMsgSize        = 4 * 1024
	maxReconnectDelay = 5 * time.Minute
	maxBackoffExp     = 20
)

var spaceRe = regexp.MustCompile(`\s+`)

// Handler writes log records to a syslog server with built-in buffering, TLS support, and automatic reconnection.
type Handler struct {
	leveler      slog.Leveler
	cfg          Config
	conn         net.Conn
	connMu       sync.RWMutex
	dialer       net.Dialer
	tlsCfg       *tls.Config
	hostname     string
	buffer       chan []byte
	flushCh      chan chan struct{}
	wg           sync.WaitGroup
	ctx          context.Context
	cancel       context.CancelFunc
	closing      atomic.Bool
	location     *time.Location
	errorHandler atomic.Pointer[mebsuta.ErrorHandler]
}

// NewHandler creates a Handler that connects to the syslog server specified in cfg.
func NewHandler(cfg Config) (*Handler, error) {
	cfg, err := cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("mebsuta/syslog: %w", err)
	}
	bufferSize := cfg.BufferSize
	if bufferSize <= 0 {
		bufferSize = defaultBufferSize
	} else if bufferSize > maxBufferSize {
		bufferSize = maxBufferSize
	}

	hostname, err := generateHostname(cfg.StaticHost)
	if err != nil {
		return nil, fmt.Errorf("mebsuta/syslog: %w", err)
	}

	loc, err := time.LoadLocation(cfg.TimeZone)
	if err != nil {
		mebsuta.ReportError(mebsuta.DefaultErrorHandler, mebsuta.HandlerError{Component: "syslog", Operation: "init", Err: fmt.Errorf("invalid timezone %q, using UTC: %w", cfg.TimeZone, err)})
		loc = time.UTC
	}

	ctx, cancel := context.WithCancel(context.Background())

	h := &Handler{
		leveler:  cfg.Level,
		cfg:      cfg,
		dialer:   net.Dialer{Timeout: dialerTimeout},
		hostname: hostname,
		buffer:   make(chan []byte, bufferSize),
		flushCh:  make(chan chan struct{}),
		ctx:      ctx,
		cancel:   cancel,
		location: loc,
	}
	eh := mebsuta.DefaultErrorHandler
	h.errorHandler.Store(&eh)

	if cfg.Secure {
		h.tlsCfg = &tls.Config{
			InsecureSkipVerify: cfg.TLSSkipVerify,
			MinVersion:         tls.VersionTLS12,
		}
	}

	if err := h.connect(); err != nil {
		cancel()
		return nil, fmt.Errorf("mebsuta/syslog: initial connection failed: %w", err)
	}

	h.wg.Add(1)
	go h.processQueue()

	return h, nil
}

func (h *Handler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.leveler.Level()
}

func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	if h.closing.Load() {
		return nil
	}

	entry := mebsuta.RecordToLogEntry(r)
	msg := h.formatMessage(entry)
	data := []byte(msg)
	return h.safeSend(data, r.Level)
}

func (h *Handler) Close() error {
	if !h.closing.CompareAndSwap(false, true) {
		return nil
	}

	close(h.buffer)
	h.wg.Wait()
	h.cancel()

	h.connMu.Lock()
	if h.conn != nil {
		if err := h.conn.Close(); err != nil {
			mebsuta.ReportError(h.loadEH(), mebsuta.HandlerError{Component: "syslog", Operation: "connect", Err: fmt.Errorf("close old connection in connect: %w", err)})
		}
		h.conn = nil
	}
	h.connMu.Unlock()

	return nil
}

// Flush drains all buffered messages without closing the connection.
func (h *Handler) Flush(timeout time.Duration) error {
	if h.closing.Load() {
		return nil
	}
	done := make(chan struct{})
	select {
	case h.flushCh <- done:
	case <-time.After(timeout):
		return fmt.Errorf("mebsuta/syslog: flush timeout")
	}
	select {
	case <-done:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("mebsuta/syslog: flush timeout")
	}
}

func (h *Handler) drainBuffer() {
	for {
		select {
		case msg := <-h.buffer:
			h.writeWithRetry(msg)
		default:
			return
		}
	}
}

func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &mebsuta.AttrsSub[*Handler]{Parent: h, Attrs: attrs}
}

func (h *Handler) WithGroup(name string) slog.Handler {
	return &mebsuta.GroupSub[*Handler]{Parent: h, Group: name}
}

func (h *Handler) setErrorHandler(fn mebsuta.ErrorHandler) {
	h.errorHandler.Store(&fn)
}

func (h *Handler) loadEH() mebsuta.ErrorHandler {
	v := h.errorHandler.Load()
	if v == nil {
		return nil
	}
	return *v
}

func (h *Handler) dialLocked() (net.Conn, error) {
	var conn net.Conn
	var err error
	if h.tlsCfg != nil {
		conn, err = tls.DialWithDialer(&h.dialer, h.cfg.Network, h.cfg.Address, h.tlsCfg)
	} else {
		conn, err = h.dialer.Dial(h.cfg.Network, h.cfg.Address)
	}
	if err != nil {
		return nil, err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		if err := tc.SetKeepAlive(true); err != nil {
			conn.Close()
			return nil, fmt.Errorf("set keep-alive: %w", err)
		}
		_ = tc.SetKeepAlivePeriod(3 * time.Minute)
	}
	return conn, nil
}

func (h *Handler) connect() error {
	h.connMu.Lock()
	defer h.connMu.Unlock()

	conn, err := h.dialLocked()
	if err != nil {
		return err
	}

	if h.conn != nil {
		if err := h.conn.Close(); err != nil {
			mebsuta.ReportError(h.loadEH(), mebsuta.HandlerError{Component: "syslog", Operation: "connect", Err: fmt.Errorf("close old connection in connect: %w", err)})
		}
	}
	h.conn = conn
	return nil
}

func (h *Handler) reconnect() {
	h.connMu.Lock()
	defer h.connMu.Unlock()
	if h.closing.Load() {
		return
	}

	conn, err := h.dialLocked()
	if err != nil {
		mebsuta.ReportError(h.loadEH(), mebsuta.HandlerError{Component: "syslog", Operation: "reconnect", Err: fmt.Errorf("reconnect failed: %w", err)})
		return
	}

	if h.conn != nil {
		if closeErr := h.conn.Close(); closeErr != nil {
			mebsuta.ReportError(h.loadEH(), mebsuta.HandlerError{Component: "syslog", Operation: "reconnect", Err: fmt.Errorf("close old connection in reconnect: %w", closeErr)})
		}
	}
	h.conn = conn
}

func (h *Handler) isConnected() bool {
	h.connMu.RLock()
	defer h.connMu.RUnlock()
	return h.conn != nil
}

func (h *Handler) write(p []byte) error {
	h.connMu.RLock()
	defer h.connMu.RUnlock()
	if h.conn == nil {
		return net.ErrClosed
	}
	if err := h.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	_, err := h.conn.Write(p)
	return err
}

func (h *Handler) writeWithRetry(msg []byte) {
	if !h.isConnected() && !h.closing.Load() {
		h.reconnect()
	}
	for i := range maxRetries {
		if err := h.write(msg); err == nil {
			return
		}
		if h.closing.Load() {
			return
		}
		if i == 0 {
			h.disconnect()
			h.reconnect()
		}
		time.Sleep(h.cfg.RetryDelay)
	}
	mebsuta.ReportError(h.loadEH(), mebsuta.HandlerError{Component: "syslog", Operation: "write", Err: fmt.Errorf("write failed after %d attempts", maxRetries)})
}

func (h *Handler) disconnect() {
	h.connMu.Lock()
	defer h.connMu.Unlock()
	if h.conn != nil {
		if err := h.conn.Close(); err != nil {
			mebsuta.ReportError(h.loadEH(), mebsuta.HandlerError{Component: "syslog", Operation: "connect", Err: fmt.Errorf("close old connection in connect: %w", err)})
		}
		h.conn = nil
	}
}

func backoffDelay(retries int32) time.Duration {
	r := retries
	if r > maxBackoffExp {
		r = maxBackoffExp
	}
	base := time.Second << min(r, 30)
	base = min(base, maxReconnectDelay)
	jitter := time.Duration(rand.Int64N(int64(base) / 2))
	return base/2 + jitter
}

func (h *Handler) processQueue() {
	defer h.wg.Done()

	reconnector := time.NewTicker(h.cfg.RetryDelay)
	defer reconnector.Stop()

	var retryCount atomic.Int32

	for {
		select {
		case msg, ok := <-h.buffer:
			if !ok {
				return
			}
			h.writeWithRetry(msg)

		case done := <-h.flushCh:
			h.drainBuffer()
			close(done)

		case <-reconnector.C:
			if !h.isConnected() {
				delay := backoffDelay(retryCount.Load())
				select {
				case <-time.After(delay):
				case <-h.ctx.Done():
					return
				case msg, ok := <-h.buffer:
					if !ok {
						return
					}
					h.writeWithRetry(msg)
					continue
				}
				h.reconnect()
				retryCount.Add(1)
			} else {
				retryCount.Store(0)
			}

		case <-h.ctx.Done():
			return
		}
	}
}

func (h *Handler) safeSend(data []byte, level slog.Level) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("mebsuta/syslog: handler closed, log dropped")
		}
	}()

	if level >= slog.LevelError {
		select {
		case h.buffer <- data:
			return nil
		case <-time.After(5 * time.Second):
			mebsuta.ReportError(h.loadEH(), mebsuta.HandlerError{Component: "syslog", Operation: "write", Err: fmt.Errorf("buffer full timeout for %v record, dropped", level)})
			return fmt.Errorf("mebsuta/syslog: buffer full timeout for %v record", level)
		}
	}

	select {
	case h.buffer <- data:
		return nil
	default:
		mebsuta.ReportError(h.loadEH(), mebsuta.HandlerError{Component: "syslog", Operation: "write", Err: fmt.Errorf("buffer full, log dropped")})
		return fmt.Errorf("mebsuta/syslog: buffer full")
	}
}

func (h *Handler) formatMessage(entry mebsuta.LogEntry) string {
	timestamp := entry.Time.In(h.location)
	severity := h.levelToSeverity(entry.Level)
	priority := h.cfg.Facility*8 + severity
	procid := os.Getpid()
	host := h.getCleanHost()

	if h.cfg.JSONInMessage {
		return h.formatJSONMessage(entry, timestamp, priority, host, procid)
	}
	return h.formatStructuredMessage(entry, timestamp, priority, host, procid)
}

func (h *Handler) formatJSONMessage(entry mebsuta.LogEntry, ts time.Time, priority int, host string, procid int) string {
	attributes := make(map[string]any)
	for _, attr := range entry.Attrs {
		attrutil.FlattenAttr(attributes, "", attr, attrutil.NaNSafe)
	}
	level := entry.Level.String()
	if entry.Level == mebsuta.LevelAudit {
		level = "AUDIT"
	}
	logData := map[string]any{
		"time":       ts.Format(time.RFC3339Nano),
		"level":      level,
		"message":    entry.Message,
		"attributes": attributes,
	}

	jsonBytes, err := json.Marshal(logData)
	if err != nil {
		mebsuta.ReportError(h.loadEH(), mebsuta.HandlerError{Component: "syslog", Operation: "marshal", Err: fmt.Errorf("marshal log entry (msg=%q, level=%v): %w", entry.Message, entry.Level, err)})
		safeData := map[string]any{
			"time":       logData["time"],
			"level":      logData["level"],
			"message":    entry.Message,
			"attributes": map[string]any{"_error": "field marshaling failed"},
		}
		jsonBytes, _ = json.Marshal(safeData)
	}
	cleaned := string(jsonBytes)
	if len(cleaned) > maxMsgSize {
		cleaned = truncateJSON(cleaned, maxMsgSize)
	}

	if h.cfg.RFC5424 {
		return fmt.Sprintf(`<%d>1 %s %s %s %d - - %s`,
			priority, ts.Format(time.RFC3339Nano), host, h.cfg.Tag, procid, cleaned) + "\n"
	}
	return fmt.Sprintf(`<%d>%s %s %s[%d]: %s`,
		priority, ts.Format("Jan _2 15:04:05"), host, h.cfg.Tag, procid, cleaned) + "\n"
}

func (h *Handler) formatStructuredMessage(entry mebsuta.LogEntry, ts time.Time, priority int, host string, procid int) string {
	msgContent := safeMessageForLog(entry.Message)
	if len(msgContent) > maxMsgSize {
		msgContent = truncateUTF8(msgContent, maxMsgSize)
	}

	if h.cfg.RFC5424 {
		var sd strings.Builder
		if len(entry.Attrs) == 0 {
			sd.WriteByte('-')
		} else {
			sd.WriteString("[mebsuta")
			for _, attr := range entry.Attrs {
				fmt.Fprintf(&sd, " %s=\"%s\"", sanitizeSDName(attr.Key), escapeSDValue(attr.Value.String()))
			}
			sd.WriteByte(']')
		}
		sdStr := sd.String()

		return fmt.Sprintf(`<%d>1 %s %s %s %d - %s %s`,
			priority, ts.Format(time.RFC3339Nano), host, h.cfg.Tag, procid, sdStr, msgContent) + "\n"
	}

	return fmt.Sprintf(`<%d>%s %s %s[%d]: %s`,
		priority, ts.Format("Jan _2 15:04:05"), host, h.cfg.Tag, procid, msgContent) + "\n"
}

func (h *Handler) levelToSeverity(level slog.Level) int {
	switch {
	case level >= mebsuta.LevelAudit:
		return 2
	case level >= slog.LevelError:
		return 3
	case level >= slog.LevelWarn:
		return 4
	case level >= slog.LevelInfo:
		return 6
	default:
		return 7
	}
}

func (h *Handler) getCleanHost() string {
	host := cleanHostname(h.hostname)
	if host == "" {
		return "localhost"
	}
	return host
}

func generateHostname(static string) (string, error) {
	if static != "" {
		static = strings.TrimSpace(static)
		static = cleanHostname(static)
		if static == "" {
			return "", fmt.Errorf("invalid static hostname")
		}
		if len(static) > maxHostnameLength {
			static = static[:maxHostnameLength]
		}
		return static, nil
	}
	hostname, err := os.Hostname()
	if err != nil {
		mebsuta.ReportError(mebsuta.DefaultErrorHandler, mebsuta.HandlerError{Component: "syslog", Operation: "init", Err: fmt.Errorf("get hostname: %w", err)})
		return "unknown", nil
	}
	hostname = cleanHostname(hostname)
	if hostname == "" {
		return "localhost", nil
	}
	if len(hostname) > maxHostnameLength {
		hostname = hostname[:maxHostnameLength]
	}
	return hostname, nil
}

func cleanHostname(hostname string) string {
	var clean strings.Builder
	for _, r := range hostname {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.':
			clean.WriteRune(r)
		default:
			clean.WriteRune('-')
		}
	}
	if ip := net.ParseIP(clean.String()); ip != nil {
		return ip.String()
	}
	return clean.String()
}

func escapeSDValue(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case ']':
			b.WriteString(`\]`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func sanitizeSDName(key string) string {
	var b strings.Builder
	b.Grow(len(key))
	for _, r := range key {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

func safeMessageForLog(msg string) string {
	cleaned := strings.Map(func(r rune) rune {
		if r >= 0 && r <= 31 {
			return ' '
		}
		return r
	}, msg)
	return strings.TrimSpace(spaceRe.ReplaceAllString(cleaned, " "))
}

func truncateJSON(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	budget := maxBytes - 13
	if budget < 10 {
		budget = 10
	}
	truncated := s[:lastRuneBoundary(s, budget)]

	var stack []byte
	inStr := false
	escaped := false
	for i := 0; i < len(truncated); i++ {
		c := truncated[i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' && inStr {
			escaped = true
			continue
		}
		if c == '"' {
			inStr = !inStr
			continue
		}
		if inStr {
			continue
		}
		switch c {
		case '{', '[':
			stack = append(stack, c)
		case '}':
			if len(stack) > 0 && stack[len(stack)-1] == '{' {
				stack = stack[:len(stack)-1]
			}
		case ']':
			if len(stack) > 0 && stack[len(stack)-1] == '[' {
				stack = stack[:len(stack)-1]
			}
		}
	}

	var suffix strings.Builder
	suffix.WriteString("...")
	if inStr {
		suffix.WriteByte('"')
	}
	for i := len(stack) - 1; i >= 0; i-- {
		if stack[i] == '{' {
			suffix.WriteByte('}')
		} else {
			suffix.WriteByte(']')
		}
	}
	result := truncated + suffix.String()
	if len(result) > maxBytes {
		result = truncateUTF8(result, maxBytes)
	}
	return result
}

func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	if maxBytes <= 0 {
		return ""
	}
	if maxBytes < 4 {
		return s[:lastRuneBoundary(s, maxBytes)]
	}
	limit := maxBytes - 3
	return s[:lastRuneBoundary(s, limit)] + "..."
}

func lastRuneBoundary(s string, n int) int {
	if n <= 0 {
		return 0
	}
	if n >= len(s) {
		return len(s)
	}
	for n > 0 && (s[n]&0xC0) == 0x80 {
		n--
	}
	return n
}

// SelfBuffered marks Handler as having built-in async buffering.
func (*Handler) SelfBuffered() {}

var (
	_ slog.Handler                = (*Handler)(nil)
	_ io.Closer                   = (*Handler)(nil)
	_ mebsuta.SelfBufferedHandler = (*Handler)(nil)
)
