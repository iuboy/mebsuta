package mebsuta

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

	"github.com/iuboy/mebsuta/go/config"
)

const (
	maxSyslogRetries        = 5
	syslogWriteTimeout      = 3 * time.Second
	syslogDialerTimeout     = 5 * time.Second
	maxSyslogHostnameLength = 255
	defaultSyslogBufferSize = 1000
	maxSyslogBufferSize     = 10000
	maxSyslogMsgSize        = 4 * 1024
	maxReconnectDelay       = 5 * time.Minute
	maxBackoffExponent      = 20
)

var spaceRe = regexp.MustCompile(`\s+`)

// SyslogHandler writes log records to a syslog server with built-in buffering, TLS support, and automatic reconnection.
type SyslogHandler struct {
	LevelHandler
	cfg          *config.SyslogConfig
	conn         net.Conn
	connMu       sync.RWMutex
	dialer       net.Dialer
	tlsCfg       *tls.Config
	hostname     string
	buffer       chan []byte
	wg           sync.WaitGroup
	ctx          context.Context
	cancel       context.CancelFunc
	closing      atomic.Bool
	location     *time.Location
	errorHandler atomic.Pointer[ErrorHandler]
}

// NewSyslogHandler creates a SyslogHandler that connects to the syslog server specified in cfg at the given log level.
func NewSyslogHandler(cfg *config.SyslogConfig, level slog.Level) (*SyslogHandler, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("mebsuta: %w", err)
	}
	bufferSize := cfg.BufferSize()
	if bufferSize <= 0 {
		bufferSize = defaultSyslogBufferSize
	} else if bufferSize > maxSyslogBufferSize {
		bufferSize = maxSyslogBufferSize
	}

	hostname, err := generateHostname(cfg.StaticHost())
	if err != nil {
		return nil, fmt.Errorf("mebsuta: %w", err)
	}

	loc, err := time.LoadLocation(cfg.TimeZone())
	if err != nil {
		ReportError(DefaultErrorHandler, "syslog", fmt.Errorf("invalid timezone %q, using UTC: %w", cfg.TimeZone(), err))
		loc = time.UTC
	}

	ctx, cancel := context.WithCancel(context.Background())

	h := &SyslogHandler{
		LevelHandler: LevelHandler{Level: level},
		cfg:          cfg,
		dialer:       net.Dialer{Timeout: syslogDialerTimeout},
		hostname:     hostname,
		buffer:       make(chan []byte, bufferSize),
		ctx:          ctx,
		cancel:       cancel,
		location:     loc,
	}
	eh := DefaultErrorHandler
	h.errorHandler.Store(&eh)

	if cfg.Secure() {
		h.tlsCfg = &tls.Config{
			InsecureSkipVerify: cfg.TLSSkipVerify(),
			MinVersion:         tls.VersionTLS12,
		}
	}

	if err := h.connect(); err != nil {
		cancel()
		return nil, fmt.Errorf("mebsuta: syslog initial connection failed: %w", err)
	}

	h.wg.Add(1)
	go h.processQueue()

	return h, nil
}

func (h *SyslogHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.closing.Load() {
		return nil
	}

	entry := RecordToLogEntry(r)
	msg := h.formatMessage(entry)
	data := []byte(msg)
	return h.safeSend(data, r.Level)
}

func (h *SyslogHandler) Close() error {
	if !h.closing.CompareAndSwap(false, true) {
		return nil
	}

	close(h.buffer)
	h.wg.Wait()
	h.cancel()

	h.connMu.Lock()
	if h.conn != nil {
		if err := h.conn.Close(); err != nil {
			ReportError(loadErrorHandler(&h.errorHandler), "syslog", fmt.Errorf("close old connection in connect: %w", err))
		}
		h.conn = nil
	}
	h.connMu.Unlock()

	return nil
}

func (h *SyslogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &AttrsSub[*SyslogHandler]{Parent: h, Attrs: attrs}
}

func (h *SyslogHandler) WithGroup(name string) slog.Handler {
	return &GroupSub[*SyslogHandler]{Parent: h, Group: name}
}

func (h *SyslogHandler) setErrorHandler(fn ErrorHandler) {
	h.errorHandler.Store(&fn)
}

func (h *SyslogHandler) dialLocked() (net.Conn, error) {
	var conn net.Conn
	var err error
	if h.tlsCfg != nil {
		conn, err = tls.DialWithDialer(&h.dialer, h.cfg.Network(), h.cfg.Address(), h.tlsCfg)
	} else {
		conn, err = h.dialer.Dial(h.cfg.Network(), h.cfg.Address())
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

func (h *SyslogHandler) connect() error {
	h.connMu.Lock()
	defer h.connMu.Unlock()

	conn, err := h.dialLocked()
	if err != nil {
		return err
	}

	if h.conn != nil {
		if err := h.conn.Close(); err != nil {
			ReportError(loadErrorHandler(&h.errorHandler), "syslog", fmt.Errorf("close old connection in connect: %w", err))
		}
	}
	h.conn = conn
	return nil
}

func (h *SyslogHandler) reconnect() {
	h.connMu.Lock()
	defer h.connMu.Unlock()
	if h.closing.Load() {
		return
	}

	conn, err := h.dialLocked()
	if err != nil {
		ReportError(loadErrorHandler(&h.errorHandler), "syslog", fmt.Errorf("reconnect failed: %w", err))
		return
	}

	if h.conn != nil {
		if closeErr := h.conn.Close(); closeErr != nil {
			ReportError(loadErrorHandler(&h.errorHandler), "syslog", fmt.Errorf("close old connection in reconnect: %w", closeErr))
		}
	}
	h.conn = conn
}

func (h *SyslogHandler) isConnected() bool {
	h.connMu.RLock()
	defer h.connMu.RUnlock()
	return h.conn != nil
}

func (h *SyslogHandler) write(p []byte) error {
	h.connMu.RLock()
	defer h.connMu.RUnlock()
	if h.conn == nil {
		return net.ErrClosed
	}
	if err := h.conn.SetWriteDeadline(time.Now().Add(syslogWriteTimeout)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	_, err := h.conn.Write(p)
	return err
}

func (h *SyslogHandler) writeWithRetry(msg []byte) {
	if !h.isConnected() && !h.closing.Load() {
		h.reconnect()
	}
	for i := range maxSyslogRetries {
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
		time.Sleep(h.cfg.RetryDelay())
	}
	ReportError(loadErrorHandler(&h.errorHandler), "syslog", fmt.Errorf("write failed after %d attempts", maxSyslogRetries))
}

func (h *SyslogHandler) disconnect() {
	h.connMu.Lock()
	defer h.connMu.Unlock()
	if h.conn != nil {
		if err := h.conn.Close(); err != nil {
			ReportError(loadErrorHandler(&h.errorHandler), "syslog", fmt.Errorf("close old connection in connect: %w", err))
		}
		h.conn = nil
	}
}

// backoffDelay 计算指数退避延迟（带抖动）。
func backoffDelay(retries int32) time.Duration {
	r := retries
	if r > maxBackoffExponent {
		r = maxBackoffExponent
	}
	base := time.Second << min(r, 30)
	base = min(base, maxReconnectDelay)
	jitter := time.Duration(rand.Int64N(int64(base) / 2))
	return base/2 + jitter
}

func (h *SyslogHandler) processQueue() {
	defer h.wg.Done()

	reconnector := time.NewTicker(h.cfg.RetryDelay())
	defer reconnector.Stop()

	var retryCount atomic.Int32

	for {
		select {
		case msg, ok := <-h.buffer:
			if !ok {
				return
			}
			h.writeWithRetry(msg)

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

func (h *SyslogHandler) safeSend(data []byte, level slog.Level) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("mebsuta/syslog: handler closed, log dropped")
		}
	}()

	// Error and Audit records: blocking send with 5s timeout, never silently dropped.
	if level >= slog.LevelError {
		select {
		case h.buffer <- data:
			return nil
		case <-time.After(5 * time.Second):
			ReportError(loadErrorHandler(&h.errorHandler), "syslog",
				fmt.Errorf("buffer full timeout for %v record, dropped", level))
			return fmt.Errorf("mebsuta/syslog: buffer full timeout for %v record", level)
		}
	}

	select {
	case h.buffer <- data:
		return nil
	default:
		ReportError(loadErrorHandler(&h.errorHandler), "syslog",
			fmt.Errorf("buffer full, log dropped"))
		return fmt.Errorf("mebsuta/syslog: buffer full")
	}
}

func (h *SyslogHandler) formatMessage(entry LogEntry) string {
	timestamp := entry.Time.In(h.location)
	severity := h.levelToSeverity(entry.Level)
	priority := h.cfg.Facility()*8 + severity
	procid := os.Getpid()
	host := h.getCleanHost()

	if h.cfg.JSONInMessage() {
		return h.formatJSONMessage(entry, timestamp, priority, host, procid)
	}
	return h.formatStructuredMessage(entry, timestamp, priority, host, procid)
}

func (h *SyslogHandler) formatJSONMessage(entry LogEntry, ts time.Time, priority int, host string, procid int) string {
	attributes := make(map[string]any)
	for _, attr := range entry.Attrs {
		flattenAttr(attributes, "", attr)
	}
	level := entry.Level.String()
	if entry.Level == LevelAudit {
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
		ReportError(loadErrorHandler(&h.errorHandler), "syslog", fmt.Errorf("marshal log entry (msg=%q, level=%v): %w", entry.Message, entry.Level, err))
		// 保留原始消息和级别，丢弃无法序列化的字段
		safeData := map[string]any{
			"time":       logData["time"],
			"level":      logData["level"],
			"message":    entry.Message,
			"attributes": map[string]any{"_error": "field marshaling failed"},
		}
		jsonBytes, _ = json.Marshal(safeData)
	}
	cleaned := string(jsonBytes)
	if len(cleaned) > maxSyslogMsgSize {
		cleaned = truncateJSON(cleaned, maxSyslogMsgSize)
	}

	if h.cfg.RFC5424() {
		return fmt.Sprintf(`<%d>1 %s %s %s %d - - %s`,
			priority, ts.Format(time.RFC3339Nano), host, h.cfg.Tag(), procid, cleaned) + "\n"
	}
	return fmt.Sprintf(`<%d>%s %s %s[%d]: %s`,
		priority, ts.Format("Jan _2 15:04:05"), host, h.cfg.Tag(), procid, cleaned) + "\n"
}

func (h *SyslogHandler) formatStructuredMessage(entry LogEntry, ts time.Time, priority int, host string, procid int) string {
	msgContent := safeMessageForLog(entry.Message)
	if len(msgContent) > maxSyslogMsgSize {
		msgContent = truncateUTF8(msgContent, maxSyslogMsgSize)
	}

	if h.cfg.RFC5424() {
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
			priority, ts.Format(time.RFC3339Nano), host, h.cfg.Tag(), procid, sdStr, msgContent) + "\n"
	}

	return fmt.Sprintf(`<%d>%s %s %s[%d]: %s`,
		priority, ts.Format("Jan _2 15:04:05"), host, h.cfg.Tag(), procid, msgContent) + "\n"
}

func (h *SyslogHandler) levelToSeverity(level slog.Level) int {
	switch {
	case level >= LevelAudit:
		return 2 // CRITICAL — audit/compliance records
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

func (h *SyslogHandler) getCleanHost() string {
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
		if len(static) > maxSyslogHostnameLength {
			static = static[:maxSyslogHostnameLength]
		}
		return static, nil
	}
	hostname, err := os.Hostname()
	if err != nil {
		ReportError(DefaultErrorHandler, "syslog", fmt.Errorf("get hostname: %w", err))
		return "unknown", nil
	}
	hostname = cleanHostname(hostname)
	if hostname == "" {
		return "localhost", nil
	}
	if len(hostname) > maxSyslogHostnameLength {
		hostname = hostname[:maxSyslogHostnameLength]
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

// sanitizeSDName replaces characters invalid in RFC5424 structured-data
// parameter names (only printable ASCII 33-126 except '=', ']', '"', space)
// with underscores.
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

// truncateJSON truncates a JSON string to at most maxBytes bytes while keeping
// it valid JSON. It truncates at a UTF-8 boundary and appends "..." plus the
// necessary closing braces/brackets/quotes to keep the document parseable.
func truncateJSON(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	// Reserve space for "..." + closing chars (up to 10: `..."}]}`  etc.)
	budget := maxBytes - 13 // "..." + up to 10 closing chars
	if budget < 10 {
		budget = 10
	}
	truncated := s[:lastRuneBoundary(s, budget)]

	// Count unclosed braces and brackets
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
	// Close in reverse order
	for i := len(stack) - 1; i >= 0; i-- {
		if stack[i] == '{' {
			suffix.WriteByte('}')
		} else {
			suffix.WriteByte(']')
		}
	}
	result := truncated + suffix.String()
	// Final safety: if still too long, hard truncate with UTF-8 safety
	if len(result) > maxBytes {
		result = truncateUTF8(result, maxBytes)
	}
	return result
}

// truncateUTF8 safely truncates s to at most maxBytes bytes, never splitting
// a multi-byte UTF-8 sequence. If truncation occurs, "..." is appended
// (within the maxBytes budget). If maxBytes < 4, no ellipsis is added.
// The result is guaranteed to be valid UTF-8.
func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	if maxBytes <= 0 {
		return ""
	}
	if maxBytes < 4 {
		// Not enough room for ellipsis; truncate to the last valid rune boundary.
		return s[:lastRuneBoundary(s, maxBytes)]
	}
	limit := maxBytes - 3
	return s[:lastRuneBoundary(s, limit)] + "..."
}

// lastRuneBoundary returns the largest byte index <= n that falls on a UTF-8
// rune boundary, ensuring s[:result] is valid UTF-8.
func lastRuneBoundary(s string, n int) int {
	if n <= 0 {
		return 0
	}
	if n >= len(s) {
		return len(s)
	}
	// Walk backward from n to find a valid rune start.
	// A valid start byte has the two high bits not equal to 0b10 (continuation).
	for n > 0 && (s[n]&0xC0) == 0x80 {
		n--
	}
	return n
}

// SelfBuffered marks SyslogHandler as having built-in async buffering.
func (*SyslogHandler) SelfBuffered() {}

var (
	_ slog.Handler        = (*SyslogHandler)(nil)
	_ io.Closer           = (*SyslogHandler)(nil)
	_ SelfBufferedHandler = (*SyslogHandler)(nil)
)
