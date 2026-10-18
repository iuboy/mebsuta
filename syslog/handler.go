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
	maxRetries             = 5
	writeTimeout           = 3 * time.Second
	dialerTimeout          = 5 * time.Second
	reconnectCheckInterval = 5 * time.Second // independent from RetryDelay, avoids excessive wake-ups
	maxHostnameLength      = 255
	defaultBufferSize      = 1000
	maxBufferSize          = 10000
	maxMsgSize             = 4 * 1024
	maxReconnectDelay      = 5 * time.Minute
	maxBackoffExp          = 20

	// RFC5424 structured-data budgets. The structured path builds SD directly
	// from record attrs (attrutil's count/size caps only apply to the JSON
	// path), so without these bounds a single attacker-controlled attr could
	// produce a multi-megabyte frame.
	maxSDParams     = 128       // max PARAMs per SD-ELEMENT
	maxSDNameLen    = 32        // RFC5424: SD-NAME is 1*32 PRINTUSASCII
	maxSDValueBytes = 4 * 1024  // per PARAM-VALUE
	maxSDBudget     = 32 * 1024 // total SD-ELEMENT bytes
	// sdTruncationMark is the reserved PARAM-NAME for the omission marker;
	// user params sanitizing to the same name are skipped (counted).
	sdTruncationMark = "_truncated"
	// rfc5424TimeLayout is RFC3339 with a fixed 6-digit fraction — RFC5424
	// TIME-SECFRAC allows at most 6 digits, RFC3339Nano emits up to 9 and
	// strict receivers reject the frame.
	rfc5424TimeLayout = "2006-01-02T15:04:05.000000Z07:00"

	// closeDrainTimeout bounds how long Close waits for the background queue
	// to flush buffered messages before cancelling and dropping the rest.
	// Without a bound, a black-holed peer (3s write timeout per message × a
	// 10000-message buffer) could stall Close for hours.
	closeDrainTimeout = 10 * time.Second

	// defaultFlushTimeout is used when Flush is called with timeout <= 0.
	defaultFlushTimeout = 5 * time.Second
)

var spaceRe = regexp.MustCompile(`\s+`)

// Handler writes log records to a syslog server with built-in buffering, TLS support, and automatic reconnection.
type Handler struct {
	leveler          slog.Leveler
	cfg              Config
	reconnectEnabled bool // resolved from cfg.Reconnect *bool during construction
	conn             net.Conn
	connMu           sync.RWMutex
	dialer           net.Dialer
	tlsCfg           *tls.Config
	hostname         string
	buffer           chan []byte
	sendMu           sync.RWMutex // RLock during buffer send; Lock during Close's close(buffer)
	flushCh          chan chan struct{}
	wg               sync.WaitGroup
	ctx              context.Context
	cancel           context.CancelFunc
	closing          atomic.Bool
	attrDropWarned   atomic.Bool // one-time warning for RFC3164 attr discarding
	dropped          atomic.Int64
	lastDropReport   atomic.Int64 // unix nanos of the last surfaced drop report
	location         *time.Location
	errorHandler     atomic.Pointer[mebsuta.ErrorHandler]
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
		mebsuta.ReportError(mebsuta.DefaultErrorHandler, &mebsuta.HandlerError{Component: "syslog", Operation: "init", Err: fmt.Errorf("invalid timezone %q, using UTC: %w", cfg.TimeZone, err)})
		loc = time.UTC
	}

	ctx, cancel := context.WithCancel(context.Background())

	h := &Handler{
		leveler:          cfg.Level,
		cfg:              cfg,
		reconnectEnabled: cfg.Reconnect != nil && *cfg.Reconnect,
		dialer:           net.Dialer{Timeout: dialerTimeout},
		hostname:         hostname,
		buffer:           make(chan []byte, bufferSize),
		flushCh:          make(chan chan struct{}),
		ctx:              ctx,
		cancel:           cancel,
		location:         loc,
	}
	eh := mebsuta.DefaultErrorHandler
	h.errorHandler.Store(&eh)

	if cfg.Secure {
		h.tlsCfg = &tls.Config{
			InsecureSkipVerify: cfg.TLSSkipVerify,
			MinVersion:         tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			},
		}
		if cfg.TLSSkipVerify {
			mebsuta.ReportError(mebsuta.DefaultErrorHandler, &mebsuta.HandlerError{Component: "syslog", Operation: "init", Err: fmt.Errorf("TLS certificate verification is disabled (InsecureSkipVerify=true) — connection is vulnerable to man-in-the-middle attacks")})
		}
	}

	if cfg.Network == "udp" {
		mebsuta.ReportError(mebsuta.DefaultErrorHandler, &mebsuta.HandlerError{Component: "syslog", Operation: "init", Err: fmt.Errorf("UDP transport sends logs in plaintext without delivery guarantees — consider using TCP with TLS for production use")})
	}

	if err := h.connect(); err != nil {
		cancel()
		return nil, fmt.Errorf("mebsuta/syslog: initial connection failed: %w", err)
	}

	h.wg.Add(1)
	go h.processQueue()

	return h, nil
}

// Enabled implements slog.Handler.
func (h *Handler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= mebsuta.SafeLevel(h.leveler)
}

// Handle implements slog.Handler.
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	if h.closing.Load() {
		return nil
	}

	entry := mebsuta.RecordToLogEntry(r)
	msg := h.formatMessage(entry)
	data := []byte(msg)
	return h.safeSend(data, r.Level)
}

// Close implements io.Closer.
//
// Drains the buffer for at most closeDrainTimeout: a black-holed peer makes
// each buffered message cost one 3s write timeout, so an unbounded drain
// could block Close (and thus process exit) for hours. On timeout the
// remaining messages are dropped and reported.
func (h *Handler) Close() error {
	if !h.closing.CompareAndSwap(false, true) {
		return nil
	}

	// sendMu (write lock around close) makes close-vs-send race-detector
	// clean: no in-flight safeSend can touch a closed channel.
	h.sendMu.Lock()
	close(h.buffer)
	h.sendMu.Unlock()

	drained := make(chan struct{})
	go func() {
		h.wg.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(closeDrainTimeout):
		remaining := len(h.buffer)
		h.cancel() // ctx gate in writeWithRetry makes remaining messages no-ops
		<-drained
		if remaining > 0 {
			h.dropped.Add(int64(remaining))
			mebsuta.ReportError(h.loadEH(), &mebsuta.HandlerError{Component: "syslog", Operation: "close", Err: fmt.Errorf("close drain timed out after %v: %d buffered records dropped", closeDrainTimeout, remaining), Dropped: int64(remaining)})
		}
	}
	h.cancel()

	h.connMu.Lock()
	if h.conn != nil {
		if err := h.conn.Close(); err != nil {
			mebsuta.ReportError(h.loadEH(), &mebsuta.HandlerError{Component: "syslog", Operation: "connect", Err: fmt.Errorf("close old connection in connect: %w", err)})
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
	if timeout <= 0 {
		timeout = defaultFlushTimeout
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
		case msg, ok := <-h.buffer:
			if !ok {
				return
			}
			h.writeWithRetry(msg)
		default:
			return
		}
	}
}

// WithAttrs implements slog.Handler.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &mebsuta.AttrsSub{Parent: h, Attrs: attrs}
}

// WithGroup implements slog.Handler.
func (h *Handler) WithGroup(name string) slog.Handler {
	return &mebsuta.GroupSub{Parent: h, Group: name}
}

func (h *Handler) setErrorHandler(fn mebsuta.ErrorHandler) {
	h.errorHandler.Store(&fn)
}

// SetErrorHandler updates the error handler at runtime. It implements
// mebsuta.ErrorHandlerSetter so WithErrorHandler propagates into this
// handler (the package-internal setErrorHandler alone is unreachable from
// another package).
// Dropped returns the total number of records dropped due to a full buffer
// (or during Close's bounded drain) — feeds mebsuta.DroppedCounter probes.
func (h *Handler) Dropped() int64 {
	return h.dropped.Load()
}

func (h *Handler) SetErrorHandler(fn mebsuta.ErrorHandler) {
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
			mebsuta.ReportError(h.loadEH(), &mebsuta.HandlerError{Component: "syslog", Operation: "connect", Err: fmt.Errorf("set keep-alive: %w", err)})
		} else if err := tc.SetKeepAlivePeriod(3 * time.Minute); err != nil {
			mebsuta.ReportError(h.loadEH(), &mebsuta.HandlerError{Component: "syslog", Operation: "connect", Err: fmt.Errorf("set keep-alive period: %w", err)})
		}
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
			mebsuta.ReportError(h.loadEH(), &mebsuta.HandlerError{Component: "syslog", Operation: "connect", Err: fmt.Errorf("close old connection in connect: %w", err)})
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
		mebsuta.ReportError(h.loadEH(), &mebsuta.HandlerError{Component: "syslog", Operation: "reconnect", Err: fmt.Errorf("reconnect failed: %w", err)})
		return
	}

	if h.conn != nil {
		if closeErr := h.conn.Close(); closeErr != nil {
			mebsuta.ReportError(h.loadEH(), &mebsuta.HandlerError{Component: "syslog", Operation: "reconnect", Err: fmt.Errorf("close old connection in reconnect: %w", closeErr)})
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
	// Context gate: once Close's drain deadline fired and cancelled the ctx,
	// skip remaining messages immediately instead of costing one 3s write
	// timeout each — that is what bounds the post-deadline drain.
	if h.ctx.Err() != nil {
		return
	}
	if !h.isConnected() && !h.closing.Load() && h.reconnectEnabled {
		h.reconnect()
	}
	for i := range maxRetries {
		if err := h.write(msg); err == nil {
			return
		}
		if h.closing.Load() {
			return
		}
		// Only disconnect + reconnect on the first failure. Subsequent retries
		// reuse the same connection to avoid thrashing on transient write errors
		// (e.g., a brief network hiccup that doesn't break the TCP session).
		if i == 0 {
			h.disconnect()
			if h.reconnectEnabled {
				h.reconnect()
			}
		}
		// Interruptible sleep: after Close's drain deadline cancels the ctx,
		// the in-flight retry must not sit out the full RetryDelay — that
		// would make the 10s Close bound soft by up to RetryDelay.
		select {
		case <-time.After(h.cfg.RetryDelay):
		case <-h.ctx.Done():
			return
		}
	}
	mebsuta.ReportError(h.loadEH(), &mebsuta.HandlerError{Component: "syslog", Operation: "write", Err: fmt.Errorf("write failed after %d attempts", maxRetries)})
}

func (h *Handler) disconnect() {
	h.connMu.Lock()
	defer h.connMu.Unlock()
	if h.conn != nil {
		if err := h.conn.Close(); err != nil {
			mebsuta.ReportError(h.loadEH(), &mebsuta.HandlerError{Component: "syslog", Operation: "connect", Err: fmt.Errorf("close old connection in connect: %w", err)})
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

	reconnector := time.NewTicker(reconnectCheckInterval)
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
			if !h.isConnected() && h.reconnectEnabled {
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
				// Re-check connection state before reconnecting to avoid TOCTOU race:
				// writeWithRetry may have already reconnected during the backoff delay.
				if !h.isConnected() {
					h.reconnect()
					retryCount.Add(1)
				} else {
					retryCount.Store(0)
				}
			} else {
				retryCount.Store(0)
			}

		case <-h.ctx.Done():
			return
		}
	}
}

// shouldReportDrop reports whether a drop should be surfaced now: at most one
// report per second, so a flood that overflows the buffer cannot amplify into
// one locked stderr write per dropped record. Callers always count the drop.
func (h *Handler) shouldReportDrop() bool {
	now := time.Now().UnixNano()
	last := h.lastDropReport.Load()
	if now-last < int64(time.Second) {
		return false
	}
	return h.lastDropReport.CompareAndSwap(last, now)
}

func (h *Handler) safeSend(data []byte, level slog.Level) error {
	// sendMu makes Close's close(buffer) race-free against in-flight sends
	// (same pattern as database.Handler; the recover guard is no longer
	// needed and was a -race DATA RACE even though the panic was caught).
	h.sendMu.RLock()
	defer h.sendMu.RUnlock()

	if h.closing.Load() {
		return fmt.Errorf("mebsuta/syslog: handler closed, log dropped")
	}

	if level >= slog.LevelError {
		select {
		case h.buffer <- data:
			return nil
		case <-time.After(h.cfg.ErrorTimeout):
			h.dropped.Add(1)
			if h.shouldReportDrop() {
				mebsuta.ReportError(h.loadEH(), &mebsuta.HandlerError{Component: "syslog", Operation: "write", Err: fmt.Errorf("buffer full timeout for %v record, dropped (total dropped: %d)", level, h.dropped.Load()), Dropped: h.dropped.Load()})
			}
			return fmt.Errorf("mebsuta/syslog: buffer full timeout for %v record", level)
		}
	}

	select {
	case h.buffer <- data:
		return nil
	default:
		h.dropped.Add(1)
		if h.shouldReportDrop() {
			mebsuta.ReportError(h.loadEH(), &mebsuta.HandlerError{Component: "syslog", Operation: "write", Err: fmt.Errorf("buffer full, log dropped (total dropped: %d)", h.dropped.Load()), Dropped: h.dropped.Load()})
		}
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
		mebsuta.ReportError(h.loadEH(), &mebsuta.HandlerError{Component: "syslog", Operation: "marshal", Err: fmt.Errorf("marshal log entry (msg=%q, level=%v): %w", entry.Message, entry.Level, err)})
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
			priority, ts.Format(rfc5424TimeLayout), host, h.cfg.Tag, procid, cleaned) + "\n"
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
		written, skipped := 0, 0
		if len(entry.Attrs) == 0 {
			sd.WriteByte('-')
		} else {
			sd.WriteString("[mebsuta")
			// RFC5424 §6.3.2 requires PARAM-NAMEs to be unique within an
			// SD-ELEMENT; sanitization can collide distinct keys ("a/b" and
			// "a_b" both become "a_b"), and strict receivers reject the whole
			// frame on duplicates. Deduplicate post-sanitization and count the
			// losers in the truncation marker.
			seen := make(map[string]struct{}, len(entry.Attrs))
			for _, attr := range entry.Attrs {
				name := sanitizeSDName(attr.Key)
				if name == "" || name == sdTruncationMark {
					// The truncation-marker name is reserved so the marker
					// itself can never collide with a user param.
					skipped++
					continue
				}
				if _, dup := seen[name]; dup {
					skipped++
					continue
				}
				seen[name] = struct{}{}
				// Enforce count and total-size budgets: the structured path
				// has no attrutil caps, and an unbounded attr (e.g. a raw
				// request body) would produce frames that fragment on UDP and
				// amplify memory on the receiver.
				if written >= maxSDParams || sd.Len() > maxSDBudget {
					skipped++
					continue
				}
				fmt.Fprintf(&sd, " %s=\"%s\"", name, escapeSDValue(truncateUTF8(attr.Value.String(), maxSDValueBytes)))
				written++
			}
			if skipped > 0 {
				fmt.Fprintf(&sd, " %s=\"%d params omitted\"", sdTruncationMark, skipped)
			}
			sd.WriteByte(']')
		}
		sdStr := sd.String()

		return fmt.Sprintf(`<%d>1 %s %s %s %d - %s %s`,
			priority, ts.Format(rfc5424TimeLayout), host, h.cfg.Tag, procid, sdStr, msgContent) + "\n"
	}

	// RFC3164 has no structured-data field: attrs are silently discarded.
	// Warn once so operators notice instead of assuming attrs were shipped.
	if len(entry.Attrs) > 0 && h.attrDropWarned.CompareAndSwap(false, true) {
		mebsuta.ReportError(h.loadEH(), &mebsuta.HandlerError{Component: "syslog", Operation: "format", Err: fmt.Errorf("RFC3164 non-JSON mode discards attributes (first occurrence; %d attrs on this record) — enable RFC5424 or JSONInMessage to preserve them", len(entry.Attrs))})
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
	return h.hostname // already cleaned and validated in generateHostname
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
		mebsuta.ReportError(mebsuta.DefaultErrorHandler, &mebsuta.HandlerError{Component: "syslog", Operation: "init", Err: fmt.Errorf("get hostname: %w", err)})
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

var builderPool = sync.Pool{
	New: func() any { return new(strings.Builder) },
}

// escapeSDValue escapes a PARAM-VALUE per RFC5424 (", \, ]) and — critically —
// replaces control characters with spaces. RFC5424 has no escape syntax for
// them, and a raw LF/CR inside SD-PARAM would terminate the frame early on
// LF-framed TCP transports, letting attacker-controlled attr values smuggle
// entire forged syslog messages (msg smuggling).
func escapeSDValue(s string) string {
	b := builderPool.Get().(*strings.Builder)
	defer func() {
		b.Reset()
		builderPool.Put(b)
	}()
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == ']':
			b.WriteString(`\]`)
		case r < 0x20 || r == 0x7f:
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// sanitizeSDName maps an attr key to a legal SD-NAME (PRINTUSASCII subset,
// capped at RFC5424's 32-character limit). Returns "" when the input has no
// usable characters; callers skip such params entirely — an empty SD-NAME
// would render an illegal ` ="value"` PARAM that strict receivers reject.
func sanitizeSDName(key string) string {
	b := builderPool.Get().(*strings.Builder)
	defer func() {
		b.Reset()
		builderPool.Put(b)
	}()
	b.Grow(min(len(key), maxSDNameLen))
	for _, r := range key {
		if b.Len() >= maxSDNameLen {
			break
		}
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

	// walkJSON tracks bracket depth and string state through a prefix of s,
	// returning the bracket stack and whether we ended inside a string.
	walkJSON := func(prefix string) (stack []byte, inStr bool) {
		escaped := false
		for i := 0; i < len(prefix); i++ {
			c := prefix[i]
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
		return
	}

	// First pass: truncate with a generous budget to estimate the suffix length.
	// We reserve at least 3 bytes for "..." plus closing quote and brackets.
	budget := maxBytes - 3
	if budget < 3 {
		budget = 3
	}
	truncated := s[:lastRuneBoundary(s, budget)]
	stack, inStr := walkJSON(truncated)

	// Build the suffix and measure its exact length.
	suffixLen := 3 // "..."
	if inStr {
		suffixLen++ // closing '"'
	}
	suffixLen += len(stack) // closing brackets

	// Second pass: precise truncation using exact suffix length.
	// Loop in case the new truncation point changes the bracket state
	// (which can only shrink the required suffix).
	for {
		preciseBudget := maxBytes - suffixLen
		if preciseBudget < 0 {
			preciseBudget = 0
		}
		truncated = s[:lastRuneBoundary(s, preciseBudget)]
		stack, inStr = walkJSON(truncated)

		newSuffixLen := 3
		if inStr {
			newSuffixLen++
		}
		newSuffixLen += len(stack)
		if newSuffixLen <= suffixLen {
			// Suffix has stabilized (can only shrink). Break without
			// reassigning suffixLen — it's not read after the loop.
			break
		}
		suffixLen = newSuffixLen
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
	return truncated + suffix.String()
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
