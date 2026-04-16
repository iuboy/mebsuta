package mebsuta

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofrs/flock"
	"github.com/iuboy/mebsuta/config"
)

// =============================================================================
// SyslogHandler — syslog 输出 slog.Handler
// =============================================================================

const (
	maxSyslogRetries        = 5
	syslogWriteTimeout      = 3 * time.Second
	syslogDialerTimeout     = 5 * time.Second
	maxSyslogHostnameLength = 255
	defaultSyslogBufferSize = 1000
	maxSyslogBufferSize     = 10000
	maxSyslogMsgSize        = 4 * 1024
	maxReconnectDelay       = 5 * time.Minute
)

var spaceRe = regexp.MustCompile(`\s+`)

// SyslogHandler 将日志记录输出到 syslog 服务器。
// 实现 slog.Handler 和 io.Closer 接口。
// 内置缓冲写入、TLS、自动重连。
type SyslogHandler struct {
	LevelHandler
	cfg          config.SyslogConfig
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
	closed       atomic.Bool
	fileLock     *flock.Flock
	location     *time.Location
	errorHandler atomic.Pointer[ErrorHandler]
}

// NewSyslogHandler 创建输出到 syslog 的 slog.Handler。
func NewSyslogHandler(cfg config.SyslogConfig, level slog.Level) (*SyslogHandler, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("mebsuta: %w", err)
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = defaultSyslogBufferSize
	} else if cfg.BufferSize > maxSyslogBufferSize {
		cfg.BufferSize = maxSyslogBufferSize
	}

	hostname, err := generateHostname(cfg.StaticHost)
	if err != nil {
		return nil, fmt.Errorf("mebsuta: %w", err)
	}

	loc, _ := time.LoadLocation(cfg.TimeZone)
	if loc == nil {
		loc = time.UTC
	}

	ctx, cancel := context.WithCancel(context.Background())

	h := &SyslogHandler{
		LevelHandler: LevelHandler{Level: level},
		cfg:          cfg,
		dialer:       net.Dialer{Timeout: syslogDialerTimeout},
		hostname:     hostname,
		buffer:       make(chan []byte, cfg.BufferSize),
		ctx:          ctx,
		cancel:       cancel,
		location:     loc,
	}
	eh := DefaultErrorHandler
	h.errorHandler.Store(&eh)

	if cfg.Secure {
		h.tlsCfg = &tls.Config{
			InsecureSkipVerify: cfg.TLSSkipVerify,
			MinVersion:         tls.VersionTLS12,
		}
	}

	lockKey := fmt.Sprintf("%s-%s", cfg.Address, cfg.Tag)
	h.fileLock = flock.New(fmt.Sprintf("%x.lock", sha256.Sum256([]byte(lockKey))))

	if err := h.connect(); err != nil {
		cancel()
		return nil, fmt.Errorf("mebsuta: syslog initial connection failed: %w", err)
	}

	h.wg.Add(1)
	go h.processQueue()

	return h, nil
}

// Handle 处理一条日志记录，格式化为 syslog 消息并发送到缓冲通道。
func (h *SyslogHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.closing.Load() || h.closed.Load() {
		return nil
	}

	entry := RecordToLogEntry(r)
	msg := h.formatMessage(entry)
	data := []byte(msg)
	return h.safeSend(data)
}

// Close 关闭 syslog 连接并释放资源。
func (h *SyslogHandler) Close() error {
	if !h.closing.CompareAndSwap(false, true) {
		return nil
	}

	h.cancel()
	close(h.buffer)
	h.wg.Wait()

	h.connMu.Lock()
	if h.conn != nil {
		_ = h.conn.Close()
		h.conn = nil
	}
	h.connMu.Unlock()

	if err := h.fileLock.Unlock(); err != nil {
		ReportError(loadErrorHandler(&h.errorHandler), "syslog", fmt.Errorf("file unlock: %w", err))
	}
	h.closed.Store(true)
	return nil
}

// WithAttrs 返回带有预置属性的新 SyslogHandler。
func (h *SyslogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &syslogAttrsHandler{
		SyslogHandler: h,
		attrs:         attrs,
	}
}

// WithGroup 返回带有分组前缀的新 SyslogHandler。
func (h *SyslogHandler) WithGroup(name string) slog.Handler {
	return &syslogGroupHandler{
		SyslogHandler: h,
		group:         name,
	}
}

// setErrorHandler 设置内部错误处理函数（由 buildHandler 传播调用）。
func (h *SyslogHandler) setErrorHandler(fn ErrorHandler) {
	h.errorHandler.Store(&fn)
}

// =============================================================================
// 连接管理
// =============================================================================

func (h *SyslogHandler) connect() error {
	h.connMu.Lock()
	defer h.connMu.Unlock()

	if h.conn != nil {
		_ = h.conn.Close()
		h.conn = nil
	}

	var conn net.Conn
	var err error
	if h.tlsCfg != nil {
		conn, err = tls.DialWithDialer(&h.dialer, h.cfg.Network, h.cfg.Address, h.tlsCfg)
	} else {
		conn, err = h.dialer.Dial(h.cfg.Network, h.cfg.Address)
	}
	if err != nil {
		return err
	}

	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(3 * time.Minute)
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

	if h.conn != nil {
		_ = h.conn.Close()
		h.conn = nil
	}

	if locked, err := h.fileLock.TryLockContext(h.ctx, 100*time.Millisecond); locked && err == nil {
		defer func() { _ = h.fileLock.Unlock() }()
	}

	var conn net.Conn
	var err error
	if h.tlsCfg != nil {
		conn, err = tls.DialWithDialer(&h.dialer, h.cfg.Network, h.cfg.Address, h.tlsCfg)
	} else {
		conn, err = h.dialer.Dial(h.cfg.Network, h.cfg.Address)
	}
	if err != nil {
		ReportError(loadErrorHandler(&h.errorHandler), "syslog", fmt.Errorf("reconnect failed: %w", err))
		return
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
	_ = h.conn.SetWriteDeadline(time.Now().Add(syslogWriteTimeout))
	_, err := h.conn.Write(p)
	return err
}

func (h *SyslogHandler) writeWithRetry(msg []byte) {
	if !h.isConnected() && !h.closing.Load() {
		h.reconnect()
	}
	for i := range maxSyslogRetries {
		if h.closing.Load() {
			return
		}
		if err := h.write(msg); err == nil {
			return
		}
		if i == 0 {
			h.disconnect()
			h.reconnect()
		}
		time.Sleep(h.cfg.RetryDelay)
	}
	ReportError(loadErrorHandler(&h.errorHandler), "syslog", fmt.Errorf("write failed after %d attempts", maxSyslogRetries))
}

func (h *SyslogHandler) disconnect() {
	h.connMu.Lock()
	defer h.connMu.Unlock()
	if h.conn != nil {
		_ = h.conn.Close()
		h.conn = nil
	}
}

func (h *SyslogHandler) processQueue() {
	defer h.wg.Done()

	reconnector := time.NewTicker(h.cfg.RetryDelay)
	defer reconnector.Stop()

	retryCount := int32(0)

	for {
		select {
		case msg, ok := <-h.buffer:
			if !ok {
				return
			}
			h.writeWithRetry(msg)

		case <-reconnector.C:
			if !h.isConnected() {
				rc := atomic.LoadInt32(&retryCount)
				if rc > 20 {
					rc = 20 // 防止 math.Pow 溢出
				}
				baseDelay := time.Second * time.Duration(math.Pow(2, float64(rc)))
				baseDelay = min(baseDelay, maxReconnectDelay)
				jitter := time.Duration(rand.Int64N(int64(baseDelay) / 2))
				delay := baseDelay/2 + jitter
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
				retryCount++
			} else {
				retryCount = 0
			}

		case <-h.ctx.Done():
			return
		}
	}
}

func (h *SyslogHandler) safeSend(data []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = net.ErrClosed
		}
	}()
	select {
	case h.buffer <- data:
		return nil
	default:
		return fmt.Errorf("mebsuta/syslog: buffer full")
	}
}

// =============================================================================
// 消息格式化
// =============================================================================

func (h *SyslogHandler) formatMessage(entry LogEntry) string {
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

func (h *SyslogHandler) formatJSONMessage(entry LogEntry, ts time.Time, priority int, host string, procid int) string {
	logData := map[string]any{
		"time":  ts.Format(time.RFC3339Nano),
		"level": entry.Level.String(),
		"msg":   entry.Message,
	}
	for _, attr := range entry.Attrs {
		logData[attr.Key] = attr.Value
	}

	jsonBytes, err := json.Marshal(logData)
	if err != nil {
		jsonBytes = []byte(`{"msg":"log marshaling failed","level":"error"}`)
	}
	cleaned := string(jsonBytes)
	if len(cleaned) > maxSyslogMsgSize {
		cleaned = cleaned[:maxSyslogMsgSize-4] + "..."
	}

	if h.cfg.RFC5424 {
		return fmt.Sprintf(`<%d>1 %s %s %s %d - - %s`,
			priority, ts.Format(time.RFC3339Nano), host, h.cfg.Tag, procid, cleaned) + "\n"
	}
	return fmt.Sprintf(`<%d>%s %s %s[%d]: %s`,
		priority, ts.Format("Jan _2 15:04:05"), host, h.cfg.Tag, procid, cleaned) + "\n"
}

func (h *SyslogHandler) formatStructuredMessage(entry LogEntry, ts time.Time, priority int, host string, procid int) string {
	msgContent := safeMessageForLog(entry.Message)
	if len(msgContent) > maxSyslogMsgSize {
		msgContent = msgContent[:maxSyslogMsgSize-3] + "..."
	}

	if h.cfg.RFC5424 {
		// 构建 SD-ELEMENT 从 Attrs
		var sd strings.Builder
		sd.WriteByte('[')
		for i, attr := range entry.Attrs {
			if i > 0 {
				sd.WriteByte(' ')
			}
			fmt.Fprintf(&sd, "%s=\"%s\"", attr.Key, escapeSDValue(attr.Value.String()))
		}
		sd.WriteByte(']')
		sdStr := sd.String()
		if sdStr == "[]" {
			sdStr = "-"
		}

		return fmt.Sprintf(`<%d>1 %s %s %s %d - %s %s`,
			priority, ts.Format(time.RFC3339Nano), host, h.cfg.Tag, procid, sdStr, msgContent) + "\n"
	}

	return fmt.Sprintf(`<%d>%s %s %s[%d]: %s`,
		priority, ts.Format("Jan _2 15:04:05"), host, h.cfg.Tag, procid, msgContent) + "\n"
}

// =============================================================================
// 辅助函数
// =============================================================================

func (h *SyslogHandler) levelToSeverity(level slog.Level) int {
	switch {
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

// escapeSDValue 转义 RFC5424 SD-ELEMENT PARAM-VALUE 中的特殊字符。
// 需要转义: " → \", \ → \\, ] → \]
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

func safeMessageForLog(msg string) string {
	cleaned := strings.Map(func(r rune) rune {
		if r >= 0 && r <= 31 {
			return ' '
		}
		return r
	}, msg)
	return strings.TrimSpace(spaceRe.ReplaceAllString(cleaned, " "))
}

// =============================================================================
// 子 Handler 类型（WithAttrs/WithGroup 返回）
// =============================================================================

type syslogAttrsHandler struct {
	*SyslogHandler
	attrs []slog.Attr
}

func (h *syslogAttrsHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, attr := range h.attrs {
		r.AddAttrs(attr)
	}
	return h.SyslogHandler.Handle(ctx, r)
}

func (h *syslogAttrsHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	merged = append(merged, h.attrs...)
	merged = append(merged, attrs...)
	return &syslogAttrsHandler{
		SyslogHandler: h.SyslogHandler,
		attrs:         merged,
	}
}

func (h *syslogAttrsHandler) WithGroup(name string) slog.Handler {
	return &syslogGroupHandler{
		SyslogHandler: h.SyslogHandler,
		group:         name,
		attrs:         h.attrs,
	}
}

type syslogGroupHandler struct {
	*SyslogHandler
	group string
	attrs []slog.Attr
}

func (h *syslogGroupHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, attr := range h.attrs {
		r.AddAttrs(attr)
	}
	return h.SyslogHandler.Handle(ctx, r)
}

func (h *syslogGroupHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, len(h.attrs), len(h.attrs)+len(attrs))
	copy(merged, h.attrs)
	for _, a := range attrs {
		merged = append(merged, slog.Attr{Key: h.group + "." + a.Key, Value: a.Value})
	}
	return &syslogAttrsHandler{
		SyslogHandler: h.SyslogHandler,
		attrs:         merged,
	}
}

func (h *syslogGroupHandler) WithGroup(name string) slog.Handler {
	return &syslogGroupHandler{
		SyslogHandler: h.SyslogHandler,
		group:         h.group + "." + name,
		attrs:         h.attrs,
	}
}

// 编译期断言
var _ slog.Handler = (*SyslogHandler)(nil)
