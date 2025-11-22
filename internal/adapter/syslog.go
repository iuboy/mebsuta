package adapter

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"mebsuta/config"
	"mebsuta/core"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofrs/flock"
)

var (
	// 自定义的错误类型
	ErrSyslogUnavailable = errors.New("syslog server unavailable")
	ErrConfigInvalid     = errors.New("invalid syslog configuration")
)

const (
	defaultNetwork    = "tcp"
	defaultRetryDelay = 500 * time.Millisecond
	maxRetries        = 5
	writeTimeout      = 3 * time.Second
	maxHostnameLength = 255
	defaultBufferSize = 1000  // 默认缓冲大小
	maxBufferSize     = 10000 // 最大缓冲限制
	flockRetryDelay   = 100 * time.Millisecond
	maxReconnectDelay = 5 * time.Minute
)

type syslogAdapter struct {
	config      config.SyslogConfig // Syslog配置
	conn        net.Conn            // Syslog连接
	connMu      sync.RWMutex        // 用于锁定连接
	dialer      net.Dialer          // 用于创建TCP连接
	tlsConfig   *tls.Config         // TLS配置
	hostname    string              // 主机名
	closing     atomic.Bool         // 是否正在关闭
	closed      atomic.Bool         // 是否已经关闭
	buffer      chan []byte         // 日志缓冲通道
	bufferSize  int                 // 当前缓冲区大小
	wg          sync.WaitGroup      // 用于等待协程结束
	ctx         context.Context     // 上下文
	cancel      context.CancelFunc  // 取消函数
	fileLock    *flock.Flock        // 文件锁实例
	reconnector *time.Ticker        // 重连定时器
	lastSuccess atomic.Value        // 最后成功时间

	retryCount int32 // 并发安全的重试计数
}

func newSyslogAdapter(cfg config.SyslogConfig) (core.WriteSyncer, error) {
	// 应用默认值并验证配置
	if cfg.Address == "" {
		return nil, fmt.Errorf("%w: address is required", ErrConfigInvalid)
	}

	if cfg.Network == "" {
		cfg.Network = defaultNetwork
	}

	if cfg.Tag == "" {
		cfg.Tag = "mebsuta"
	}

	if cfg.RetryDelay <= 0 {
		cfg.RetryDelay = defaultRetryDelay
	}

	if cfg.BufferSize <= 0 {
		cfg.BufferSize = defaultBufferSize
	} else if cfg.BufferSize > maxBufferSize {
		cfg.BufferSize = maxBufferSize
	}

	// 获取或生成主机名
	hostname, err := generateHostname(cfg.StaticHost)
	if err != nil {
		return nil, fmt.Errorf("hostname generation failed: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	adapter := &syslogAdapter{
		config:      cfg,
		dialer:      net.Dialer{Timeout: 5 * time.Second},
		hostname:    hostname,
		buffer:      make(chan []byte, cfg.BufferSize),
		bufferSize:  cfg.BufferSize,
		ctx:         ctx,
		cancel:      cancel,
		reconnector: time.NewTicker(cfg.RetryDelay),
	}

	if cfg.Secure {
		adapter.tlsConfig = &tls.Config{
			InsecureSkipVerify: cfg.TLSSkipVerify,
			MinVersion:         tls.VersionTLS12,
		}
	}

	lockKey := fmt.Sprintf("%s-%s", cfg.Address, cfg.Tag)
	adapter.fileLock = flock.New(fmt.Sprintf("%x.lock", sha256.Sum256([]byte(lockKey))))

	adapter.lastSuccess.Store(time.Time{})

	if err := adapter.connect(); err != nil {
		adapter.cancel() // 清理资源
		return nil, fmt.Errorf("initial connection failed: %w", err)
	}
	adapter.wg.Add(1)
	go adapter.processQueue()

	return adapter, nil
}

// connect 建立或重建连接
func (a *syslogAdapter) connect() error {
	a.connMu.Lock()
	defer a.connMu.Unlock()

	// 关闭现有连接
	if a.conn != nil {
		_ = a.conn.Close()
		a.conn = nil
	}

	var conn net.Conn
	var err error

	// 创建TCP或TLS连接
	if a.tlsConfig != nil {
		conn, err = tls.DialWithDialer(&a.dialer, a.config.Network, a.config.Address, a.tlsConfig)
	} else {
		conn, err = a.dialer.Dial(a.config.Network, a.config.Address)
	}

	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}

	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(3 * time.Minute)
	}

	a.conn = conn
	return nil
}

func (a *syslogAdapter) processQueue() {
	defer a.wg.Done()
	defer a.reconnector.Stop()

	for {
		select {
		case msg, ok := <-a.buffer:
			if !ok {
				return // 通道关闭，退出协程
			}
			a.writeWithRetry(msg)

		case <-a.reconnector.C:
			// 定期检查连接状态
			if !a.isConnected() {
				delay := time.Second * time.Duration(math.Pow(2, float64(atomic.LoadInt32(&a.retryCount))))
				if delay > maxReconnectDelay {
					delay = maxReconnectDelay
				}
				time.Sleep(delay)
				a.reconnect()
				atomic.AddInt32(&a.retryCount, 1)
			} else {
				atomic.StoreInt32(&a.retryCount, 0)
			}

		case <-a.ctx.Done():
			return
		}
	}
}

func (a *syslogAdapter) writeWithRetry(msg []byte) {
	if !a.isConnected() && !a.closing.Load() {
		a.reconnect()
	}
	for i := 0; i < maxRetries; i++ {
		if a.closing.Load() {
			return
		}

		if err := a.write(msg); err == nil {
			a.lastSuccess.Store(time.Now())
			return
		}

		if i == 0 {
			a.disconnect()
			a.reconnect()
		}

		time.Sleep(a.config.RetryDelay)
	}

	fmt.Fprintf(os.Stderr, "syslog write failed after %d attempts\n", maxRetries)
}

func (a *syslogAdapter) reconnect() {
	a.connMu.Lock()
	defer a.connMu.Unlock()

	if a.conn != nil {
		_ = a.conn.Close()
		a.conn = nil
	}

	a.closed.Store(false)

	// 获取文件锁（防止多进程同时操作）
	if locked, err := a.fileLock.TryLockContext(a.ctx, flockRetryDelay); locked && err == nil {
		defer func() { _ = a.fileLock.Unlock() }()
	} else if err != nil {
		fmt.Fprintf(os.Stderr, "file lock failed: %v\n", err)
		return
	}

	var conn net.Conn
	var err error
	if a.tlsConfig != nil {
		conn, err = tls.DialWithDialer(&a.dialer, a.config.Network, a.config.Address, a.tlsConfig)
	} else {
		conn, err = a.dialer.Dial(a.config.Network, a.config.Address)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "syslog reconnect failed: %v\n", err)
		return
	}

	a.conn = conn
}

func (a *syslogAdapter) write(p []byte) error {
	a.connMu.RLock()
	defer a.connMu.RUnlock()

	if a.conn == nil {
		return net.ErrClosed
	}

	if err := a.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}

	_, err := a.conn.Write(p)
	return err
}

func (a *syslogAdapter) WriteEvent(event *core.LogEvent) error {
	if a.closing.Load() || a.closed.Load() {
		return net.ErrClosed
	}
	timestamp := event.Timestamp.In(a.getTimeZone())
	severity := a.levelToSeverity(event.Level)
	priority := a.config.Facility*8 + severity
	procid := os.Getpid()
	host := a.getCleanHost()
	var msg string
	// 构造日志内容
	if a.config.JSONInMessage {
		// 模式1: 把结构化日志序列化为紧凑 JSON 作为消息体
		logData := map[string]interface{}{
			"time":       timestamp.Format(time.RFC3339Nano),
			"level":      event.Level,
			"msg":        event.Message,
			"service":    event.ServiceName,
			"request_id": event.RequestID,
			"host":       event.Host,
			"pid":        event.PID,
			"caller":     event.Caller,
			"stack":      event.Stack,
		}
		for k, v := range event.Fields {
			if k != "time" && k != "level" && k != "msg" && k != "service" && k != "request_id" {
				logData[k] = v
			}
		}
		jsonBytes, err := json.Marshal(logData)
		if err != nil {
			jsonBytes = []byte(`{"msg":"log marshaling failed","level":"error"}`)
		}
		// cleaned := cleanSyslogMessage(jsonBytes)
		cleaned := string(jsonBytes)
		if len(cleaned) > 4*1024 {
			cleaned = cleaned[:4*1024-4] + "..."
		}
		if a.config.RFC5424 {
			timeStr := timestamp.Format(time.RFC3339Nano)
			msg = fmt.Sprintf(`<%d>1 %s %s %s %d - - %s`,
				priority, timeStr, host, a.config.Tag, procid, cleaned)
		} else {
			timeStr := timestamp.Format("Jan _2 15:04:05")
			msg = fmt.Sprintf(`<%d>%s %s %s[%d]: %s`,
				priority, timeStr, host, a.config.Tag, procid, cleaned)
		}
	} else {
		// 模式2: 使用结构化数据 SD-ELEMENT（仅 RFC5424） + 纯文本消息
		msgContent := safeMessageForLog(event.Message)
		if a.config.RFC5424 {
			timeStr := timestamp.Format(time.RFC3339Nano)
			sd := fmt.Sprintf(`[service="%s" reqid="%s"]`,
				event.ServiceName, event.RequestID)
			msg = fmt.Sprintf(`<%d>1 %s %s %s %d %s %s`,
				priority, timeStr, host, a.config.Tag, procid, sd, msgContent)
		} else {
			extra := fmt.Sprintf(`service="%s" reqid="%s"`,
				event.ServiceName, event.RequestID)
			timeStr := timestamp.Format("Jan _2 15:04:05")
			msg = fmt.Sprintf(`<%d>%s %s %s[%d]: %s %s`,
				priority, timeStr, host, a.config.Tag, procid, msgContent, extra)
		}
	}

	// 添加换行符（RFC 要求）
	msg += "\n"

	// 写入缓冲区
	select {
	case a.buffer <- []byte(msg):
		return nil
	default:
		return fmt.Errorf("syslog buffer full")
	}
}

func (a *syslogAdapter) Write(p []byte) (n int, err error) {
	if a.closing.Load() || a.closed.Load() {
		return 0, net.ErrClosed
	}

	s := string(p)

	// Step 1: 将文本中的 \xNN 转换为真实字节
	rawBytes := replaceTextHexEscapes(s)

	processed := escapeControlCharsInBytes(rawBytes)
	fmt.Fprintf(os.Stderr, "PROCESSED: %s\n", processed) // 🔥 加这行

	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(processed), &raw); err != nil {
		fmt.Fprintf(os.Stderr, "JSON ERROR: %v\n", err) // 🔥 加这行

		event := &core.LogEvent{
			Timestamp: time.Now(),
			Level:     "info",
			Message:   string(p),
			Host:      a.hostname,
			PID:       os.Getpid(),
		}
		return len(p), a.WriteEvent(event)
	}

	event := &core.LogEvent{
		Timestamp:   extractTime(raw),
		Level:       extractLevel(raw),
		Message:     coalesceStr(castToString(raw["msg"]), castToString(raw["message"]), "log received"),
		Caller:      castToString(raw["caller"]),
		Stack:       castToString(raw["stack"]),
		Fields:      extractFields(raw),
		ServiceName: extractServiceName(raw),
		RequestID:   extractRequestID(raw),
		Host:        a.hostname,
		PID:         os.Getpid(),
	}

	return len(p), a.WriteEvent(event)
}

func (a *syslogAdapter) Sync() error {
	a.connMu.RLock()
	defer a.connMu.RUnlock()
	if tcpConn, ok := a.conn.(*net.TCPConn); ok {
		return tcpConn.SetWriteDeadline(time.Time{})
	}
	return nil
}

func (a *syslogAdapter) Close() error {
	if !a.closing.CompareAndSwap(false, true) {
		return nil
	}

	a.cancel()
	close(a.buffer)
	a.wg.Wait()

	a.connMu.Lock()
	if a.conn != nil {
		_ = a.conn.Close()
		a.conn = nil
	}
	a.connMu.Unlock()

	_ = a.fileLock.Unlock()
	a.closed.Store(true)
	return nil
}

// extractSeverity 从日志中提取Syslog严重级别
// func extractSeverity(msg []byte) int {
// 	var entry struct {
// 		Level  string `json:"level"`
// 		Level2 string `json:"lvl"`
// 	}
// 	if err := json.Unmarshal(msg, &entry); err != nil {
// 		return 6
// 	}

// 	levelStr := strings.ToLower(entry.Level)
// 	if levelStr == "" {
// 		levelStr = strings.ToLower(entry.Level2)
// 	}

// 	switch levelStr {
// 	case "debug", "debuglevel", "-1":
// 		return 7
// 	case "info", "infolevel", "0":
// 		return 6
// 	case "warn", "warninglevel", "warnlevel", "1":
// 		return 4
// 	case "error", "errorlevel", "2":
// 		return 3
// 	case "dpanic", "dpaniclevel", "3":
// 		return 2
// 	case "panic", "paniclevel", "4":
// 		return 2
// 	case "fatal", "fatallevel", "5":
// 		return 0
// 	default:
// 		return 6
// 	}
// }

// formatMessage 格式化为Syslog消息（现在由 WriteEvent 直接构建）
// func (a *syslogAdapter) formatMessage(msg []byte, severity int, timestamp time.Time) string {
// 	priority := a.config.Facility*8 + severity
// 	procid := os.Getpid()
// 	cleanedMsg := cleanSyslogMessage(msg)
// 	host := a.getCleanHost()
// 	tm := timestamp.In(a.getTimeZone())

// 	if a.config.RFC5424 {
// 		timeStr := tm.Format(time.RFC3339Nano)
// 		return fmt.Sprintf("<%d>1 %s %s %s %d - %s\n", priority, timeStr, host, a.config.Tag, procid, cleanedMsg)
// 	}

// 	timeStr := tm.Format("Jan _2 15:04:05")
// 	return fmt.Sprintf("<%d>%s %s %s[%d]: %s\n", priority, timeStr, host, a.config.Tag, procid, cleanedMsg)
// }

// 生成主机名
func generateHostname(staticHostname string) (string, error) {
	if staticHostname != "" {
		staticHostname = strings.TrimSpace(staticHostname)
		staticHostname = cleanHostname(staticHostname)
		if staticHostname == "" {
			return "", errors.New("invalid static hostname")
		}
		if len(staticHostname) > maxHostnameLength {
			staticHostname = staticHostname[:maxHostnameLength]
		}
		return staticHostname, nil
	}
	hostname, err := os.Hostname()
	if err != nil {
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

// 清理主机名非法字符
func cleanHostname(hostname string) string {
	var clean strings.Builder
	for _, r := range hostname {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '.':
			clean.WriteRune(r)
		default:
			clean.WriteRune('-')
		}
	}

	ip := net.ParseIP(clean.String())
	if ip != nil {
		return ip.String()
	}
	return clean.String()
}

// cleanSyslogMessage 清理消息中的非法字符，转义控制字符
// func cleanSyslogMessage(data []byte) string {
// 	var processed []byte
// 	// processed = replaceHexEscapes(data)
// 	processed = escapeControlChars(processed)

// 	safe := strings.Map(func(r rune) rune {
// 		if r == '\t' || r == '\n' || r == '\r' {
// 			return ' '
// 		}
// 		return r
// 	}, string(processed))
// 	safe = regexp.MustCompile(`\s+`).ReplaceAllString(strings.TrimSpace(safe), " ")
// 	return safe
// }

// func safeMessageForLog(msg string) string {
// 	return regexp.MustCompile(`\s+`).ReplaceAllString(strings.TrimSpace(msg), " ")
// }

func safeMessageForLog(msg string) string {
	// 将所有 ASCII 控制字符（0–31）替换为空格
	cleaned := strings.Map(func(r rune) rune {
		if r >= 0 && r <= 31 {
			return ' '
		}
		return r
	}, msg)

	// 压缩空白并去除首尾空格
	spaceRe := regexp.MustCompile(`\s+`)
	return strings.TrimSpace(spaceRe.ReplaceAllString(cleaned, " "))
}

func (a *syslogAdapter) isConnected() bool {
	a.connMu.RLock()
	defer a.connMu.RUnlock()
	return a.conn != nil
}

func (a *syslogAdapter) disconnect() {
	a.connMu.Lock()
	defer a.connMu.Unlock()
	if a.conn != nil {
		_ = a.conn.Close()
		a.conn = nil
	}
}

// func replaceHexEscapes(data []byte) []byte {
// 	re := regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
// 	return re.ReplaceAllFunc(data, func(match []byte) []byte {
// 		var b byte
// 		if _, err := fmt.Sscanf(string(match), "\\x%02x", &b); err != nil {
// 			return []byte{0xef, 0xbf, 0xbd} // Unicode replacement char
// 		}
// 		return []byte{b}
// 	})
// }

// func escapeControlChars(data []byte) []byte {
// 	var buf bytes.Buffer
// 	for _, b := range data {
// 		switch {
// 		case b == '\t', b == '\n', b == '\r':
// 			buf.WriteByte(b)
// 		case b >= 32 && b <= 126:
// 			buf.WriteByte(b)
// 		default:
// 			fmt.Fprintf(&buf, "\\u%04X", b)
// 		}
// 	}
// 	return buf.Bytes()
// }

func (a *syslogAdapter) levelToSeverity(level string) int {
	l := strings.ToLower(level)
	switch {
	case l == "debug":
		return 7
	case l == "info":
		return 6
	case l == "warn", l == "warning":
		return 4
	case l == "error":
		return 3
	case l == "fatal", l == "panic":
		return 0
	default:
		return 6
	}
}

func (a *syslogAdapter) getTimeZone() *time.Location {
	loc, _ := time.LoadLocation(a.config.TimeZone)
	if loc == nil {
		return time.UTC
	}
	return loc
}

func (a *syslogAdapter) getCleanHost() string {
	host := cleanHostname(a.hostname)
	if host == "" {
		return "localhost"
	}
	return host
}

func extractTime(raw map[string]interface{}) time.Time {
	if ts, ok := raw["time"].(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			return t
		}
	}
	return time.Now() // 默认返回当前时间
}
func extractLevel(raw map[string]interface{}) string {
	if level, ok := raw["level"].(string); ok && level != "" {
		return level
	}
	if lvl, ok := raw["lvl"].(string); ok && lvl != "" {
		return lvl
	}
	return "info" // 默认返回 info 级别
}
func coalesceStr(strs ...string) string {
	for _, s := range strs {
		if s != "" {
			return s
		}
	}
	return ""
}
func castToString(value interface{}) string {
	if value == nil {
		return ""
	}
	if str, ok := value.(string); ok {
		return str
	}
	return fmt.Sprintf("%v", value)
}
func extractFields(raw map[string]interface{}) map[string]interface{} {
	fields := make(map[string]interface{})
	for key, value := range raw {
		switch key {
		case "time", "level", "msg", "message", "caller", "stack", "service", "request_id", "host", "pid":
			continue // 跳过已知的标准字段
		default:
			fields[key] = value
		}
	}
	return fields
}
func extractServiceName(raw map[string]interface{}) string {
	if service, ok := raw["service"].(string); ok && service != "" {
		return service
	}
	return "unknown_service" // 默认返回 unknown_service
}
func extractRequestID(raw map[string]interface{}) string {
	if reqID, ok := raw["request_id"].(string); ok && reqID != "" {
		return reqID
	}
	return "" // 默认返回空字符串
}

// func coalesce(strs ...string) string {
// 	for _, s := range strs {
// 		if s != "" {
// 			return s
// 		}
// 	}
// 	return ""
// }

// func escapeControlCharsForJSON(data []byte) []byte {
// 	var buf bytes.Buffer
// 	for _, b := range data {
// 		switch {
// 		case b == '\t', b == '\n', b == '\r':
// 			buf.WriteByte(b)
// 		case b >= 32 && b <= 126:
// 			buf.WriteByte(b)
// 		default:
// 			fmt.Fprintf(&buf, "\\u%04X", b)
// 		}
// 	}
// 	return buf.Bytes()
// }

// func escapeControlCharsInString(s string) string {
// 	var buf bytes.Buffer
// 	for _, r := range s {
// 		switch {
// 		case r == '\t', r == '\n', r == '\r':
// 			buf.WriteRune(r)
// 		case r >= 32 && r <= 126:
// 			buf.WriteRune(r)
// 		default:
// 			fmt.Fprintf(&buf, "\\u%04X", r)
// 		}
// 	}
// 	return buf.String()
// }

// func escapeControlCharsForJSONString(s string) string {
// 	var buf strings.Builder
// 	for i := 0; i < len(s); i++ {
// 		b := s[i]
// 		if (b >= 32 && b <= 126) || b == '\t' || b == '\n' || b == '\r' {
// 			buf.WriteByte(b)
// 		} else {
// 			fmt.Fprintf(&buf, "\\u%04X", b)
// 		}
// 	}
// 	return buf.String()
// }

func replaceTextHexEscapes(s string) []byte {
	re := regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	return re.ReplaceAllFunc([]byte(s), func(match []byte) []byte {
		var b byte
		if _, err := fmt.Sscanf(string(match), "\\x%02x", &b); err != nil {
			return []byte{0xEF, 0xBF, 0xBD} // UTF-8 REPLACEMENT CHARACTER
		}
		return []byte{b}
	})
}

func escapeControlCharsInBytes(data []byte) string {
	var buf strings.Builder
	for _, b := range data {
		if (b >= 32 && b <= 126) || b == '\t' || b == '\n' || b == '\r' {
			buf.WriteByte(b)
		} else {
			fmt.Fprintf(&buf, "\\u%04X", b)
		}
	}
	return buf.String()
}
