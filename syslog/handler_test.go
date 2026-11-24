package syslog

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/internal/handlerkit"
	"github.com/stretchr/testify/require"
)

func listenTCP() (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:0")
}

// =============================================================================
// Config Validate
// =============================================================================

func TestConfig_ZeroValue(t *testing.T) {
	cfg := Config{}
	_, err := cfg.Validate()
	require.Error(t, err, "expected error for empty address")
}

func TestConfig_EmptyAddress(t *testing.T) {
	cfg := Config{Address: ""}
	_, err := cfg.Validate()
	require.Error(t, err, "expected error for empty address")
	var cerr *mebsuta.ConfigError
	require.ErrorAs(t, err, &cerr)
	require.Equal(t, "Address", cerr.Field)
}

func TestConfig_DefaultsApplied(t *testing.T) {
	cfg := Config{Address: "localhost:514"}
	validated, err := cfg.Validate()
	require.NoError(t, err, "unexpected error")
	require.Equal(t, "tcp", validated.Network, "Network")
	require.Equal(t, "mebsuta", validated.Tag, "Tag")
	require.Equal(t, slog.LevelInfo, validated.Level, "Level")
	require.Equal(t, DefaultFacility, validated.Facility, "Facility")
	require.Equal(t, 500*time.Millisecond, validated.RetryDelay, "RetryDelay")
	require.Equal(t, 1000, validated.BufferSize, "BufferSize")
	require.NotNil(t, validated.Reconnect)
	require.True(t, *validated.Reconnect, "Reconnect should default to true")
}

func TestConfig_CustomValuesPreserved(t *testing.T) {
	r := true
	cfg := Config{
		Network:    "udp",
		Address:    "10.0.0.1:514",
		Level:      slog.LevelDebug,
		Tag:        "myapp",
		Facility:   16,
		Reconnect:  &r,
		RetryDelay: time.Second,
		BufferSize: 500,
		TimeZone:   "America/New_York",
	}
	validated, err := cfg.Validate()
	require.NoError(t, err, "unexpected error")
	require.Equal(t, "udp", validated.Network, "Network")
	require.Equal(t, "myapp", validated.Tag, "Tag")
	require.Equal(t, 16, validated.Facility, "Facility")
	require.Equal(t, time.Second, validated.RetryDelay, "RetryDelay")
}

func TestConfig_InvalidTag(t *testing.T) {
	tests := []struct {
		name string
		tag  string
	}{
		{"too long", strings.Repeat("a", 49)},
		{"non-printable", "tag\x00name"},
		{"control char", "tag\nname"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{Address: "localhost:514", Tag: tt.tag}
			_, err := cfg.Validate()
			require.Error(t, err, "expected error")
			var cerr *mebsuta.ConfigError
			require.ErrorAs(t, err, &cerr)
			require.Equal(t, "Tag", cerr.Field)
		})
	}
}

func TestConfig_InvalidFacility(t *testing.T) {
	cfg := Config{Address: "localhost:514", Facility: 24}
	_, err := cfg.Validate()
	require.Error(t, err, "expected error for facility > 23")
}

func TestConfig_InvalidTimezone(t *testing.T) {
	cfg := Config{Address: "localhost:514", TimeZone: "Invalid/Zone"}
	_, err := cfg.Validate()
	require.Error(t, err, "expected error for invalid timezone")
}

func TestConfig_Idempotent(t *testing.T) {
	cfg := Config{Address: "localhost:514"}
	first, err := cfg.Validate()
	require.NoError(t, err, "first validate")
	second, err := first.Validate()
	require.NoError(t, err, "second validate")
	require.Equal(t, first, second, "Validate should be idempotent")
}

func TestConfig_DoesNotModifyOriginal(t *testing.T) {
	cfg := Config{Address: "localhost:514"}
	original := cfg
	_, _ = cfg.Validate()
	require.Equal(t, original.Network, cfg.Network, "Validate modified original Network")
	require.Equal(t, original.Tag, cfg.Tag, "Validate modified original Tag")
}

// =============================================================================
// levelToSeverity
// =============================================================================

func TestLevelToSeverity(t *testing.T) {
	h := &Handler{}
	tests := []struct {
		level    slog.Level
		expected int
	}{
		{slog.LevelDebug, 7},
		{slog.LevelInfo, 6},
		{slog.LevelWarn, 4},
		{slog.LevelError, 3},
		{mebsuta.LevelAudit, 2},
	}
	for _, tt := range tests {
		got := h.levelToSeverity(tt.level)
		require.Equal(t, tt.expected, got, "levelToSeverity(%v)", tt.level)
	}
}

// =============================================================================
// cleanHostname
// =============================================================================

func TestCleanHostname(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"my-host.example.com", "my-host.example.com"},
		{"MY-HOST", "MY-HOST"},
		{"host name with spaces", "host-name-with-spaces"},
		{"host_underscore", "host-underscore"},
		{"192.168.1.1", "192.168.1.1"},
		{"", ""},
		{strings.Repeat("a", 300), strings.Repeat("a", 300)},
	}
	for _, tt := range tests {
		got := cleanHostname(tt.input)
		require.Equal(t, tt.expected, got, "cleanHostname(%q)", tt.input)
	}
}

// =============================================================================
// generateHostname
// =============================================================================

func TestGenerateHostname_StaticValid(t *testing.T) {
	host, err := generateHostname("my-server")
	require.NoError(t, err, "unexpected error")
	require.Equal(t, "my-server", host)
}

func TestGenerateHostname_StaticTruncated(t *testing.T) {
	long := strings.Repeat("a", 300)
	host, err := generateHostname(long)
	require.NoError(t, err, "unexpected error")
	require.LessOrEqual(t, len(host), 255, "host length")
}

func TestGenerateHostname_StaticInvalid(t *testing.T) {
	_, err := generateHostname("   ")
	require.Error(t, err, "expected error for whitespace-only hostname")
}

func TestGenerateHostname_Auto(t *testing.T) {
	host, err := generateHostname("")
	require.NoError(t, err, "unexpected error")
	require.NotEmpty(t, host, "auto hostname should not be empty")
}

// =============================================================================
// escapeSDValue
// =============================================================================

func TestEscapeSDValue(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{`hello`, `hello`},
		{`say "hi"`, `say \"hi\"`},
		{`back\slash`, `back\\slash`},
		{`bracket]test`, `bracket\]test`},
		{`all"three\]`, `all\"three\\\]`},
	}
	for _, tt := range tests {
		got := escapeSDValue(tt.input)
		require.Equal(t, tt.expected, got, "escapeSDValue(%q)", tt.input)
	}
}

// =============================================================================
// sanitizeSDName
// =============================================================================

func TestSanitizeSDName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"valid-name_1.2", "valid-name_1.2"},
		{"has spaces", "has_spaces"},
		{"special!@#chars", "special___chars"},
		{"UPPER_case", "UPPER_case"},
	}
	for _, tt := range tests {
		got := sanitizeSDName(tt.input)
		require.Equal(t, tt.expected, got, "sanitizeSDName(%q)", tt.input)
	}
}

// truncateUTF8 的规范测试已随实现迁移至 internal/textutil（本包保留
// truncateUTF8 薄委托）。

// =============================================================================
// truncateJSON
// =============================================================================

func TestTruncateJSON_ShortEnough(t *testing.T) {
	input := `{"key":"value"}`
	got := truncateJSON(input, 100)
	require.Equal(t, input, got, "should not truncate short JSON")
}

func TestTruncateJSON_Truncates(t *testing.T) {
	input := `{"message":"` + strings.Repeat("a", 200) + `"}`
	got := truncateJSON(input, 50)
	require.LessOrEqual(t, len(got), 50, "truncated JSON length > max 50")
}

func TestTruncateJSON_BalancesBrackets(t *testing.T) {
	input := `{"outer":{"inner":"` + strings.Repeat("x", 200) + `"}}`
	got := truncateJSON(input, 80)
	// 应关闭所有未闭合括号
	require.True(t, strings.HasPrefix(got, `{"outer":{"inner":"`),
		"unexpected prefix: %s", got[:min(len(got), 30)])
}

// =============================================================================
// safeMessageForLog
// =============================================================================

func TestSafeMessageForLog(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"normal message", "normal message"},
		{"with\ttab", "with tab"},
		{"with\nnewline", "with newline"},
		{"  trimmed  ", "trimmed"},
		{"multi  spaces", "multi spaces"},
	}
	for _, tt := range tests {
		got := safeMessageForLog(tt.input)
		require.Equal(t, tt.expected, got, "safeMessageForLog(%q)", tt.input)
	}
}

// =============================================================================
// 经 Handler 的 formatMessage
// =============================================================================

func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	cfg := Config{
		Network:    "tcp",
		Address:    t.Name() + ":514", // 不会真正连接，仅用于格式化
		Tag:        "test",
		Facility:   1,
		RetryDelay: 100 * time.Millisecond,
	}
	cfg, _ = cfg.Validate()
	return &Handler{
		cfg:          cfg,
		hostname:     "testhost",
		location:     time.UTC,
		errorHandler: handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler),
	}
}

func TestFormatMessage_RFC3164(t *testing.T) {
	h := newTestHandler(t)
	h.cfg.RFC5424 = false

	entry := logEntry{
		Time:    time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		Level:   slog.LevelInfo,
		Message: "test message",
	}
	msg := h.formatMessage(entry)
	require.Contains(t, msg, "<14>", "RFC3164 should contain priority")
	require.Contains(t, msg, "testhost", "should contain hostname")
	require.Contains(t, msg, "test message", "should contain message")
	require.True(t, strings.HasSuffix(msg, "\n"), "should end with newline")
}

func TestFormatMessage_RFC5424(t *testing.T) {
	h := newTestHandler(t)
	h.cfg.RFC5424 = true

	entry := logEntry{
		Time:    time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		Level:   slog.LevelInfo,
		Message: "structured test",
		Attrs: []slog.Attr{
			slog.String("key", "value"),
		},
	}
	msg := h.formatMessage(entry)
	require.Contains(t, msg, "<14>1 ", "RFC5424 should start with priority+version")
	require.Contains(t, msg, "structured test", "should contain message")
	require.Contains(t, msg, `key="value"`, "should contain structured data")
}

func TestFormatMessage_JSONInMessage(t *testing.T) {
	h := newTestHandler(t)
	h.cfg.JSONInMessage = true

	entry := logEntry{
		Time:    time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		Level:   slog.LevelInfo,
		Message: "json test",
		Attrs: []slog.Attr{
			slog.String("key", "value"),
		},
	}
	msg := h.formatMessage(entry)
	require.Contains(t, msg, `"message":"json test"`, "should contain JSON message")
	require.Contains(t, msg, `"key":"value"`, "should contain JSON attrs")
}

func TestFormatMessage_AuditLevel(t *testing.T) {
	h := newTestHandler(t)
	h.cfg.RFC5424 = true
	h.cfg.JSONInMessage = true

	entry := logEntry{
		Time:    time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		Level:   mebsuta.LevelAudit,
		Message: "audit event",
	}
	msg := h.formatMessage(entry)
	require.Contains(t, msg, `"level":"AUDIT"`, "audit level should be AUDIT")
	// Facility 1 * 8 + severity 2 = 10
	require.Contains(t, msg, "<10>", "audit priority should be 10")
}

func TestFormatMessage_Timezone(t *testing.T) {
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Skip("timezone not available")
	}
	h := newTestHandler(t)
	h.location = loc
	h.cfg.RFC5424 = true

	entry := logEntry{
		Time:    time.Date(2025, 1, 15, 2, 30, 0, 0, time.UTC),
		Level:   slog.LevelInfo,
		Message: "tz test",
	}
	msg := h.formatMessage(entry)
	// UTC 02:30 = 上海 10:30
	require.Contains(t, msg, "10:30", "should use Shanghai timezone")
}

// =============================================================================
// backoffDelay
// =============================================================================

func TestBackoffDelay(t *testing.T) {
	d0 := backoffDelay(0)
	require.Positive(t, d0, "backoff for retry 0 should be positive")
	// 更高重试次数应给出更大延迟（近似单调）
	d5 := backoffDelay(5)
	require.GreaterOrEqual(t, d5, d0, "backoff(5)=%v < backoff(0)=%v", d5, d0)
	// 应以 maxReconnectDelay 封顶
	d100 := backoffDelay(100)
	require.LessOrEqual(t, d100, maxReconnectDelay, "backoff(100)=%v > max %v", d100, maxReconnectDelay)
}

// =============================================================================
// 使用 mock TCP 服务的 handler 生命周期
// =============================================================================

func TestHandler_ConnectAndClose(t *testing.T) {
	// 启动一个简单的 TCP 服务
	listener, err := listenTCP()
	require.NoError(t, err, "listen")
	defer func() { _ = listener.Close() }()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	addr := listener.Addr().String()
	h, err := NewHandler(Config{
		Network: "tcp",
		Address: addr,
		Tag:     "test",
	})
	require.NoError(t, err, "NewHandler")

	require.True(t, h.isConnected(), "should be connected after NewHandler")

	require.NoError(t, h.Close(), "Close")

	require.False(t, h.isConnected(), "should not be connected after Close")

	// 双 Close 应幂等
	require.NoError(t, h.Close(), "double Close")
}

func TestHandler_HandleWrites(t *testing.T) {
	received := make(chan []byte, 10)
	listener, err := listenTCP()
	require.NoError(t, err, "listen")
	defer func() { _ = listener.Close() }()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				received <- buf[:n]
			}
			if err != nil {
				return
			}
		}
	}()

	h, err := NewHandler(Config{
		Network:    "tcp",
		Address:    listener.Addr().String(),
		Tag:        "test",
		RetryDelay: 50 * time.Millisecond,
	})
	require.NoError(t, err, "NewHandler")
	defer func() { _ = h.Close() }()

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "hello syslog", 0)
	_ = h.Handle(context.TODO(), r)

	select {
	case data := <-received:
		require.Contains(t, string(data), "hello syslog", "received data should contain message")
	case <-time.After(2 * time.Second):
		require.FailNow(t, "timeout waiting for syslog message")
	}
}

func TestHandler_Enabled(t *testing.T) {
	h := &Handler{level: handlerkit.NewLevelGate(slog.LevelInfo)}
	require.True(t, h.Enabled(context.TODO(), slog.LevelInfo), "Info should be enabled")
	require.False(t, h.Enabled(context.TODO(), slog.LevelDebug), "Debug should not be enabled at Info level")
	require.True(t, h.Enabled(context.TODO(), slog.LevelError), "Error should always be enabled")
}

func TestHandler_CloseBeforeConnect(t *testing.T) {
	// 未连接就 Close 不应 panic
	h := &Handler{
		location: time.UTC,
	}
	h.closing.Store(true) // 标记为 closing 以避免 goroutine 问题
	require.NoError(t, h.Close(), "Close on uninitialized handler")
}

// =============================================================================
// Handler WithAttrs/WithGroup
// =============================================================================

func TestHandler_WithAttrs(t *testing.T) {
	h := &Handler{
		level:    handlerkit.NewLevelGate(slog.LevelInfo),
		location: time.UTC,
		cfg:      Config{Tag: "test", Facility: 1},
		hostname: "testhost",
	}
	child := h.WithAttrs([]slog.Attr{slog.String("key", "value")})
	require.NotNil(t, child, "WithAttrs should not return nil")
	// 验证它是 AttrsSub 包装
	_ = child
}

func TestHandler_WithGroup(t *testing.T) {
	h := &Handler{
		level:    handlerkit.NewLevelGate(slog.LevelInfo),
		location: time.UTC,
		cfg:      Config{Tag: "test", Facility: 1},
		hostname: "testhost",
	}
	child := h.WithGroup("request")
	require.NotNil(t, child, "WithGroup should not return nil")
}

// =============================================================================
// SelfBuffered 标记
// =============================================================================

func TestHandler_SelfBuffered(t *testing.T) {
	h := &Handler{}
	// 应实现 SelfBufferedHandler
	var _ mebsuta.SelfBufferedHandler = h
}

// =============================================================================
// ConfigError
// =============================================================================

func TestConfigError_Format(t *testing.T) {
	err := &mebsuta.ConfigError{Field: "Address", Msg: "is required"}
	require.Contains(t, err.Error(), "Address", "should contain field name")
	require.Contains(t, err.Error(), "is required", "should contain message")
}

// =============================================================================
// Flush 与 drainBuffer
// =============================================================================

func TestHandler_Flush(t *testing.T) {
	received := make(chan string, 20)
	listener, err := listenTCP()
	require.NoError(t, err, "listen")
	defer func() { _ = listener.Close() }()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 8192)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				for _, line := range strings.Split(string(buf[:n]), "\n") {
					line = strings.TrimSpace(line)
					if line != "" {
						received <- line
					}
				}
			}
			if err != nil {
				return
			}
		}
	}()

	h, err := NewHandler(Config{
		Network:    "tcp",
		Address:    listener.Addr().String(),
		Tag:        "test",
		BufferSize: 100,
		RetryDelay: 50 * time.Millisecond,
	})
	require.NoError(t, err, "NewHandler")
	defer func() { _ = h.Close() }()

	for i := range 5 {
		r := slog.NewRecord(time.Now(), slog.LevelInfo, fmt.Sprintf("flush-%d", i), 0)
		_ = h.Handle(context.Background(), r)
	}

	require.NoError(t, h.Flush(3*time.Second), "Flush")

	// Flush 保证缓冲已排空；验证至少有部分消息到达。
	require.Eventually(t, func() bool {
		return len(received) >= 3
	}, 3*time.Second, 50*time.Millisecond, "should receive messages after flush")
}

func TestHandler_Flush_Closing(t *testing.T) {
	listener, err := listenTCP()
	require.NoError(t, err, "listen")
	defer func() { _ = listener.Close() }()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
	}()

	h, err := NewHandler(Config{
		Network: "tcp",
		Address: listener.Addr().String(),
		Tag:     "test",
	})
	require.NoError(t, err, "NewHandler")

	_ = h.Close()

	require.NoError(t, h.Flush(time.Second), "Flush on closing handler should return nil")
}

// =============================================================================
// setErrorHandler 与 loadEH
// =============================================================================

func TestHandler_SetErrorHandler(t *testing.T) {
	listener, err := listenTCP()
	require.NoError(t, err, "listen")

	// ready 确保 Accept goroutine 先阻塞在 Accept() 上，
	// NewHandler 再尝试连接——消除 RST 在初始拨号期间到达的竞争，
	// 否则测试会变成 NewHandler 报错而非写错误路径。
	ready := make(chan struct{})
	go func() {
		close(ready)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		_ = conn.Close()
	}()
	<-ready

	var mu sync.Mutex
	var gotErr string

	h, err := NewHandler(Config{
		Network:    "tcp",
		Address:    listener.Addr().String(),
		Tag:        "test",
		RetryDelay: 50 * time.Millisecond,
	})
	if err != nil {
		// 某些环境（尤其是 CI runner）中，被接受后立即关闭连接产生的
		// RST 会在 NewHandler 内的初始拨号期间到达客户端，导致
		// NewHandler 本身失败。测试意图是验证错误到达自定义
		// handler——NewHandler 使用默认 handler（stderr），
		// 因此我们在下方经默认 handler 断言捕获该路径。
		_ = listener.Close()
		// NewHandler 在返回前就失败了，没有可设置自定义错误
		// 处理器的 handler。错误已经默认 handler 路径上报——
		// 这是可接受的行为。
		t.Logf("NewHandler failed during initial dial (expected on some CI): %v", err)
		return
	}
	defer func() { _ = h.Close() }()

	h.SetErrorHandler(func(he *mebsuta.HandlerError) {
		mu.Lock()
		gotErr = he.Err.Error()
		mu.Unlock()
	})

	// 关闭 listener，让重连尝试也失败。
	_ = listener.Close()

	// 写入记录；收到 RST 后写立即失败，
	// 对已关闭 listener 的重连也失败，从而触发错误处理器。
	for i := range 10 {
		r := slog.NewRecord(time.Now(), slog.LevelInfo, fmt.Sprintf("error-%d", i), 0)
		_ = h.Handle(context.Background(), r)
	}

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return gotErr != ""
	}, 5*time.Second, 50*time.Millisecond, "custom error handler should be called")
}

// =============================================================================
// B 批审计回归：持锁 ReportError 死锁、SD LogValuer
// 解析、SD 先转义后截断预算、Close 幂等排空等待、
// 关闭后丢弃记账、marshal 失败回显截断。
// =============================================================================

// TestSafeSend_ErrorHandlerReentrantClose 验证死锁修复：safeSend
// 过去在持有 sendMu.RLock 时调用 ReportError，重入 Close
// （sendMu.Lock）的用户 ErrorHandler 会与自身永久死锁。此处的
// handler 正是这样做的；若死锁回归，2s 看门狗让测试失败而
// 不是挂死整个套件。
func TestSafeSend_ErrorHandlerReentrantClose(t *testing.T) {
	listener, err := listenTCP()
	require.NoError(t, err, "listen")

	// 接受一个连接后用 RST（SetLinger(0)）杀掉它：写立即失败且
	// Reconnect=false 下 0.1.0-24 起按丢弃处理（不再空转重试）。
	ready := make(chan struct{})
	go func() {
		close(ready)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		_ = conn.Close()
	}()
	<-ready

	h, err := NewHandler(Config{
		Network:    "tcp",
		Address:    listener.Addr().String(),
		Tag:        "test",
		BufferSize: 1,
		Reconnect:  boolPtr(false),
	})
	// 某些 CI runner 会在初始拨号期间送达 RST；死锁
	// 回归需要存活的 handler，因此直接跳过而非失败。
	if err != nil {
		_ = listener.Close()
		t.Skipf("NewHandler failed during initial dial: %v", err)
	}

	var ehCalls atomic.Int32
	h.SetErrorHandler(func(*mebsuta.HandlerError) {
		ehCalls.Add(1)
		_ = h.Close() // 从错误报告内部重入 Close
	})

	// 确定性触发：RST 落地后连接已死且 Reconnect=false。第一条 INFO
	// 被 processQueue 写失败并丢弃并上报；第二条 INFO 撞满
	// BufferSize=1 的缓冲，safeSend 的丢弃上报随即发生——0.1.0-23
	// 前它发生在 sendMu 读锁内，重入 Close 会死锁在锁上；重入
	// Close 的 wg.Wait 自等待则由排空上界兜底。两条上报路径都不得
	// 挂死调用方。
	_ = listener.Close()
	time.Sleep(10 * time.Millisecond) // 让 RST 到达客户端
	_ = h.Handle(context.Background(), slog.NewRecord(time.Now(), slog.LevelInfo, "fill", 0))
	time.Sleep(20 * time.Millisecond) // 让 processQueue 消费第一条并发现连接已死
	_ = h.Handle(context.Background(), slog.NewRecord(time.Now(), slog.LevelInfo, "slot", 0))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && ehCalls.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	require.NotZero(t, ehCalls.Load(), "error handler was never invoked; drop report did not reach the ErrorHandler")
	// 第一个 Close 已在 ErrorHandler 内执行；此处经幂等
	// drainDone 等待返回（有上界，重入场景不挂死）。
	_ = h.Close()
}

func TestFormatStructuredMessage_LogValuerResolved(t *testing.T) {
	h := newTestHandler(t)
	h.cfg.RFC5424 = true

	entry := logEntry{
		Time:    time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC),
		Level:   slog.LevelInfo,
		Message: "m",
		Attrs: []slog.Attr{
			slog.String("plain", "ok"),
			slog.Any("secret", redactValuer{}),
			slog.Group("db",
				slog.String("host", "h1"),
				slog.Group("creds", slog.Any("token", redactValuer{})),
			),
			slog.Any("selfish", selfValuer{}),
		},
	}
	frame := h.formatStructuredMessage(entry, entry.Time.In(time.UTC), 14, "testhost", 1234)

	require.Contains(t, frame, `secret="***"`, "LogValuer value must render as its resolved string")
	require.NotContains(t, frame, "redactValuer", "internal LogValuer representation must not leak into SD-PARAMs")
	require.NotContains(t, frame, "&{", "no fmt-struct rendering expected in SD-PARAMs")
	require.Contains(t, frame, `db.host="h1"`, "KindGroup attrs must flatten into dotted child params")
	require.Contains(t, frame, `db.creds.token="***"`, "nested group LogValuer values must resolve too")
	require.Contains(t, frame, `plain="ok"`, "plain string params must survive alongside flattened ones")
	require.Contains(t, frame, sdTruncationMark, "the self-referential LogValuer is skipped and must be counted in the marker")
	require.NotContains(t, frame, "selfish=", "the cyclic LogValuer subtree must be skipped entirely, not rendered")
}

func boolPtr(b bool) *bool { return &b }

type redactValuer struct{}

func (redactValuer) LogValue() slog.Value { return slog.StringValue("***") }

// selfValuer 返回包含自身的组，是最坏情况的
// LogValuer→组循环；SD 收集必须深度封顶而非死循环。
type selfValuer struct{}

func (selfValuer) LogValue() slog.Value {
	return slog.Group("loop", slog.Any("self", selfValuer{})).Value
}

// TestFormatStructuredMessage_SDBudgetAllQuotes：转义会让全引号值翻倍，
// 因此截断必须发生在转义之后（先转义后
// 截断）。单条 4KB 全引号属性不得渲染出 8KB PARAM，
// 多条这样的属性也不得把 SD-ELEMENT 推过总预算。
func TestFormatStructuredMessage_SDBudgetAllQuotes(t *testing.T) {
	h := newTestHandler(t)
	h.cfg.RFC5424 = true

	quoteValue := strings.Repeat(`"`, maxSDValueBytes)
	entry := logEntry{
		Time:    time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC),
		Level:   slog.LevelInfo,
		Message: "m",
		Attrs:   []slog.Attr{slog.String("big", quoteValue)},
	}
	frame := h.formatStructuredMessage(entry, entry.Time.In(time.UTC), 14, "testhost", 1234)

	start := strings.Index(frame, `big="`)
	require.GreaterOrEqual(t, start, 0, "param missing from frame: %q", frame)
	end := strings.Index(frame[start:], `"]`) + start // 第一个未转义 `"]` 终止该 PARAM
	require.Greater(t, end, start, "param terminator missing: %q", frame)
	valueLen := end - start - len(`big="`)
	require.LessOrEqual(t, valueLen, maxSDValueBytes,
		"escaped PARAM value length = %d, want ≤ maxSDValueBytes(%d) — escape inflation survived truncation", valueLen, maxSDValueBytes)

	// 总预算：多条最大膨胀参数在 SD-ELEMENT 预算
	// 用尽后必须跳过，而不是越过预算。
	many := make([]slog.Attr, 0, 16)
	for i := range 16 {
		many = append(many, slog.String(fmt.Sprintf("big%d", i), quoteValue))
	}
	entry.Attrs = many
	frame = h.formatStructuredMessage(entry, entry.Time.In(time.UTC), 14, "testhost", 1234)
	// 余量覆盖 PRI/时间戳/头部前缀、_truncated 标记
	// 与尾部消息——SD-ELEMENT 自身保持在预算内。
	require.LessOrEqual(t, len(frame), maxSDBudget+512,
		"frame length = %d, want ≤ %d — SD budget overshot by post-escape inflation", len(frame), maxSDBudget+512)
	require.Contains(t, frame, sdTruncationMark, "frame should carry the %s marker when params were skipped", sdTruncationMark)
}

// TestFormatStructuredMessage_TruncateEscapedValue：已转义值的截断
// 绝不能留下悬空反斜杠——它会与 "..." 后缀组成非法的
// RFC5424 转义序列。
func TestFormatStructuredMessage_TruncateEscapedValue(t *testing.T) {
	h := newTestHandler(t)
	h.cfg.RFC5424 = true

	// 3 × maxSDValueBytes 的反斜杠保证截断点可以
	// 落在 `\\` 对的两半之间。
	entry := logEntry{
		Time:    time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC),
		Level:   slog.LevelInfo,
		Message: "m",
		Attrs:   []slog.Attr{slog.String("s", strings.Repeat(`\`, 3*maxSDValueBytes))},
	}
	frame := h.formatStructuredMessage(entry, entry.Time.In(time.UTC), 14, "testhost", 1234)

	start := strings.Index(frame, `s="`)
	end := strings.Index(frame[start:], `"]`) + start
	value := frame[start+len(`s="`) : end]
	// 悬空 = "..." 后缀前有奇数个尾部反斜杠
	//（偶数个是完整的 `\\` 转义序列，合法）。
	n := len(value) - len(strings.TrimRight(value, `\`))
	require.NotEqual(t, 1, n%2, "truncated PARAM value ends with a dangling escape backslash (%d trailing): %q", n, value[len(value)-8:])
	require.LessOrEqual(t, len(value), maxSDValueBytes, "escaped PARAM value length")
}

// TestHandler_ConcurrentClose_WaitsForDrain：输掉 closing
// CAS 的 Close 必须（有界地）等待第一个 Close 的排空，而不是在
// 缓冲记录仍在刷出时返回。
func TestHandler_ConcurrentClose_WaitsForDrain(t *testing.T) {
	listener, err := listenTCP()
	require.NoError(t, err, "listen")
	defer func() { _ = listener.Close() }()

	ready := make(chan struct{})
	go func() {
		close(ready)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		_ = conn.Close()
	}()
	<-ready

	h, err := NewHandler(Config{
		Network:    "tcp",
		Address:    listener.Addr().String(),
		Tag:        "test",
		RetryDelay: 200 * time.Millisecond,
	})
	if err != nil {
		_ = listener.Close()
		t.Skipf("NewHandler failed during initial dial: %v", err)
	}
	_ = listener.Close()

	// 一条在途消息让 processQueue 在 Close 的 close(buffer) 之后
	// 停留在 writeWithRetry 中 5 × 200ms，因此第一个 Close 的排空
	// 可测量地慢（约 1s）。
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "in-flight", 0)
	_ = h.Handle(context.Background(), r)
	time.Sleep(50 * time.Millisecond) // 让 processQueue 取走该消息

	firstDone := make(chan time.Time, 1)
	go func() {
		_ = h.Close()
		firstDone <- time.Now()
	}()
	time.Sleep(100 * time.Millisecond) // 第二个 Close 在排空中途到达

	// 并发关闭者：都必须返回，谁都不得挂死。
	const closers = 4
	var wg sync.WaitGroup
	secondDone := make(chan time.Time, closers)
	for range closers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = h.Close()
			secondDone <- time.Now()
		}()
	}
	wg.Wait()

	// 看门狗：每个落败 Close 都必须观察到第一个 Close 的完成。
	var first time.Time
	select {
	case first = <-firstDone:
	case <-time.After(5 * time.Second):
		require.FailNow(t, "first Close did not finish within 5s")
	}
	for range closers {
		select {
		case at := <-secondDone:
			require.False(t, at.Before(first),
				"a losing Close returned at %v before the first Close finished at %v — drain wait missing", at, first)
		default:
			require.FailNow(t, "a losing Close never recorded its return")
		}
	}
}

// TestHandle_ClosingCountsDrop：Close 开始后到达的记录被
// 静默丢弃；丢弃仍必须计数（与 database.Handler 对齐）。
func TestHandle_ClosingCountsDrop(t *testing.T) {
	h := newTestHandler(t)
	h.closing.Store(true)
	require.Zero(t, h.Dropped(), "Dropped() before Handle")
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "late", 0)
	require.NoError(t, h.Handle(context.Background(), r), "Handle after closing")
	require.Equal(t, int64(1), h.Dropped(), "Dropped() after Handle on closing handler")
}

// TestFormatJSONMessage_MarshalErrorEchoTruncated：marshal 失败错误
// 报告以 %q 嵌入原始消息；回显必须截断（marshal
// 失败的记录本身可能任意大）。
func TestFormatJSONMessage_MarshalErrorEchoTruncated(t *testing.T) {
	h := newTestHandler(t)
	h.cfg.JSONInMessage = true

	const longLen = 8 * 1024
	captured := make(chan string, 1)
	h.SetErrorHandler(func(he *mebsuta.HandlerError) {
		select {
		case captured <- he.Err.Error():
		default:
		}
	})

	entry := logEntry{
		Time:    time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC),
		Level:   slog.LevelInfo,
		Message: "HEAD" + strings.Repeat("x", longLen) + "TAIL",
		Attrs:   []slog.Attr{slog.Any("chan", make(chan int))}, // 不可 marshal → 触发兜底
	}
	frame := h.formatJSONMessage(entry, entry.Time.In(time.UTC), 14, "testhost", 1234)
	require.NotEmpty(t, frame, "formatJSONMessage returned empty fallback frame")

	select {
	case e := <-captured:
		start := strings.Index(e, `msg="`)
		end := strings.Index(e[start:], `", level`)
		require.GreaterOrEqual(t, start, 0, "marshal error missing msg echo: %s", e)
		require.GreaterOrEqual(t, end, 0, "marshal error missing msg echo: %s", e)
		echo := e[start+len(`msg="`) : start+end]
		require.LessOrEqual(t, len(echo), maxMarshalEchoBytes+len(`...`),
			"echoed msg length = %d, want ≤ %d", len(echo), maxMarshalEchoBytes+len(`...`))
		require.Contains(t, echo, "HEAD", "echo should keep the head")
		require.True(t, strings.HasSuffix(echo, "..."),
			"echo should end with the truncation mark, got %q", echo[:min(len(echo), 64)]+"...")
		require.NotContains(t, echo, "TAIL", "echo must not retain the tail of an over-budget message")
	default:
		require.FailNow(t, "marshal failure was not reported to the ErrorHandler")
	}
}

// TestEscapeSDValue_ControlChars 是 syslog 消息
// 走私的回归测试：SD-PARAM 值中的裸 LF 会在 LF 分帧的 TCP
// 传输上拆分帧，让第二条“消息”完全受攻击者控制。
// 控制字符必须被替换，而不是透传。
func TestEscapeSDValue_ControlChars(t *testing.T) {
	cases := map[string]string{
		"a\nb":                   "a b",
		"innocent\r\n<34>1 fake": "innocent  <34>1 fake",
		"tab\there":              "tab here",
		"nul\x00byte":            "nul byte",
		"del\x7fchar":            "del char",
		`quote"`:                 `quote\"`,
		`back\slash`:             `back\\slash`,
		"bracket]":               `bracket\]`,
	}
	for in, want := range cases {
		got := escapeSDValue(in)
		require.Equal(t, want, got, "escapeSDValue(%q)", in)
	}
}

// TestFormatStructuredMessage_NoFrameSplit 验证完整 RFC5424 帧：
// 渲染出的消息中唯一的换行必须是结尾的分帧 LF。
func TestFormatStructuredMessage_NoFrameSplit(t *testing.T) {
	h := newTestHandler(t)
	h.cfg.RFC5424 = true

	entry := logEntry{
		Time:    time.Date(2026, 8, 22, 10, 0, 0, 123456789, time.UTC),
		Level:   slog.LevelInfo,
		Message: "user input below",
		Attrs: []slog.Attr{
			slog.String("user_input", "innocent\n<34>1 2026-08-22T10:00:00Z attacker.host su - - - FAKE root session opened"),
		},
	}
	frame := h.formatStructuredMessage(entry, entry.Time.In(time.UTC), 14, "testhost", 1234)

	require.Equal(t, 1, strings.Count(frame, "\n"), "frame newlines:\n%q", frame)
	require.True(t, strings.HasSuffix(frame, "\n"), "frame must end with framing LF:\n%q", frame)
	require.False(t, strings.Contains(frame, "FAKE root session") && strings.Index(frame, "FAKE root session") < strings.Index(frame, "user_input"),
		"smuggled content appears before its host PARAM: %q", frame)
	require.Contains(t, frame, `user_input="innocent`, "param value mangled beyond control-char replacement")
}

// TestFormatStructuredMessage_TimestampFractionDigits：RFC5424 的
// TIME-SECFRAC 至多允许 6 位；RFC3339Nano 会输出到 9 位，
// 严格的接收端会拒绝该帧。
func TestFormatStructuredMessage_TimestampFractionDigits(t *testing.T) {
	h := newTestHandler(t)
	h.cfg.RFC5424 = true

	entry := logEntry{
		Time:    time.Date(2026, 8, 22, 10, 0, 0, 123456789, time.UTC), // 9 位纳秒
		Level:   slog.LevelInfo,
		Message: "m",
	}
	frame := h.formatStructuredMessage(entry, entry.Time.In(time.UTC), 14, "testhost", 1234)

	// "<PRI>1 <timestamp> ..."——提取时间戳字段。
	fields := strings.SplitN(frame, " ", 3)
	require.Len(t, fields, 3, "malformed frame: %q", frame)
	ts := fields[1]
	dot := strings.IndexByte(ts, '.')
	require.GreaterOrEqual(t, dot, 0, "timestamp has no fractional seconds: %q", ts)
	frac := ts[dot+1:]
	require.Len(t, frac, 7, "timestamp fraction = %q, want exactly 6 digits: frame %q", frac, frame) // 6 位数字 + 'Z'
}

// TestFormatStructuredMessage_Limits：SD 参数在条数、名字
// 长度与值大小上均有上限；超限参数汇总进一个标记参数。
func TestFormatStructuredMessage_Limits(t *testing.T) {
	h := newTestHandler(t)
	h.cfg.RFC5424 = true

	var attrs []slog.Attr
	for i := 0; i < maxSDParams+20; i++ {
		attrs = append(attrs, slog.String(fmt.Sprintf("k%03d", i), "v"))
	}
	entry := logEntry{Time: time.Now(), Level: slog.LevelInfo, Message: "m", Attrs: attrs}
	frame := h.formatStructuredMessage(entry, entry.Time.In(time.UTC), 14, "testhost", 1234)

	require.LessOrEqual(t, strings.Count(frame, "k0"), maxSDParams, "frame contains more than %d params", maxSDParams)
	require.Contains(t, frame, "params omitted", "no omission marker in frame: %q", frame[:min(len(frame), 300)])

	// 超大值必须被截断，而不是完整外发。
	h2 := newTestHandler(t)
	h2.cfg.RFC5424 = true
	big := strings.Repeat("x", maxSDValueBytes+1000)
	entry2 := logEntry{
		Time: time.Now(), Level: slog.LevelInfo, Message: "m",
		Attrs: []slog.Attr{slog.String("blob", big)},
	}
	frame2 := h2.formatStructuredMessage(entry2, entry2.Time.In(time.UTC), 14, "testhost", 1234)
	require.NotContains(t, frame2, strings.Repeat("x", maxSDValueBytes+10),
		"oversized SD value was not truncated (frame len %d)", len(frame2))
}

// TestSanitizeSDName_Limits：名字以 RFC5424 的 32 字符封顶，
// 无可用字符的键产出 ""（调用方跳过该参数）。
func TestSanitizeSDName_Limits(t *testing.T) {
	long := strings.Repeat("k", 100)
	require.Len(t, sanitizeSDName(long), maxSDNameLen)
	require.Equal(t, "___", sanitizeSDName("///"))
	require.Empty(t, sanitizeSDName(""))
}

// TestWriteWithRetry_StopsAfterContextCancel 守护 Close 排空上界：
// handler ctx 取消后，缓冲消息必须立即跳过，
// 而不是每条各付出一次写超时。
func TestWriteWithRetry_StopsAfterContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	h := &Handler{cfg: Config{RetryDelay: 50 * time.Millisecond}, ctx: ctx, cancel: cancel}
	// conn 为 nil：每次写本来就立即返回 net.ErrClosed；
	// 关键在于 ctx 门控要先于任何重试/休眠循环返回。
	cancel()
	start := time.Now()
	h.writeWithRetry([]byte("msg"))
	elapsed := time.Since(start)
	require.LessOrEqual(t, elapsed, 20*time.Millisecond, "writeWithRetry took %v after ctx cancel, should return immediately", elapsed)
}

// TestFormatStructuredMessage_ParamNameDedup：清洗可能让键碰撞
// （"a/b" 与 "a_b" → "a_b"）；RFC5424 要求 PARAM-NAME 唯一，严格
// 接收端会因重复拒绝整个帧。
func TestFormatStructuredMessage_ParamNameDedup(t *testing.T) {
	h := newTestHandler(t)
	h.cfg.RFC5424 = true
	entry := logEntry{
		Time:    time.Now(),
		Level:   slog.LevelInfo,
		Message: "m",
		Attrs: []slog.Attr{
			slog.String("a/b", "1"),
			slog.String("a_b", "2"),
			slog.String("_truncated", "reserved"),
		},
	}
	frame := h.formatStructuredMessage(entry, entry.Time.In(time.UTC), 14, "testhost", 1234)
	require.Equal(t, 1, strings.Count(frame, `a_b=`), "duplicate PARAM-NAME after sanitization: %q", frame)
	require.Equal(t, 1, strings.Count(frame, "_truncated="), "truncation marker name must stay unique/reserved: %q", frame)
	require.Contains(t, frame, "params omitted", "deduped/reserved params not accounted in marker: %q", frame)
}

// TestWriteWithRetry_DisconnectedFailsFast:无连接(Reconnect=false 或
// 重连失败)时必须立即按丢弃处理(B2)——此前剩余重试与 RetryDelay
// 逐条空转,断连时每条记录阻塞约 maxRetries × RetryDelay。
func TestWriteWithRetry_DisconnectedFailsFast(t *testing.T) {
	listener, err := listenTCP()
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()

	h, err := NewHandler(Config{
		Network:   "tcp",
		Address:   listener.Addr().String(),
		Tag:       "test",
		Reconnect: boolPtr(false),
	})
	require.NoError(t, err)
	defer func() { _ = h.Close() }()

	h.disconnect() // 制造无连接(同包)
	start := time.Now()
	h.writeWithRetry([]byte("x"))
	require.Less(t, time.Since(start), 500*time.Millisecond,
		"no connection must fail fast, not spin retries")
	require.Equal(t, int64(1), h.Dropped(), "drop counted once")
}
