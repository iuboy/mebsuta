package mebsuta

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/require"

	"github.com/iuboy/mebsuta/go/config"
)

// mockSyslogServer is a simple TCP server for testing syslog handler.
type mockSyslogServer struct {
	listener net.Listener
	messages []string
	mu       sync.Mutex
	conns    []net.Conn
	connMu   sync.Mutex
	closed   atomic.Bool
}

func newMockSyslogServer(t *testing.T) *mockSyslogServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := &mockSyslogServer{listener: ln}
	go srv.acceptLoop()
	return srv
}

func (s *mockSyslogServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.connMu.Lock()
		s.conns = append(s.conns, conn)
		s.connMu.Unlock()
		go s.readLoop(conn)
	}
}

func (s *mockSyslogServer) readLoop(conn net.Conn) {
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 8192), 8192)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			s.mu.Lock()
			s.messages = append(s.messages, line)
			s.mu.Unlock()
		}
	}
}

func (s *mockSyslogServer) Addr() string {
	return s.listener.Addr().String()
}

func (s *mockSyslogServer) Messages() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]string, len(s.messages))
	copy(cp, s.messages)
	return cp
}

func (s *mockSyslogServer) MessageCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.messages)
}

func (s *mockSyslogServer) WaitForMessages(t *testing.T, count int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.MessageCount() >= count {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d messages, got %d", count, s.MessageCount())
}

func (s *mockSyslogServer) CloseAllConnections() {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	for _, c := range s.conns {
		c.Close()
	}
	s.conns = nil
}

func (s *mockSyslogServer) Close() {
	s.closed.Store(true)
	s.listener.Close()
	s.connMu.Lock()
	for _, c := range s.conns {
		c.Close()
	}
	s.conns = nil
	s.connMu.Unlock()
}

func defaultTestConfig(srv *mockSyslogServer) *config.SyslogConfig {
	cfg, _ := config.NewSyslogConfig("tcp", srv.Addr(),
		config.WithSyslogTag("test"),
		config.WithSyslogFacility(1),
		config.WithSyslogRetryDelay(100*time.Millisecond),
		config.WithBufferSize(100),
	)
	return cfg
}

// =============================================================================
// TestSyslogHandler_Handle — verify records are sent to mock server
// =============================================================================

func TestSyslogHandler_Handle(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.Close()

	h, err := NewSyslogHandler(defaultTestConfig(srv), slog.LevelDebug)
	require.NoError(t, err)
	defer h.Close()

	logger := slog.New(h)
	logger.Info("hello syslog", "key", "value")

	srv.WaitForMessages(t, 1, 3*time.Second)
	msgs := srv.Messages()
	require.Len(t, msgs, 1)
	require.Contains(t, msgs[0], "hello syslog")
}

func TestSyslogHandler_Handle_MultipleRecords(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.Close()

	h, err := NewSyslogHandler(defaultTestConfig(srv), slog.LevelDebug)
	require.NoError(t, err)
	defer h.Close()

	logger := slog.New(h)
	for i := range 5 {
		logger.Info("msg", "i", i)
	}

	srv.WaitForMessages(t, 5, 5*time.Second)
	require.Equal(t, 5, srv.MessageCount())
}

// =============================================================================
// TestSyslogHandler_Close — verify graceful shutdown
// =============================================================================

func TestSyslogHandler_Close(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.Close()

	h, err := NewSyslogHandler(defaultTestConfig(srv), slog.LevelDebug)
	require.NoError(t, err)

	logger := slog.New(h)
	logger.Info("before close")
	srv.WaitForMessages(t, 1, 3*time.Second)

	require.NoError(t, h.Close())

	// Second close should be idempotent
	require.NoError(t, h.Close())

	// Handle after close should return nil
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "after close", 0)
	require.NoError(t, h.Handle(context.Background(), r))
}

// TestSyslogHandler_CloseFlushesBufferedMessages verifies that Close() drains
// all messages still in the buffer — matching the persistence-boundary contract
// in SPEC.md §Close.
func TestSyslogHandler_CloseFlushesBufferedMessages(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.Close()

	h, err := NewSyslogHandler(defaultTestConfig(srv), slog.LevelDebug)
	require.NoError(t, err)

	const n = 10
	for i := range n {
		r := slog.NewRecord(time.Now(), slog.LevelInfo, fmt.Sprintf("buffered-%d", i), 0)
		require.NoError(t, h.Handle(context.Background(), r))
	}

	// Close without waiting for any messages — Close must flush them all.
	require.NoError(t, h.Close())

	srv.WaitForMessages(t, n, 5*time.Second)
	msgs := srv.Messages()
	require.Len(t, msgs, n, "Close should flush all buffered messages")

	received := make(map[string]bool, n)
	for _, m := range msgs {
		received[m] = true
	}
	for i := range n {
		require.True(t, received[fmt.Sprintf("buffered-%d", i)] ||
			func() bool {
				for m := range received {
					if strings.Contains(m, fmt.Sprintf("buffered-%d", i)) {
						return true
					}
				}
				return false
			}(),
			"message buffered-%d should be received", i)
	}
}

func TestSyslogHandler_CloseDoesNotRetryUnavailableConn(t *testing.T) {
	client, server := net.Pipe()
	require.NoError(t, server.Close())

	ctx, cancel := context.WithCancel(context.Background())
	testCfg, _ := config.NewSyslogConfig("tcp", "localhost", config.WithSyslogRetryDelay(time.Hour))
	h := &SyslogHandler{
		LevelHandler: LevelHandler{Level: slog.LevelDebug},
		cfg:          testCfg,
		conn:         client,
		buffer:       make(chan []byte, 1),
		ctx:          ctx,
		cancel:       cancel,
	}
	eh := ErrorHandler(func(string, error) {})
	h.errorHandler.Store(&eh)
	h.buffer <- []byte("close-boundary\n")

	h.wg.Add(1)
	go h.processQueue()

	start := time.Now()
	require.NoError(t, h.Close())
	require.Less(t, time.Since(start), 500*time.Millisecond)
}

// =============================================================================
// TestSyslogHandler_Reconnect — verify reconnect establishes new connection
// =============================================================================

func TestSyslogHandler_Reconnect(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.Close()

	cfg, _ := config.NewSyslogConfig("tcp", srv.Addr(),
		config.WithSyslogTag("test"),
		config.WithSyslogFacility(1),
		config.WithSyslogRetryDelay(50*time.Millisecond),
		config.WithBufferSize(100),
	)

	h, err := NewSyslogHandler(cfg, slog.LevelDebug)
	require.NoError(t, err)
	defer h.Close()

	// Verify initially connected
	require.True(t, h.isConnected(), "should be connected initially")

	// Sever the connection on the server side
	srv.CloseAllConnections()
	time.Sleep(50 * time.Millisecond)

	// Handler's conn is now broken but non-nil
	// Force a disconnect + reconnect
	h.disconnect()
	require.False(t, h.isConnected(), "should be disconnected after disconnect()")

	h.reconnect()
	require.True(t, h.isConnected(), "should be reconnected after reconnect()")

	// Verify writing works on the new connection
	logger := slog.New(h)
	logger.Info("after reconnect")
	srv.WaitForMessages(t, 1, 3*time.Second)
	msgs := srv.Messages()
	require.Len(t, msgs, 1)
	require.Contains(t, msgs[0], "after reconnect")
}

// =============================================================================
// TestSyslogHandler_FormatMessages — verify format output
// =============================================================================

func TestSyslogHandler_FormatMessages_Structured(t *testing.T) {
	loc, _ := time.LoadLocation("UTC")
	h := &SyslogHandler{
		LevelHandler: LevelHandler{Level: slog.LevelDebug},
		cfg: func() *config.SyslogConfig {
			c, _ := config.NewSyslogConfig("tcp", "localhost", config.WithSyslogFacility(1), config.WithSyslogTag("test"))
			return c
		}(),
		location: loc,
	}

	entry := LogEntry{
		Time:    time.Date(2026, 1, 15, 10, 30, 0, 0, loc),
		Level:   slog.LevelInfo,
		Message: "structured test",
	}
	msg := h.formatMessage(entry)

	// priority = 1*8 + 6 = 14
	require.Contains(t, msg, "<14>")
	require.Contains(t, msg, "structured test")
}

func TestSyslogHandler_FormatMessages_StructuredRFC5424(t *testing.T) {
	loc, _ := time.LoadLocation("UTC")
	h := &SyslogHandler{
		LevelHandler: LevelHandler{Level: slog.LevelDebug},
		cfg: func() *config.SyslogConfig {
			c, _ := config.NewSyslogConfig("tcp", "localhost", config.WithSyslogFacility(1), config.WithSyslogTag("test"), config.WithRFC5424(true))
			return c
		}(),
		location: loc,
	}

	entry := LogEntry{
		Time:    time.Date(2026, 1, 15, 10, 30, 0, 0, loc),
		Level:   slog.LevelError,
		Message: "rfc5424 test",
		Attrs:   []slog.Attr{slog.String("code", "500")},
	}
	msg := h.formatMessage(entry)

	require.Contains(t, msg, "<11>")
	require.Contains(t, msg, "<11>1 ")
	require.Contains(t, msg, "rfc5424 test")
	require.Contains(t, msg, `code="500"`)
}

func TestSyslogHandler_FormatMessages_JSON(t *testing.T) {
	loc, _ := time.LoadLocation("UTC")
	h := &SyslogHandler{
		LevelHandler: LevelHandler{Level: slog.LevelDebug},
		cfg: func() *config.SyslogConfig {
			c, _ := config.NewSyslogConfig("tcp", "localhost", config.WithSyslogFacility(1), config.WithSyslogTag("test"), config.WithJSONInMessage(true))
			return c
		}(),
		location: loc,
	}

	entry := LogEntry{
		Time:    time.Date(2026, 1, 15, 10, 30, 0, 0, loc),
		Level:   slog.LevelWarn,
		Message: "json format test",
		Attrs:   []slog.Attr{slog.String("module", "auth")},
	}
	msg := h.formatMessage(entry)

	require.Contains(t, msg, "<12>")

	idx := strings.Index(msg, "{")
	require.GreaterOrEqual(t, idx, 0)

	var data map[string]any
	err := json.Unmarshal([]byte(msg[idx:]), &data)
	require.NoError(t, err)
	require.Equal(t, "json format test", data["message"])
	require.Equal(t, "WARN", data["level"])
	attrs := data["attributes"].(map[string]any)
	require.Equal(t, "auth", attrs["module"])
}

// =============================================================================
// TestSyslogHandler_PriorityCalculation — verify facility*8+severity
// =============================================================================

func TestSyslogHandler_PriorityCalc(t *testing.T) {
	loc, _ := time.LoadLocation("UTC")
	h := &SyslogHandler{
		LevelHandler: LevelHandler{Level: slog.LevelDebug},
		cfg: func() *config.SyslogConfig {
			c, _ := config.NewSyslogConfig("tcp", "localhost", config.WithSyslogFacility(1), config.WithSyslogTag("test"))
			return c
		}(),
		location: loc,
	}

	tests := []struct {
		level    slog.Level
		expected int
	}{
		{slog.LevelDebug, 1*8 + 7}, // 15
		{slog.LevelInfo, 1*8 + 6},  // 14
		{slog.LevelWarn, 1*8 + 4},  // 12
		{slog.LevelError, 1*8 + 3}, // 11
		{LevelAudit, 1*8 + 2},      // 10
	}

	for _, tt := range tests {
		entry := LogEntry{Time: time.Now().In(loc), Level: tt.level, Message: "test"}
		msg := h.formatMessage(entry)
		prefix := fmt.Sprintf("<%d>", tt.expected)
		require.Contains(t, msg, prefix, "level=%v priority", tt.level)
	}
}

// =============================================================================
// TestSyslogHandler_LevelSeverity — verify severity mapping
// =============================================================================

func TestSyslogHandler_LevelSeverity(t *testing.T) {
	h := &SyslogHandler{}
	tests := []struct {
		level    slog.Level
		expected int
	}{
		{slog.LevelDebug, 7},
		{slog.LevelInfo, 6},
		{slog.LevelWarn, 4},
		{slog.LevelError, 3},
		{LevelAudit, 2},
	}
	for _, tt := range tests {
		require.Equal(t, tt.expected, h.levelToSeverity(tt.level), "levelToSeverity(%v)", tt.level)
	}
}

// =============================================================================
// TestSyslogHandler_ConcurrentWrites — verify no data race
// =============================================================================

func TestSyslogHandler_ConcurrentWrites(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.Close()

	h, err := NewSyslogHandler(defaultTestConfig(srv), slog.LevelDebug)
	require.NoError(t, err)
	defer h.Close()

	logger := slog.New(h)
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			logger.Info("concurrent", "n", n)
		}(i)
	}
	wg.Wait()

	srv.WaitForMessages(t, 50, 5*time.Second)
	require.Equal(t, 50, srv.MessageCount())
}

// =============================================================================
// TestSyslogHandler_BufferFull — verify safeSend drops on full buffer
// =============================================================================

func TestSyslogHandler_BufferFull(t *testing.T) {
	// Test safeSend directly with a full channel (no consumer)
	h := &SyslogHandler{
		LevelHandler: LevelHandler{Level: slog.LevelDebug},
		cfg: func() *config.SyslogConfig {
			c, _ := config.NewSyslogConfig("tcp", "localhost", config.WithSyslogFacility(1), config.WithSyslogTag("test"))
			return c
		}(),
		buffer: make(chan []byte, 1),
	}

	// Fill the buffer
	h.buffer <- []byte("first")

	// Next send should return buffer full error
	err := h.safeSend([]byte("overflow"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "buffer full")
}

// =============================================================================
// TestSyslogHandler_LevelAudit — verify audit records are sent
// =============================================================================

func TestSyslogHandler_LevelAudit(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.Close()

	h, err := NewSyslogHandler(defaultTestConfig(srv), slog.LevelError)
	require.NoError(t, err)
	defer h.Close()

	logger := slog.New(h)

	// Info should be filtered by level
	logger.Info("should be filtered")

	// Audit should pass (LevelAudit >= LevelError)
	logger.Log(context.Background(), LevelAudit, "audit event", "action", "login")

	srv.WaitForMessages(t, 1, 3*time.Second)
	msgs := srv.Messages()
	require.Len(t, msgs, 1)
	require.Contains(t, msgs[0], "audit event")
}

// =============================================================================
// TestSyslogHandler_EscapeSDValue — structured data value escaping
// =============================================================================

func TestSyslogHandler_EscapeSDValue(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{`has"quote`, `has\"quote`},
		{`has\backslash`, `has\\backslash`},
		{`has]bracket`, `has\]bracket`},
	}

	for _, tt := range tests {
		got := escapeSDValue(tt.input)
		require.Equal(t, tt.expected, got, "escapeSDValue(%q)", tt.input)
	}
}

// =============================================================================
// TestSyslogHandler_CleanHostname — hostname sanitization
// =============================================================================

func TestSyslogHandler_CleanHostname(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"my-host.example.com", "my-host.example.com"},
		{"HOST.NAME", "HOST.NAME"},
		{"host with spaces", "host-with-spaces"},
		{"", ""},
		{"192.168.1.1", "192.168.1.1"},
	}

	for _, tt := range tests {
		got := cleanHostname(tt.input)
		require.Equal(t, tt.expected, got, "cleanHostname(%q)", tt.input)
	}
}

// =============================================================================
// TestSyslogHandler_BackoffDelay — verify exponential backoff
// =============================================================================

func TestSyslogHandler_BackoffDelay(t *testing.T) {
	// With retries=0, base is 1s, result should be 500ms..1s
	d0 := backoffDelay(0)
	require.GreaterOrEqual(t, d0, 500*time.Millisecond)
	require.LessOrEqual(t, d0, time.Second)

	// With retries=1, base is 2s, result should be 1s..2s
	d1 := backoffDelay(1)
	require.GreaterOrEqual(t, d1, time.Second)
	require.LessOrEqual(t, d1, 2*time.Second)

	// High retry count should be capped at maxReconnectDelay
	dHigh := backoffDelay(30)
	require.LessOrEqual(t, dHigh, maxReconnectDelay)
}

// =============================================================================
// TestSyslogHandler_WithAttrs_WithGroup — verify chain returns correct types
// =============================================================================

func TestSyslogHandler_MockWithAttrs(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.Close()

	h, err := NewSyslogHandler(defaultTestConfig(srv), slog.LevelDebug)
	require.NoError(t, err)
	defer h.Close()

	child := h.WithAttrs([]slog.Attr{slog.String("preset", "val")})
	attrsH, ok := child.(*AttrsSub[*SyslogHandler])
	require.True(t, ok, "WithAttrs should return *AttrsSub[*SyslogHandler]")
	require.Len(t, attrsH.Attrs, 1)
	require.Equal(t, "preset", attrsH.Attrs[0].Key)
}

func TestSyslogHandler_MockWithGroup(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.Close()

	h, err := NewSyslogHandler(defaultTestConfig(srv), slog.LevelDebug)
	require.NoError(t, err)
	defer h.Close()

	child := h.WithGroup("request")
	groupH, ok := child.(*GroupSub[*SyslogHandler])
	require.True(t, ok, "WithGroup should return *GroupSub[*SyslogHandler]")
	require.Equal(t, "request", groupH.Group)
}

// =============================================================================
// TestSyslogHandler_NewConnectionFailure — verify constructor error
// =============================================================================

func TestSyslogHandler_NewConnectionFailure(t *testing.T) {
	cfg, _ := config.NewSyslogConfig("tcp", "127.0.0.1:1",
		config.WithSyslogTag("test"),
		config.WithSyslogFacility(1),
		config.WithSyslogRetryDelay(100*time.Millisecond),
		config.WithBufferSize(10),
	)

	_, err := NewSyslogHandler(cfg, slog.LevelInfo)
	require.Error(t, err)
	require.Contains(t, err.Error(), "initial connection failed")
}

// =============================================================================
// TestSyslogHandler_SafeMessageForLog — verify control char stripping
// =============================================================================

func TestSyslogHandler_SafeMessageForLog(t *testing.T) {
	require.Equal(t, "hello world", safeMessageForLog("hello\x00world"))
	require.Equal(t, "a b c", safeMessageForLog("a\x01b\x02c"))
	require.Equal(t, "clean", safeMessageForLog("clean"))
}

// =============================================================================
// TestTruncateUTF8 — verify UTF-8-safe truncation
// =============================================================================

func TestTruncateUTF8_ASCII(t *testing.T) {
	require.Equal(t, "short", truncateUTF8("short", 100))
	require.Equal(t, "ab...", truncateUTF8("abcdef", 5))
	require.Equal(t, "abcdef", truncateUTF8("abcdef", 6))  // exact fit, no truncation
	require.Equal(t, "abcdef", truncateUTF8("abcdef", 10)) // larger, no truncation
}

func TestTruncateUTF8_2ByteUTF8(t *testing.T) {
	// "é" = 2 bytes (0xC3 0xA9)
	s := "café"
	require.Equal(t, "café", truncateUTF8(s, 10)) // no truncation needed
	// "ééééé" = 10 bytes, max=9 -> truncate at boundary
	result := truncateUTF8("ééééé", 9)
	require.True(t, utf8.ValidString(result), "result must be valid UTF-8")
	require.LessOrEqual(t, len(result), 9)
	require.True(t, strings.HasSuffix(result, "..."))
}

func TestTruncateUTF8_3ByteUTF8(t *testing.T) {
	// "你" = 3 bytes
	result := truncateUTF8("你好世界更多内容", 15)
	require.True(t, utf8.ValidString(result), "result must be valid UTF-8")
	require.LessOrEqual(t, len(result), 15)
}

func TestTruncateUTF8_NoSplit(t *testing.T) {
	// Ensure a multi-byte character is never split
	s := "aé你🎉b"
	for max := 1; max <= len(s); max++ {
		result := truncateUTF8(s, max)
		require.True(t, utf8.ValidString(result), "max=%d result must be valid UTF-8: %q", max, result)
		require.LessOrEqual(t, len(result), max, "max=%d result must fit in budget", max)
	}
}

func TestTruncateUTF8_EdgeCases(t *testing.T) {
	require.Equal(t, "", truncateUTF8("", 10))
	require.Equal(t, "abc", truncateUTF8("abc", 3))
	require.Equal(t, "", truncateUTF8("hello", 0))
	require.Equal(t, "a", truncateUTF8("abcdef", 1))
	require.Equal(t, "é", truncateUTF8("éabc", 2))
}
