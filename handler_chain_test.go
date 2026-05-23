package mebsuta

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// =============================================================================
// Handler Chain Integration Tests
// =============================================================================

// chainBuf wraps a bytes.Buffer with mutex for safe concurrent access in tests.
type chainBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *chainBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *chainBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *chainBuf) Lines() []string {
	raw := b.String()
	if raw == "" {
		return nil
	}
	result := splitLines(raw)
	return result
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := s[start:i]
			if line != "" {
				lines = append(lines, line)
			}
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// parseJSONLines parses each line as JSON, returning a slice of maps.
func parseJSONLines(t *testing.T, lines []string) []map[string]any {
	t.Helper()
	result := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("invalid JSON line: %q: %v", line, err)
		}
		result = append(result, m)
	}
	return result
}

// TestChain_SamplingAsyncStdout verifies Sampling -> Async -> Stdout produces
// correctly sampled output with async buffering.
func TestChain_SamplingAsyncStdout(t *testing.T) {
	var buf chainBuf
	stdout := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	sampled := WithSampling(stdout, SamplingConfig{Enabled: true, Initial: 5, Thereafter: 3, Window: time.Second})
	async := WithAsync(sampled, AsyncConfig{BufferSize: 64})
	logger := slog.New(async)

	for i := range 20 {
		logger.Info("msg", "i", i)
	}

	require.NoError(t, CloseAll(logger.Handler()))

	lines := buf.Lines()
	entries := parseJSONLines(t, lines)

	// First 5 should all pass (Initial=5)
	var initialCount int
	for _, e := range entries {
		msg, _ := e["message"].(string)
		if msg == "msg" {
			attrs := e["attributes"].(map[string]any)
			i := int(attrs["i"].(float64))
			if i < 5 {
				initialCount++
			}
		}
	}
	if initialCount != 5 {
		t.Errorf("expected 5 initial records, got %d", initialCount)
	}

	// After initial, only every 3rd should pass (Thereafter=3)
	// Total expected: 5 (initial) + ~5 (sampled from remaining 15) = ~10
	if len(entries) > 15 {
		t.Errorf("sampling should reduce output, got %d entries", len(entries))
	}
}

// TestChain_SamplingAsyncFile verifies Sampling -> Async -> File writes
// correctly to a file with sampling applied.
func TestChain_SamplingAsyncFile(t *testing.T) {
	dir := t.TempDir()
	cfg := FileConfig{Path: filepath.Join(dir, "test.log"), MaxSizeMB: 10}
	fileH, err := NewFileHandler(cfg)
	require.NoError(t, err)

	sampled := WithSampling(fileH, SamplingConfig{Enabled: true, Initial: 100, Thereafter: 10, Window: time.Second})
	async := WithAsync(sampled, AsyncConfig{BufferSize: 64})
	logger := slog.New(async)

	for i := range 50 {
		logger.Info("msg", "i", i)
	}

	require.NoError(t, CloseAll(logger.Handler()))

	data, err := os.ReadFile(filepath.Join(dir, "test.log"))
	require.NoError(t, err)
	lines := splitLines(string(data))
	if len(lines) != 50 {
		t.Errorf("Initial=100 means all 50 should pass, got %d", len(lines))
	}
}

// TestChain_MetricsSamplingAsync verifies Metrics -> Sampling -> Async
// records metrics correctly through the chain.
func TestChain_MetricsSamplingAsync(t *testing.T) {
	var buf chainBuf
	stdout := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})
	mm := &mockMetrics{}

	sampled := WithSampling(stdout, SamplingConfig{Enabled: true, Initial: 100, Thereafter: 1, Window: time.Second})
	async := WithAsync(sampled, AsyncConfig{BufferSize: 64})
	metrics := WithMetrics(async, mm, "chain-test")

	logger := slog.New(metrics)
	for i := range 5 {
		logger.Info("metric msg", "i", i)
	}
	require.NoError(t, CloseAll(logger.Handler()))

	if mm.handleLatency == 0 {
		t.Error("MetricsHandler should have recorded handle latency")
	}

	lines := buf.Lines()
	if len(lines) != 5 {
		t.Errorf("expected 5 output lines, got %d", len(lines))
	}
}

// TestChain_MultiStdoutFile verifies Multi([Stdout, File]) fans out correctly.
func TestChain_MultiStdoutFile(t *testing.T) {
	var buf chainBuf
	stdout := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})

	dir := t.TempDir()
	cfg := FileConfig{Path: filepath.Join(dir, "test.log"), MaxSizeMB: 10}
	fileH, err := NewFileHandler(cfg)
	require.NoError(t, err)

	logger, err := New(
		WithHandler(stdout),
		WithHandler(fileH),
	)
	require.NoError(t, err)

	logger.Info("fanout test", "key", "value")
	require.NoError(t, CloseAll(logger.Handler()))

	// Stdout should have the message
	stdoutLines := buf.Lines()
	if len(stdoutLines) != 1 {
		t.Fatalf("stdout: expected 1 line, got %d", len(stdoutLines))
	}
	entry := parseJSONLines(t, stdoutLines)
	if entry[0]["message"] != "fanout test" {
		t.Errorf("stdout message = %v, want 'fanout test'", entry[0]["message"])
	}

	// File should also have the message
	data, err := os.ReadFile(filepath.Join(dir, "test.log"))
	require.NoError(t, err)
	fileLines := splitLines(string(data))
	if len(fileLines) != 1 {
		t.Fatalf("file: expected 1 line, got %d", len(fileLines))
	}
}

// TestChain_ReverseOrderAsyncSampling verifies Async -> Sampling (reversed order)
// still works correctly, though behavior differs from Sampling -> Async.
func TestChain_ReverseOrderAsyncSampling(t *testing.T) {
	var buf chainBuf
	stdout := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelInfo})

	async := WithAsync(stdout, AsyncConfig{BufferSize: 64})
	sampled := WithSampling(async, SamplingConfig{Enabled: true, Initial: 3, Thereafter: 100, Window: time.Second})

	logger := slog.New(sampled)
	for i := range 10 {
		logger.Info("reverse", "i", i)
	}
	require.NoError(t, CloseAll(logger.Handler()))

	lines := buf.Lines()
	// With reversed order, sampling happens before async buffering.
	// Initial=3 means first 3 pass, rest are sampled away.
	if len(lines) != 3 {
		t.Errorf("expected 3 lines (Initial=3), got %d", len(lines))
	}
}

// TestChain_AuditLevelNotDropped verifies Audit records pass through
// all decorator types without being dropped or sampled.
func TestChain_AuditLevelNotDropped(t *testing.T) {
	var buf chainBuf
	stdout := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelDebug})

	sampled := WithSampling(stdout, SamplingConfig{Enabled: true, Initial: 3, Thereafter: 1000, Window: time.Second})
	async := WithAsync(sampled, AsyncConfig{BufferSize: 64})

	logger := slog.New(async)

	// These should be sampled: only first 3 (Initial=3) pass
	for i := range 10 {
		logger.Info("normal msg", "i", i)
	}

	// Audit should bypass sampling (Level >= Error always passes)
	AuditFunc(logger, "audit event", "action", "login")

	require.NoError(t, CloseAll(logger.Handler()))

	lines := buf.Lines()
	entries := parseJSONLines(t, lines)

	// Audit must be present
	found := false
	for _, e := range entries {
		if e["message"] == "audit event" {
			found = true
			if e["level"] != "AUDIT" {
				t.Errorf("audit level = %v, want AUDIT", e["level"])
			}
		}
	}
	if !found {
		t.Errorf("audit record not found in %d entries", len(entries))
	}

	// Only 3 normal (Initial=3) + 1 audit = 4 total
	if len(entries) != 4 {
		t.Errorf("expected 4 entries (3 normal + 1 audit), got %d", len(entries))
	}
}

// AuditFunc logs at Audit level using the provided logger directly.
func AuditFunc(logger *slog.Logger, msg string, args ...any) {
	logger.Log(context.Background(), LevelAudit, msg, args...)
}

// TestChain_CloseAllPropagation verifies CloseAll propagates through
// the full decorator chain and closes all resources.
func TestChain_CloseAllPropagation(t *testing.T) {
	dir := t.TempDir()
	cfg := FileConfig{Path: filepath.Join(dir, "test.log"), MaxSizeMB: 10}
	fileH, err := NewFileHandler(cfg)
	require.NoError(t, err)

	sampled := WithSampling(fileH, SamplingConfig{Enabled: true, Initial: 100, Thereafter: 1, Window: time.Second})
	async := WithAsync(sampled, AsyncConfig{BufferSize: 64})

	logger := slog.New(async)
	logger.Info("before close")

	// CloseAll should: close Async (drain buffer) -> close Sampling (stop ticker) -> close File
	require.NoError(t, CloseAll(logger.Handler()))

	// Verify file was written before close
	data, err := os.ReadFile(filepath.Join(dir, "test.log"))
	require.NoError(t, err)
	if len(data) == 0 {
		t.Error("file should have data after CloseAll")
	}
}

// TestChain_AuditBypassesAsyncBuffer verifies that Error/Audit level records
// use blocking send in Async, not the non-blocking fast path.
func TestChain_AuditBypassesAsyncBuffer(t *testing.T) {
	var buf chainBuf
	stdout := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelDebug})

	// Tiny buffer to increase chance of drops for normal records
	async := WithAsync(stdout, AsyncConfig{BufferSize: 1})

	logger := slog.New(async)

	// Flood with normal records to fill the tiny buffer
	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			logger.Info("flood", "i", n)
		}(i)
	}
	wg.Wait()

	// Audit should still get through (blocking send with 5s timeout)
	AuditFunc(logger, "critical audit")

	require.NoError(t, CloseAll(logger.Handler()))

	lines := buf.Lines()
	// At minimum, the audit record must be present
	found := false
	for _, line := range lines {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil {
			if m["message"] == "critical audit" {
				found = true
				break
			}
		}
	}
	if !found {
		t.Errorf("audit record not found in %d output lines", len(lines))
	}
}

// mockSelfBuffered is a minimal handler implementing SelfBufferedHandler,
// used to test the generic rejection logic in WithAsync.
type mockSelfBuffered struct{}

func (h *mockSelfBuffered) Enabled(_ context.Context, _ slog.Level) bool  { return true }
func (*mockSelfBuffered) SelfBuffered()                                     {}
func (*mockSelfBuffered) Handle(_ context.Context, _ slog.Record) error   { return nil }
func (h *mockSelfBuffered) WithAttrs(attrs []slog.Attr) slog.Handler      { return h }
func (h *mockSelfBuffered) WithGroup(name string) slog.Handler            { return h }

// TestChain_AsyncWrappingSelfBufferedRejected verifies WithAsync rejects any
// handler implementing SelfBufferedHandler.
func TestChain_AsyncWrappingSelfBufferedRejected(t *testing.T) {
	inner := &mockSelfBuffered{}
	result := WithAsync(inner, AsyncConfig{BufferSize: 64})

	_, isAsync := result.(*AsyncHandler)
	require.False(t, isAsync, "WithAsync should not wrap SelfBufferedHandler")
	require.Same(t, inner, result, "should return the original handler")
}

// TestChain_CloseAllThroughDecorators verifies CloseAll properly closes
// the inner handler through AttrsSub and GroupSub decorators.
func TestChain_CloseAllThroughDecorators(t *testing.T) {
	dir := t.TempDir()
	cfg := FileConfig{Path: filepath.Join(dir, "test.log"), MaxSizeMB: 10}
	fileH, err := NewFileHandler(cfg)
	require.NoError(t, err)

	// Wrap in WithAttrs and WithGroup
	withAttrs := fileH.WithAttrs([]slog.Attr{slog.String("key", "value")})
	withGroup := withAttrs.WithGroup("mygroup")

	logger := slog.New(withGroup)
	logger.Info("test message")

	// CloseAll should propagate through WithGroup -> WithAttrs -> FileHandler
	require.NoError(t, CloseAll(logger.Handler()))

	// Verify file was written and closed
	data, err := os.ReadFile(filepath.Join(dir, "test.log"))
	require.NoError(t, err)
	if len(data) == 0 {
		t.Error("file should have data after CloseAll through decorators")
	}
}
