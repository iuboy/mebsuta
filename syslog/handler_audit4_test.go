package syslog

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iuboy/mebsuta"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Batch D audit regressions: lock-held ReportError deadlock, SD LogValuer
// resolution, SD escape-then-truncate budgets, Close idempotent drain wait,
// post-close drop accounting, marshal-failure echo truncation.
// =============================================================================

// TestSafeSend_ErrorHandlerReentrantClose exercises the deadlock fix: safeSend
// used to call ReportError while holding sendMu.RLock, so a user ErrorHandler
// that re-entered Close (sendMu.Lock) deadlocked against itself forever. The
// handler here does exactly that; a 2s watchdog fails the test instead of
// hanging the suite if the deadlock ever regresses.
func TestSafeSend_ErrorHandlerReentrantClose(t *testing.T) {
	listener, err := listenTCP()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	// Accept one connection then kill it with RST (SetLinger(0)) so writes
	// fail instantly and writeWithRetry only costs RetryDelay per attempt —
	// the drain inside Close stays well under the watchdog.
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
		Network:      "tcp",
		Address:      listener.Addr().String(),
		Tag:          "test",
		BufferSize:   1,
		RetryDelay:   100 * time.Millisecond,
		ErrorTimeout: 50 * time.Millisecond,
		Reconnect:    boolPtr(false),
	})
	// Some CI runners deliver the RST during the initial dial; the deadlock
	// regression needs a live handler, so bail out without failing.
	if err != nil {
		_ = listener.Close()
		t.Skipf("NewHandler failed during initial dial: %v", err)
	}

	var ehCalls atomic.Int32
	h.setErrorHandler(func(*mebsuta.HandlerError) {
		ehCalls.Add(1)
		_ = h.Close() // re-entrant Close from inside the error report
	})

	// Deterministic trigger: after the RST lands, fill-0 sends processQueue
	// into writeWithRetry's 5 × RetryDelay retry sleeps (~500ms stuck), the
	// fill-1 record occupies the only buffer slot, and the Error-level
	// trigger then hits the full-buffer timeout and reports — the report that
	// used to fire while safeSend still held sendMu.RLock.
	_ = listener.Close()
	time.Sleep(10 * time.Millisecond) // let the RST reach the client
	fill := slog.NewRecord(time.Now(), slog.LevelInfo, "fill", 0)
	_ = h.Handle(context.Background(), fill) // consumed by processQueue → stuck in retries
	time.Sleep(2 * time.Millisecond)
	slot := slog.NewRecord(time.Now(), slog.LevelInfo, "slot", 0)
	_ = h.Handle(context.Background(), slot) // occupies the buffer slot
	r := slog.NewRecord(time.Now(), slog.LevelError, "trigger", 0)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = h.Handle(context.Background(), r)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		buf := make([]byte, 64*1024)
		buf = buf[:runtime.Stack(buf, true)]
		t.Fatalf("Handle did not return within 2s — ErrorHandler re-entering Close deadlocked on sendMu\nStacks:\n%s", buf)
	}
	if ehCalls.Load() == 0 {
		t.Fatal("error handler was never invoked; drop report did not reach the ErrorHandler")
	}
	// First Close already ran inside the ErrorHandler; this returns via the
	// idempotent drainDone wait.
	_ = h.Close()
}

// TestFormatStructuredMessage_LogValuerResolved: SD-PARAM values must be the
// Resolve()d string, not the fmt rendering of the LogValuer's internal
// representation (sensitive fields wrapped in a redacting LogValuer leaked
// their wrapper struct before the fix).
func TestFormatStructuredMessage_LogValuerResolved(t *testing.T) {
	h := newTestHandler(t)
	h.cfg.RFC5424 = true

	entry := mebsuta.LogEntry{
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

// selfValuer returns a group containing itself, the worst-case
// LogValuer→group cycle; SD collection must depth-cap instead of looping.
type selfValuer struct{}

func (selfValuer) LogValue() slog.Value {
	return slog.Group("loop", slog.Any("self", selfValuer{})).Value
}

// TestFormatStructuredMessage_SDBudgetAllQuotes: escaping can double a value
// of all quotes, so truncation must happen after escaping (escape-then-
// truncate). A single 4KB all-quote attr must not render an 8KB PARAM, and
// many of them must not push the SD-ELEMENT past its total budget.
func TestFormatStructuredMessage_SDBudgetAllQuotes(t *testing.T) {
	h := newTestHandler(t)
	h.cfg.RFC5424 = true

	quoteValue := strings.Repeat(`"`, maxSDValueBytes)
	entry := mebsuta.LogEntry{
		Time:    time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC),
		Level:   slog.LevelInfo,
		Message: "m",
		Attrs:   []slog.Attr{slog.String("big", quoteValue)},
	}
	frame := h.formatStructuredMessage(entry, entry.Time.In(time.UTC), 14, "testhost", 1234)

	start := strings.Index(frame, `big="`)
	if start < 0 {
		t.Fatalf("param missing from frame: %q", frame)
	}
	end := strings.Index(frame[start:], `"]`) + start // first unescaped `"]` terminates the PARAM
	if end <= start {
		t.Fatalf("param terminator missing: %q", frame)
	}
	valueLen := end - start - len(`big="`)
	if valueLen > maxSDValueBytes {
		t.Errorf("escaped PARAM value length = %d, want ≤ maxSDValueBytes(%d) — escape inflation survived truncation", valueLen, maxSDValueBytes)
	}

	// Total-budget: many maximally-inflating params must skip once the
	// SD-ELEMENT budget is reached instead of overshooting it.
	many := make([]slog.Attr, 0, 16)
	for i := range 16 {
		many = append(many, slog.String(fmt.Sprintf("big%d", i), quoteValue))
	}
	entry.Attrs = many
	frame = h.formatStructuredMessage(entry, entry.Time.In(time.UTC), 14, "testhost", 1234)
	// Margin covers the PRI/TIMESTAMP/HEADER prefix, the _truncated marker
	// and the trailing message — the SD-ELEMENT itself stays within budget.
	if len(frame) > maxSDBudget+512 {
		t.Errorf("frame length = %d, want ≤ %d — SD budget overshot by post-escape inflation", len(frame), maxSDBudget+512)
	}
	if !strings.Contains(frame, sdTruncationMark) {
		t.Errorf("frame should carry the %s marker when params were skipped: %q", sdTruncationMark, frame)
	}
}

// TestFormatStructuredMessage_TruncateEscapedValue: truncation of an escaped
// value must never leave a dangling backslash that would pair with the "..."
// suffix into an illegal RFC5424 escape sequence.
func TestFormatStructuredMessage_TruncateEscapedValue(t *testing.T) {
	h := newTestHandler(t)
	h.cfg.RFC5424 = true

	// 3 × maxSDValueBytes of backslashes guarantees the truncation point can
	// land between the halves of a `\\` pair.
	entry := mebsuta.LogEntry{
		Time:    time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC),
		Level:   slog.LevelInfo,
		Message: "m",
		Attrs:   []slog.Attr{slog.String("s", strings.Repeat(`\`, 3*maxSDValueBytes))},
	}
	frame := h.formatStructuredMessage(entry, entry.Time.In(time.UTC), 14, "testhost", 1234)

	start := strings.Index(frame, `s="`)
	end := strings.Index(frame[start:], `"]`) + start
	value := frame[start+len(`s="`) : end]
	// Dangling = an odd number of trailing backslashes right before the "..."
	// suffix (an even count is a sequence of complete `\\` escapes and legal).
	n := len(value) - len(strings.TrimRight(value, `\`))
	if n%2 == 1 {
		t.Errorf("truncated PARAM value ends with a dangling escape backslash (%d trailing): %q", n, value[len(value)-8:])
	}
	if len(value) > maxSDValueBytes {
		t.Errorf("escaped PARAM value length = %d, want ≤ %d", len(value), maxSDValueBytes)
	}
}

// TestHandler_ConcurrentClose_WaitsForDrain: a Close that loses the closing
// CAS must wait (bounded) for the first Close's drain instead of returning
// while buffered records are still being flushed.
func TestHandler_ConcurrentClose_WaitsForDrain(t *testing.T) {
	listener, err := listenTCP()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
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

	// One in-flight message keeps processQueue inside writeWithRetry for
	// 5 × 200ms after Close's close(buffer), so the first Close's drain is
	// measurably slow (~1s).
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "in-flight", 0)
	_ = h.Handle(context.Background(), r)
	time.Sleep(50 * time.Millisecond) // let processQueue pick the message up

	firstDone := make(chan time.Time, 1)
	go func() {
		_ = h.Close()
		firstDone <- time.Now()
	}()
	time.Sleep(100 * time.Millisecond) // second Close arrives mid-drain

	// Concurrent closers: all must return, none may hang.
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

	// Watchdog: every loser Close must observe the first Close's completion.
	var first time.Time
	select {
	case first = <-firstDone:
	case <-time.After(5 * time.Second):
		t.Fatal("first Close did not finish within 5s")
	}
	for range closers {
		select {
		case at := <-secondDone:
			if at.Before(first) {
				t.Errorf("a losing Close returned at %v before the first Close finished at %v — drain wait missing", at, first)
			}
		default:
			t.Fatal("a losing Close never recorded its return")
		}
	}
}

// TestHandle_ClosingCountsDrop: records arriving after Close started are
// dropped silently; the drop must still be counted (database.Handler parity).
func TestHandle_ClosingCountsDrop(t *testing.T) {
	h := newTestHandler(t)
	h.closing.Store(true)
	if got := h.Dropped(); got != 0 {
		t.Fatalf("Dropped() = %d, want 0 before Handle", got)
	}
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "late", 0)
	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatalf("Handle after closing returned %v, want nil", err)
	}
	if got := h.Dropped(); got != 1 {
		t.Errorf("Dropped() = %d, want 1 after Handle on closing handler", got)
	}
}

// TestFormatJSONMessage_MarshalErrorEchoTruncated: the marshal-failure error
// report embeds the original message with %q; the echo must be truncated (the
// record that failed to marshal can itself be arbitrarily large).
func TestFormatJSONMessage_MarshalErrorEchoTruncated(t *testing.T) {
	h := newTestHandler(t)
	h.cfg.JSONInMessage = true

	const longLen = 8 * 1024
	captured := make(chan string, 1)
	h.setErrorHandler(func(he *mebsuta.HandlerError) {
		select {
		case captured <- he.Err.Error():
		default:
		}
	})

	entry := mebsuta.LogEntry{
		Time:    time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC),
		Level:   slog.LevelInfo,
		Message: "HEAD" + strings.Repeat("x", longLen) + "TAIL",
		Attrs:   []slog.Attr{slog.Any("chan", make(chan int))}, // unmarshalable → triggers the fallback
	}
	frame := h.formatJSONMessage(entry, entry.Time.In(time.UTC), 14, "testhost", 1234)
	if frame == "" {
		t.Fatal("formatJSONMessage returned empty fallback frame")
	}

	select {
	case e := <-captured:
		start := strings.Index(e, `msg="`)
		end := strings.Index(e[start:], `", level`)
		if start < 0 || end < 0 {
			t.Fatalf("marshal error missing msg echo: %s", e)
		}
		echo := e[start+len(`msg="`) : start+end]
		if len(echo) > maxMarshalEchoBytes+len(`...`) {
			t.Errorf("echoed msg length = %d, want ≤ %d", len(echo), maxMarshalEchoBytes+len(`...`))
		}
		if !strings.Contains(echo, "HEAD") || !strings.HasSuffix(echo, "...") {
			t.Errorf("echo should keep the head and end with the truncation mark, got %q", echo[:min(len(echo), 64)]+"...")
		}
		if strings.Contains(echo, "TAIL") {
			t.Error("echo must not retain the tail of an over-budget message")
		}
	default:
		t.Fatal("marshal failure was not reported to the ErrorHandler")
	}
}
