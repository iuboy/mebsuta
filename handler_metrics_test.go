package mebsuta

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type recordingMetrics struct {
	mu       sync.Mutex
	handles  int
	errors   int
	dropped  int64
	panicsOn string // when non-empty, every method with this op name panics
}

func (m *recordingMetrics) ObserveHandle(time.Duration) {
	if m.panicsOn == "observe" {
		panic("metrics exploded")
	}
	m.mu.Lock()
	m.handles++
	m.mu.Unlock()
}

func (m *recordingMetrics) IncError(string) {
	if m.panicsOn == "error" {
		panic("metrics exploded")
	}
	m.mu.Lock()
	m.errors++
	m.mu.Unlock()
}

func (m *recordingMetrics) IncDroppedN(_ string, n int64) {
	if m.panicsOn == "dropped" {
		panic("metrics exploded")
	}
	m.mu.Lock()
	m.dropped += n
	m.mu.Unlock()
}

// TestMetricsHandler_SurfacesDrops: buffer-full floods inside the wrapped
// chain must show up as IncDropped — previously the counter existed but no
// library code ever called it, so mebsuta_log_dropped_total stayed 0.
func TestMetricsHandler_SurfacesDrops(t *testing.T) {
	block := make(chan struct{})
	inner := blockingHandler{block: block}

	m := &recordingMetrics{}
	h := WithMetrics(
		WithAsync(inner, AsyncConfig{BufferSize: 2}),
		m, "test",
	)
	defer func() { close(block) }()

	logger := slog.New(h)
	for i := 0; i < 100; i++ {
		logger.Info("flood")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		dropped := m.dropped
		m.mu.Unlock()
		if dropped >= 1 {
			return // surfaced
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.FailNow(t, "drops never surfaced to IncDropped")
}

// TestMetricsHandler_MetricsPanicContained: a panicking user metrics
// implementation must not kill the log call.
func TestMetricsHandler_MetricsPanicContained(t *testing.T) {
	var buf mutexBuffer
	m := &recordingMetrics{panicsOn: "observe"}
	h := WithMetrics(newContractJSONHandler(&buf, nil), m, "test")

	logger := slog.New(h)
	logger.Info("must survive")
	require.Contains(t, buf.String(), "must survive", "record lost after metrics panic")
}

// jumpDropHandler simulates a buffering handler whose Dropped counter jumps
// by a whole batch between two Handle calls (e.g. a database flush failure
// dropping every queued record at once).
type jumpDropHandler struct {
	dropped atomic.Int64
}

func (h *jumpDropHandler) Dropped() int64 { return h.dropped.Load() }
func (h *jumpDropHandler) Enabled(context.Context, slog.Level) bool {
	return true
}
func (h *jumpDropHandler) Handle(context.Context, slog.Record) error {
	// Batch flush failure: N queued records die together.
	h.dropped.Store(25)
	return nil
}
func (h *jumpDropHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *jumpDropHandler) WithGroup(string) slog.Handler      { return h }
func (h *jumpDropHandler) unwrapHandler() slog.Handler        { return nil }

// TestMetricsHandler_DroppedByMagnitude: IncDroppedN must carry the size of
// the drop (25), not a per-Handle +1 — the counter jump happened inside one
// Handle call, so a count-based increment under-reports 25:1.
func TestMetricsHandler_DroppedByMagnitude(t *testing.T) {
	m := &recordingMetrics{}
	h := WithMetrics(&jumpDropHandler{}, m, "db")

	// First Handle: counter still 0, no drop surfaced yet.
	_ = h.Handle(context.Background(), slog.NewRecord(time.Now(), slog.LevelInfo, "prime", 0))
	// Second Handle: the inner "flush" failed and dropped 25 records at once.
	_ = h.Handle(context.Background(), slog.NewRecord(time.Now(), slog.LevelInfo, "batch", 0))

	m.mu.Lock()
	defer m.mu.Unlock()
	require.Equal(t, int64(25), m.dropped, "reported dropped total (full magnitude of the jump)")
}

// TestSafeMulti_ErrorHandlerAtomic: setErrorHandler swaps the callback while
// concurrent Handle calls read it — with the old bare *ErrorHandler this was
// a data race (-race is the oracle). The shared-slot clone semantics must
// also survive: a swap via a WithAttrs clone is visible to the original.
func TestSafeMulti_ErrorHandlerAtomic(t *testing.T) {
	bad := &panicHandler{msg: "boom"}
	h := safeMultiHandler([]slog.Handler{bad}, SilentErrorHandler()).(*safeMulti)

	var mu sync.Mutex
	reports := 0
	h.setErrorHandler(func(*HandlerError) {
		mu.Lock()
		reports++
		mu.Unlock()
	})

	var handlersWG, settersWG sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		handlersWG.Add(1)
		go func() {
			defer handlersWG.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = h.Handle(context.Background(), slog.NewRecord(time.Now(), slog.LevelInfo, "racing", 0))
				}
			}
		}()
	}
	for range 4 {
		settersWG.Add(1)
		go func() {
			defer settersWG.Done()
			fn := func(*HandlerError) {}
			for range 200 {
				h.setErrorHandler(fn)
			}
		}()
	}
	settersWG.Add(1)
	go func() {
		defer settersWG.Done()
		clone := h.WithAttrs([]slog.Attr{slog.String("k", "v")}).(*safeMulti)
		clone.setErrorHandler(func(*HandlerError) {})
	}()

	settersWG.Wait()
	// With the swap storm settled, reinstall the counting callback: every
	// subsequent Handle panic must reach it (shared-slot visibility is
	// preserved by the atomic pointer).
	h.setErrorHandler(func(*HandlerError) {
		mu.Lock()
		reports++
		mu.Unlock()
	})
	for range 5 {
		_ = h.Handle(context.Background(), slog.NewRecord(time.Now(), slog.LevelInfo, "after settle", 0))
	}
	close(stop)
	handlersWG.Wait()

	mu.Lock()
	defer mu.Unlock()
	require.GreaterOrEqual(t, reports, 5, "post-storm panics must reach the freshly installed handler")
}

// TestMetricsHandler_ClonesShareDropBaseline:丢弃记账必须跨
// WithAttrs/WithGroup 克隆共享。此前每个克隆的 lastDropped 从 0
// 起算,首次 Handle 把内层累计丢弃数整体重报一遍——真实丢 25 条、
// 根 + 2 克隆共报 75(0.1.0-22 修复)。
func TestMetricsHandler_ClonesShareDropBaseline(t *testing.T) {
	m := &recordingMetrics{}
	sink := &jumpDropHandler{}
	h := WithMetrics(sink, m, "test")

	// 根视图先解析 counter 并建立基线(此时 Dropped()=0)。
	_ = h.Handle(context.Background(), slog.NewRecord(time.Now(), slog.LevelInfo, "prime", 0))

	// 内层丢弃 25 条;根 + 2 个克隆各自 Handle。
	sink.dropped.Store(25)
	_ = h.Handle(context.Background(), slog.NewRecord(time.Now(), slog.LevelInfo, "root", 0))
	cloned := slog.New(h).With("k", "v").Handler()
	_ = cloned.Handle(context.Background(), slog.NewRecord(time.Now(), slog.LevelInfo, "clone", 0))
	grouped := slog.New(h).WithGroup("g").Handler()
	_ = grouped.Handle(context.Background(), slog.NewRecord(time.Now(), slog.LevelInfo, "group", 0))

	m.mu.Lock()
	defer m.mu.Unlock()
	require.Equal(t, int64(25), m.dropped,
		"cumulative drops must be reported once across root + clones, got %d", m.dropped)
}
