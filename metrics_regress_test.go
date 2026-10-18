package mebsuta

import (
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
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

func (m *recordingMetrics) IncDropped(string) {
	if m.panicsOn == "dropped" {
		panic("metrics exploded")
	}
	m.mu.Lock()
	m.dropped++
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
	t.Fatal("drops never surfaced to IncDropped")
}

// TestMetricsHandler_MetricsPanicContained: a panicking user metrics
// implementation must not kill the log call.
func TestMetricsHandler_MetricsPanicContained(t *testing.T) {
	var buf mutexBuffer
	m := &recordingMetrics{panicsOn: "observe"}
	h := WithMetrics(newContractJSONHandler(&buf, nil), m, "test")

	logger := slog.New(h)
	logger.Info("must survive")
	if !strings.Contains(buf.String(), "must survive") {
		t.Fatalf("record lost after metrics panic: %q", buf.String())
	}
}
