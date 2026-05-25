// metrics: Prometheus-style metrics collection for log handlers
package main

import (
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/iuboy/mebsuta"
)

type consoleMetrics struct {
	handled atomic.Int64
	errors  atomic.Int64
	dropped atomic.Int64
}

func (m *consoleMetrics) ObserveHandle(d time.Duration) {
	m.handled.Add(1)
	fmt.Printf("handle: %v\n", d)
}

func (m *consoleMetrics) IncError(name string) {
	m.errors.Add(1)
	fmt.Printf("error from %s\n", name)
}

func (m *consoleMetrics) IncDropped(name string) {
	m.dropped.Add(1)
	fmt.Printf("dropped from %s\n", name)
}

func main() {
	m := &consoleMetrics{}
	logger, err := mebsuta.New(
		mebsuta.UseMetrics(m, "myapp"),
	)
	if err != nil {
		panic(err)
	}
	slog.SetDefault(logger)
	defer mebsuta.CloseAll(logger.Handler())

	slog.Info("hello", "msg", "world")
	slog.Warn("warning")
	slog.Error("error")

	fmt.Printf("total handled: %d, errors: %d, dropped: %d\n",
		m.handled.Load(), m.errors.Load(), m.dropped.Load())
}
