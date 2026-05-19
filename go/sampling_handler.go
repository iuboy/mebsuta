package mebsuta

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iuboy/mebsuta/go/config"
)

// SamplingHandler 是 slog.Handler 装饰器，按时间窗口对日志进行采样。
// Error 及以上级别始终记录。每个窗口前 Initial 条全部记录，之后每 Thereafter 条记录 1 条。
type SamplingHandler struct {
	inner   slog.Handler
	cfg     config.SamplingConfig
	count   *atomic.Int64 // 指针，跨 WithAttrs/WithGroup 共享
	ticker  *time.Ticker
	stopCh  chan struct{}
	wg      *sync.WaitGroup // 指针，跨 WithAttrs/WithGroup 共享
	stopped *atomic.Bool    // 指针，跨 WithAttrs/WithGroup 共享
}

func WithSampling(inner slog.Handler, cfg config.SamplingConfig) slog.Handler {
	if !cfg.Enabled || inner == nil {
		return inner
	}
	if cfg.Window <= 0 {
		cfg.Window = time.Second
	}
	if cfg.Initial <= 0 {
		cfg.Initial = 100
	}
	if cfg.Thereafter <= 0 {
		cfg.Thereafter = 10
	}

	h := &SamplingHandler{
		inner:   inner,
		cfg:     cfg,
		count:   &atomic.Int64{},
		ticker:  time.NewTicker(cfg.Window),
		stopCh:  make(chan struct{}),
		wg:      &sync.WaitGroup{},
		stopped: &atomic.Bool{},
	}
	h.wg.Add(1)
	go h.resetLoop()
	return h
}

func (h *SamplingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	if level >= slog.LevelError {
		return true
	}
	return h.inner.Enabled(ctx, level)
}

func (h *SamplingHandler) Handle(ctx context.Context, r slog.Record) error {
	// Error 及以上始终记录
	if r.Level >= slog.LevelError {
		return h.inner.Handle(ctx, r)
	}

	count := h.count.Add(1)

	cfg := h.cfg
	if count <= int64(cfg.Initial) {
		return h.inner.Handle(ctx, r)
	}
	if (count-int64(cfg.Initial))%int64(cfg.Thereafter) == 0 {
		return h.inner.Handle(ctx, r)
	}

	// 被采样跳过
	return nil
}

func (h *SamplingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &SamplingHandler{
		inner:   h.inner.WithAttrs(attrs),
		cfg:     h.cfg,
		count:   h.count, // 共享计数器（atomic，无需额外同步）
		ticker:  h.ticker,
		stopCh:  h.stopCh,
		wg:      h.wg, // 共享 WaitGroup（Close 需等待 goroutine 退出）
		stopped: h.stopped,
	}
}

func (h *SamplingHandler) WithGroup(name string) slog.Handler {
	return &SamplingHandler{
		inner:   h.inner.WithGroup(name),
		cfg:     h.cfg,
		count:   h.count,
		ticker:  h.ticker,
		stopCh:  h.stopCh,
		wg:      h.wg,
		stopped: h.stopped,
	}
}

func (h *SamplingHandler) Close() error {
	if !h.stopped.CompareAndSwap(false, true) {
		return nil
	}
	h.ticker.Stop()
	close(h.stopCh)
	h.wg.Wait()
	return nil
}

func (h *SamplingHandler) unwrapHandler() slog.Handler {
	return h.inner
}

func (h *SamplingHandler) resetLoop() {
	defer h.wg.Done()
	for {
		select {
		case <-h.ticker.C:
			h.count.Store(0)
		case <-h.stopCh:
			return
		}
	}
}

var (
	_ slog.Handler = (*SamplingHandler)(nil)
	_ io.Closer    = (*SamplingHandler)(nil)
)
