// Package mebsutatest 为 mebsuta 日志 handler 提供测试工具。
//
// # 仅限测试
//
// 本包用于测试断言，不用于生产。CaptureHandler 会把收到的每条记录
// 无上限地留在内存——长时间运行的进程经它打日志会持续膨胀，直到内存
// 耗尽。绝不要把它装进生产 handler 链；请使用真正的落盘 handler
// （stdout、文件、syslog、数据库）。
//
// 典型用法：
//
//	h := mebsutatest.NewCaptureHandler()
//	logger := slog.New(h)
//	logger.Info("hello", "key", "value")
//	mebsutatest.AssertRecordCount(t, h, 1)
//	mebsutatest.AssertHasAttr(t, h, 0, "key", "value")
package mebsutatest

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// CapturedRecord 持有一条被捕获的日志记录及其全部属性。
type CapturedRecord struct {
	Time    time.Time
	Level   slog.Level
	Message string
	Attrs   []slog.Attr
}

// CaptureHandler 是把所有记录捕获到内存供测试断言的 slog.Handler。
// 并发安全。
type CaptureHandler struct {
	mu      sync.Mutex
	records []CapturedRecord
	enabled slog.Level
}

// NewCaptureHandler 创建接受所有日志级别的 CaptureHandler。
func NewCaptureHandler() *CaptureHandler {
	return &CaptureHandler{enabled: slog.LevelDebug}
}

// NewCaptureHandlerAt 创建只接受级别 >= min 的 CaptureHandler。
func NewCaptureHandlerAt(min slog.Level) *CaptureHandler {
	return &CaptureHandler{enabled: min}
}

// Enabled 实现 slog.Handler。
func (h *CaptureHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.enabled
}

// Handle 实现 slog.Handler。
func (h *CaptureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	rec := CapturedRecord{
		Time:    r.Time,
		Level:   r.Level,
		Message: r.Message,
	}
	r.Attrs(func(a slog.Attr) bool {
		rec.Attrs = append(rec.Attrs, a)
		return true
	})
	h.records = append(h.records, rec)
	return nil
}

// WithAttrs 实现 slog.Handler。
func (h *CaptureHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &captureAttrsHandler{parent: h, attrs: attrs}
}

// WithGroup 实现 slog.Handler。
func (h *CaptureHandler) WithGroup(name string) slog.Handler {
	return &captureGroupHandler{parent: h, group: name}
}

// Records 返回全部被捕获的记录。返回的切片是副本。
func (h *CaptureHandler) Records() []CapturedRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]CapturedRecord, len(h.records))
	copy(out, h.records)
	return out
}

// Len 返回被捕获记录的数量。
func (h *CaptureHandler) Len() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.records)
}

// Reset 清空全部被捕获的记录。
func (h *CaptureHandler) Reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = nil
}

// Last 返回最近捕获的一条记录；没有记录时返回 false。
func (h *CaptureHandler) Last() (CapturedRecord, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.records) == 0 {
		return CapturedRecord{}, false
	}
	return h.records[len(h.records)-1], true
}

type captureAttrsHandler struct {
	parent *CaptureHandler
	attrs  []slog.Attr
	group  string
}

func (h *captureAttrsHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.parent.Enabled(ctx, level)
}

func (h *captureAttrsHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.group != "" {
		prefixed := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
		r.Attrs(func(a slog.Attr) bool {
			prefixed.AddAttrs(slog.Attr{Key: h.group + "." + a.Key, Value: a.Value})
			return true
		})
		// 对 h.attrs 同样施加 group 前缀，使
		// WithGroup("g").WithAttrs(slog.String("k","v")) 输出 "g.k"="v"。
		for _, a := range h.attrs {
			prefixed.AddAttrs(slog.Attr{Key: h.group + "." + a.Key, Value: a.Value})
		}
		return h.parent.Handle(ctx, prefixed)
	}
	// AddAttrs 前先 Clone（slog 契约）：在 fan-out 场景中原始记录与兄弟
	// handler 共享，直接修改会把捕获的预置属性泄漏进它们的记录。
	newR := r.Clone()
	newR.AddAttrs(h.attrs...)
	r = newR
	return h.parent.Handle(ctx, r)
}

func (h *captureAttrsHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	// 分配全新切片，使共享底层数组不会因后续 append 被污染，
	// 符合 WithAttrs 的不可变契约。
	merged := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	merged = append(merged, h.attrs...)
	merged = append(merged, attrs...)
	return &captureAttrsHandler{parent: h.parent, attrs: merged, group: h.group}
}

func (h *captureAttrsHandler) WithGroup(name string) slog.Handler {
	// 拼接 group，使 WithGroup("g1").WithAttrs(...).WithGroup("g2")
	// 产出 "g1.g2" 而不是丢弃 "g1"。
	joinedGroup := name
	if h.group != "" {
		joinedGroup = h.group + "." + name
	}
	return &captureGroupHandler{parent: h.parent, group: joinedGroup, attrs: h.attrs}
}

type captureGroupHandler struct {
	parent *CaptureHandler
	group  string
	attrs  []slog.Attr
}

func (h *captureGroupHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.parent.Enabled(ctx, level)
}

func (h *captureGroupHandler) Handle(ctx context.Context, r slog.Record) error {
	prefixed := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		prefixed.AddAttrs(slog.Attr{Key: h.group + "." + a.Key, Value: a.Value})
		return true
	})
	// 对 h.attrs 同样施加 group 前缀，使
	// WithGroup("g").WithAttrs(slog.String("k","v")) 输出 "g.k"="v"。
	for _, a := range h.attrs {
		prefixed.AddAttrs(slog.Attr{Key: h.group + "." + a.Key, Value: a.Value})
	}
	return h.parent.Handle(ctx, prefixed)
}

func (h *captureGroupHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	// 保留 group handler 上累积的属性——此前的代码会整体丢弃 h.attrs，
	// 导致 WithGroup("g").WithAttrs([a1]).WithAttrs([a2]) 丢失 a1。
	merged := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	merged = append(merged, h.attrs...)
	merged = append(merged, attrs...)
	return &captureAttrsHandler{parent: h.parent, attrs: merged, group: h.group}
}

func (h *captureGroupHandler) WithGroup(name string) slog.Handler {
	return &captureGroupHandler{parent: h.parent, group: h.group + "." + name, attrs: h.attrs}
}

var (
	_ slog.Handler = (*CaptureHandler)(nil)
	_ slog.Handler = (*captureAttrsHandler)(nil)
	_ slog.Handler = (*captureGroupHandler)(nil)
)
