// Package otlp 通过 OpenTelemetry 日志管线导出 slog 记录。
//
// 该 handler 是纯粹的 API 桥：把 slog 记录转换为 OTel 日志记录，并通过
// log.LoggerProvider 发出——通常是由 mebsuta/telemetry 引导所持有、由其
// 负责 exporter 与关停路径的那个。本包有意不导入任何携带 exporter 或
// gRPC 的模块，从而在编译图中保持 grpc-free；把它与本地输出（stdout、
// 文件、数据库）并列接线，绝不会把 telemetry 栈拖进一个没要它的二进制。
//
// 用法：
//
//	tel, _ := telemetry.Start(ctx, telemetry.Config{
//		ServiceName: "svc",
//		Endpoint:    "http://mebsuta-forwarder:4318",
//	})
//	defer tel.Shutdown(ctx)
//	logger, _ := mebsuta.New(
//		mebsuta.WithHandler(otlp.NewHandler(tel.LoggerProvider(), otlp.Config{})),
//	)
//
// trace 关联是原生的：logs SDK 从发出 slog 调用所传入的 context 填充每条
// 记录的 TraceID/SpanID，因此在 span 内打日志（mebsuta.StartSpan 或任意
// otel tracer）无需任何 extractor 即可关联日志与 trace。
package otlp

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"time"

	"github.com/iuboy/mebsuta"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
	lognoop "go.opentelemetry.io/otel/log/noop"
)

// DefaultLoggerName 是 Config.LoggerName 为空时使用的 instrumentation
// scope。
const DefaultLoggerName = "github.com/iuboy/mebsuta/otlp"

// Config 配置 OTLP 日志 handler。
type Config struct {
	// LoggerName 是发出记录的 instrumentation scope 名称（在 OTLP 导出中
	// 作为 scope 呈现，例如供下游按 logger 过滤）。"" → DefaultLoggerName。
	LoggerName string
	// MinLevel 是经管线发出的最低 slog 级别。0 → slog.LevelInfo，与其他
	// 所有 mebsuta handler 的默认级别过滤一致；设为 slog.LevelDebug 可
	// 全量发出并在上游做选择性丢弃（UseSampling、级别装饰器）。
	MinLevel slog.Level
}

// Handler 是把记录桥接到 OTel 日志管线的 slog.Handler。并发安全。
type Handler struct {
	logger log.Logger
	min    slog.Level
	// OTel log API 没有 logger 侧的 WithAttrs/WithGroup，因此预置属性与
	// group 路径存在这里。预置属性在 WithAttrs 时固化其 group 前缀
	// （按键名预拼接存储）；记录属性在发出时取 handler 当前的 group
	// 前缀——即 slog 语义：WithGroup 只影响之后加入的属性。
	attrs  []slog.Attr
	groups string
}

// NewHandler 把 slog 记录桥接到 lp 之后的管线。lp 为 nil 时得到 no-op
// handler：组合辅助函数可以无条件接线，配错的管线退化为静默而非 panic。
func NewHandler(lp log.LoggerProvider, cfg Config) *Handler {
	if lp == nil {
		lp = lognoop.NewLoggerProvider()
	}
	name := cfg.LoggerName
	if name == "" {
		name = DefaultLoggerName
	}
	return &Handler{
		logger: lp.Logger(name),
		min:    cfg.MinLevel,
	}
}

// Enabled 实现 slog.Handler。
func (h *Handler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.min
}

// Handle 实现 slog.Handler。
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	var rec log.Record
	rec.SetTimestamp(r.Time)
	rec.SetObservedTimestamp(time.Now())
	// SeverityNumber 采用共享的规范映射（频段基数 5/9/13/17，
	// LevelAudit → 21）；SeverityText 保留 slog 的渲染，供下游做
	// 基于文本的过滤。
	rec.SetSeverity(log.Severity(mebsuta.SeverityNumber(r.Level)))
	rec.SetSeverityText(r.Level.String())
	rec.SetBody(attribute.StringValue(r.Message))
	rec.AddAttributes(h.convert(r)...)
	h.logger.Emit(ctx, rec)
	return nil
}

// WithAttrs 实现 slog.Handler。返回的 handler 与 h 不共享任何可变状态
// （写时复制），符合 slog With* 方法的不可变契约。
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	next := *h
	next.attrs = make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	next.attrs = append(next.attrs, h.attrs...)
	for _, a := range attrs {
		// 把当前 group 前缀固化进存储键；convert() 不再给预置属性
		// 追加前缀。
		key := a.Key
		if h.groups != "" {
			key = h.groups + "." + key
		}
		next.attrs = append(next.attrs, slog.Attr{Key: key, Value: a.Value})
	}
	return &next
}

// WithGroup 实现 slog.Handler。
func (h *Handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	next := *h
	if h.groups == "" {
		next.groups = name
	} else {
		next.groups = h.groups + "." + name
	}
	return &next
}

var _ slog.Handler = (*Handler)(nil)

// convert 把 handler 的预置属性加上记录的属性转换为 OTel 属性。预置属性
// 已预拼键名（WithAttrs 固化了其前缀）；记录属性按当前 group 路径作为
// 键。group 递归扁平化为点分键。
func (h *Handler) convert(r slog.Record) []attribute.KeyValue {
	out := make([]attribute.KeyValue, 0, len(h.attrs)+r.NumAttrs())
	for _, a := range h.attrs {
		out = append(out, toOTelAttrs("", a)...)
	}
	r.Attrs(func(a slog.Attr) bool {
		out = append(out, toOTelAttrs(h.groups, a)...)
		return true
	})
	return out
}

// toOTelAttrs 把带 group 前缀的一个 slog 属性转换为零个或多个 OTel
// 属性。KindGroup 值递归扁平化为点分键；空 group 消失——与 slog 的
// JSON handler 行为一致。
func toOTelAttrs(prefix string, a slog.Attr) []attribute.KeyValue {
	if a.Equal(slog.Attr{}) {
		return nil
	}
	key := a.Key
	if prefix != "" {
		key = prefix + "." + key
	}
	if a.Value.Kind() == slog.KindGroup {
		var out []attribute.KeyValue
		for _, m := range a.Value.Group() {
			out = append(out, toOTelAttrs(key, m)...)
		}
		return out
	}
	return []attribute.KeyValue{{
		Key:   attribute.Key(key),
		Value: toOTelValue(a.Value),
	}}
}

// toOTelValue 把 slog 的值种类映射到更窄的 OTel 属性值集合。OTel 没有
// 无符号/时间/时长种类：超过 MaxInt64 的 uint64 与时间戳退化为十进制 /
// RFC3339 字符串形式，而不是静默丢数据；时长转为 int64 纳秒（OTel 对
// 时长的语义约定）。
func toOTelValue(v slog.Value) attribute.Value {
	switch v.Kind() {
	case slog.KindString:
		return attribute.StringValue(v.String())
	case slog.KindInt64:
		return attribute.Int64Value(v.Int64())
	case slog.KindUint64:
		u := v.Uint64()
		if u <= math.MaxInt64 {
			return attribute.Int64Value(int64(u))
		}
		return attribute.StringValue(strconv.FormatUint(u, 10))
	case slog.KindFloat64:
		return attribute.Float64Value(v.Float64())
	case slog.KindBool:
		return attribute.BoolValue(v.Bool())
	case slog.KindTime:
		return attribute.StringValue(v.Time().Format(time.RFC3339Nano))
	case slog.KindDuration:
		return attribute.Int64Value(v.Duration().Nanoseconds())
	default: // KindAny 及其余情况
		return attribute.StringValue(fmt.Sprintf("%v", v.Any()))
	}
}
