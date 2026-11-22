// slogtest 一致性认证:用标准库 testing/slogtest 的全部用例,验证各
// 装饰器(SamplingHandler、MetricsHandler、contextExtractorHandler、
// safeMulti)忠实转发 slog 语义——不改调用方的 Record、不丢属性、
// 正确传递 WithAttrs/WithGroup、Enabled 委托一致。
//
// 方法:被测装饰器包裹一个"契约完美 Sink"(slog.NewJSONHandler)。
// Sink 收到什么就如实序列化什么;装饰器若破坏语义(原地改记录、
// 吞属性、group 处理错),Sink 的输出就会偏离 slogtest 的期望。
//
// 有意不纳入的对象(设计性偏离,非缺陷):
//   - contractJSONHandler/StdoutHandler:输出契约使用 "message" 键与
//     扁平化 attributes,与 slog 默认 schema("msg"、嵌套 group)不同,
//     无法通过默认解析;其行为由 handler_json_test 与 docs/SPEC.md 覆盖。
//   - AttrsSub/GroupSub:group 语义是键前缀扁平化而非嵌套,服务于
//     database/syslog/mbta 的扁平输出形态,同样与 slog 嵌套语义不同。
//   - AsyncHandler:后台 goroutine 写出,slogtest 要求同步可见性。
package mebsuta

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"
	"testing/slogtest"
	"time"
)

// conformanceSink 返回写入 buf 的标准库 JSON handler,作为契约完美 Sink。
func conformanceSink(buf *bytes.Buffer) slog.Handler {
	return slog.NewJSONHandler(buf, nil)
}

// parseLastSinkLine 解析 sink 缓冲的最后一行(record-per-line)。
// 每个用例使用独立的新 handler 与缓冲,缓冲内即该用例的全部输出。
func parseLastSinkLine(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var line []byte
	for {
		l, err := buf.ReadBytes('\n')
		if err != nil {
			break
		}
		line = l
	}
	var m map[string]any
	if err := json.Unmarshal(line, &m); err != nil {
		t.Fatalf("slogtest: 解析 sink 输出 %q 失败: %v", line, err)
	}
	return m
}

// TestSlogTestConformance_SamplingHandler 以 slogtest 全量用例认证采样
// 装饰器。Initial 预算调大,使单用例内的少量记录全部放行——用例验证
// 的是转发保真,采样丢弃行为由 handler_sampling_test 覆盖。
func TestSlogTestConformance_SamplingHandler(t *testing.T) {
	var buf *bytes.Buffer
	slogtest.Run(t,
		func(*testing.T) slog.Handler {
			buf = new(bytes.Buffer)
			return WithSampling(conformanceSink(buf), SamplingConfig{
				Enabled: true, Initial: 1000, Thereafter: 1000, Window: time.Hour,
			})
		},
		func(t *testing.T) map[string]any { return parseLastSinkLine(t, buf) },
	)
}

// noopMetrics 是 slogtest 认证用的 HandlerMetrics 空实现。
type noopMetrics struct{}

func (noopMetrics) ObserveHandle(time.Duration) {}
func (noopMetrics) IncError(string)             {}
func (noopMetrics) IncDroppedN(string, int64)   {}

// TestSlogTestConformance_MetricsHandler 认证指标装饰器的转发路径。
func TestSlogTestConformance_MetricsHandler(t *testing.T) {
	var buf *bytes.Buffer
	slogtest.Run(t,
		func(*testing.T) slog.Handler {
			buf = new(bytes.Buffer)
			return WithMetrics(conformanceSink(buf), noopMetrics{}, "conformance")
		},
		func(t *testing.T) map[string]any { return parseLastSinkLine(t, buf) },
	)
}

// TestSlogTestConformance_ContextExtractor 认证 context 提取装饰器。
// 提取器返回 nil(不注入),专注验证克隆与转发契约;注入路径由
// handler_context_test 覆盖。
func TestSlogTestConformance_ContextExtractor(t *testing.T) {
	var buf *bytes.Buffer
	extract := func(context.Context) []slog.Attr { return nil }
	slogtest.Run(t,
		func(*testing.T) slog.Handler {
			buf = new(bytes.Buffer)
			return WithContextExtractor(conformanceSink(buf), extract)
		},
		func(t *testing.T) map[string]any { return parseLastSinkLine(t, buf) },
	)
}

// TestSlogTestConformance_MultiHandler 认证 safeMulti fanout:两个子
// handler(真实 Sink + 丢弃 Sink),验证逐 handler 克隆与转发。
func TestSlogTestConformance_MultiHandler(t *testing.T) {
	var buf *bytes.Buffer
	slogtest.Run(t,
		func(t *testing.T) slog.Handler {
			buf = new(bytes.Buffer)
			l, err := New(
				WithHandler(conformanceSink(buf)),
				WithHandler(slog.NewJSONHandler(io.Discard, nil)),
			)
			if err != nil {
				t.Fatal(err)
			}
			return l.Handler()
		},
		func(t *testing.T) map[string]any { return parseLastSinkLine(t, buf) },
	)
}
