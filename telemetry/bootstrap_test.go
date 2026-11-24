package telemetry

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/mebsutatest"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

func TestStart_NoOpMode(t *testing.T) {
	tel, err := Start(context.Background(), Config{})
	require.NoError(t, err, "no-op Start 必须永不报错")
	require.False(t, tel.Enabled(), "空 endpoint 必须得到禁用的 Telemetry")
	require.NoError(t, tel.Shutdown(context.Background()), "no-op Shutdown 必须为 nil")
	// 访问器必须是可用（no-op）的实现，绝不为 nil。
	require.NotNil(t, tel.TracerProvider())
	require.NotNil(t, tel.MeterProvider())
	require.NotNil(t, tel.LoggerProvider())
	// Shutdown 两次：第二次调用同样是 no-op。
	require.NoError(t, tel.Shutdown(context.Background()), "第二次 Shutdown 必须为 nil")
}

func TestStart_AllSignals(t *testing.T) {
	r := mebsutatest.NewOTLPReceiver()
	defer r.Close()
	no := false // 保持全局干净；全局行为由专门的测试覆盖
	tel, err := Start(context.Background(), Config{
		ServiceName:    "svc",
		ServiceVersion: "1.2.3",
		Environment:    "test",
		Endpoint:       r.URL(),
		SetGlobal:      &no,
	})
	require.NoError(t, err)
	require.True(t, tel.Enabled(), "配置了 endpoint 时 telemetry 必须处于启用状态")

	ctx := context.Background()

	// 通过已启动的 provider 发一个 span。
	_, span := tel.TracerProvider().Tracer("test.tracer").Start(ctx, "operation")
	span.SetAttributes(attribute.String("op.kind", "unit-test"))
	span.End()

	// 通过已启动的 provider 发一个指标。
	ctr, err := tel.MeterProvider().Meter("test.meter").Int64Counter("test.requests")
	require.NoError(t, err)
	ctr.Add(ctx, 3)

	// 通过已启动的 provider 发一条日志记录。
	var rec log.Record
	rec.SetSeverity(log.SeverityInfo)
	rec.SetSeverityText("INFO")
	rec.SetBody(attribute.StringValue("hello from telemetry test"))
	tel.LoggerProvider().Logger("test.logger").Emit(ctx, rec)

	// Shutdown 冲刷全部三条管线。
	require.NoError(t, tel.Shutdown(context.Background()), "shutdown")

	spans := r.Spans()
	require.Len(t, spans, 1)
	require.Equal(t, "operation", spans[0].Name)

	fams := r.MetricFamilies()
	require.Len(t, fams, 1)
	require.Equal(t, "test.requests", fams[0].Name)

	records := r.LogRecords()
	require.Len(t, records, 1)
	require.Equal(t, "hello from telemetry test", records[0].Body.GetStringValue())

	// 资源标识搭在每个信号上；在 trace 批次上检查它。
	attrs := r.Traces()[0].ResourceSpans[0].Resource.GetAttributes()
	v, ok := mebsutatest.AttrValue(attrs, "service.name")
	require.True(t, ok, "service.name 必须存在")
	require.Equal(t, "svc", v)
	v, ok = mebsutatest.AttrValue(attrs, "service.version")
	require.True(t, ok, "service.version 必须存在")
	require.Equal(t, "1.2.3", v)
	v, ok = mebsutatest.AttrValue(attrs, "deployment.environment.name")
	require.True(t, ok, "deployment.environment.name 必须存在")
	require.Equal(t, "test", v)
}

func TestStart_SignalSubset(t *testing.T) {
	r := mebsutatest.NewOTLPReceiver()
	defer r.Close()
	no := false
	tel, err := Start(context.Background(), Config{
		ServiceName: "svc",
		Endpoint:    r.URL(),
		Signals:     Traces,
		SetGlobal:   &no,
	})
	require.NoError(t, err)
	defer tel.Shutdown(context.Background())

	// 未选择的信号必须暴露 no-op provider：通过未选择的 MeterProvider
	// 发指标不会送达任何内容。
	m := tel.MeterProvider().Meter("x")
	ctr, err := m.Int64Counter("should.not.arrive")
	require.NoError(t, err)
	ctr.Add(context.Background(), 1)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, span := tel.TracerProvider().Tracer("t").Start(ctx, "sub")
	span.End()
	tel.Shutdown(context.Background())

	require.Empty(t, r.MetricFamilies(), "未选择 Metrics 时不得捕获任何指标族")
	require.Len(t, r.Spans(), 1)
}

func TestStart_SetGlobal(t *testing.T) {
	r := mebsutatest.NewOTLPReceiver()
	defer r.Close()
	defer resetGlobals()

	tel, err := Start(context.Background(), Config{
		ServiceName: "global-svc",
		Endpoint:    r.URL(),
		Signals:     Traces,
		// SetGlobal 留 nil → 默认为 true。
	})
	require.NoError(t, err)
	defer tel.Shutdown(context.Background())

	// 全局 tracer（otelgin 式插桩读取的那个）必须接到已启动的
	// provider 上。
	_, span := otel.Tracer("via-global").Start(context.Background(), "global-op")
	span.End()
	tel.Shutdown(context.Background())

	spans := r.Spans()
	require.Len(t, spans, 1)
	require.Equal(t, "global-op", spans[0].Name)
}

// resetGlobals 恢复 otel 内置的 no-op 默认值，使 SetGlobal 测试不会把
// provider 泄漏给本包中的其他测试；同时复位覆盖告警的安装跟踪。
func resetGlobals() {
	mebsutatest.ResetOTelGlobals()
	ResetGlobalTracking()
}

// TestOTelErrorHandlerBridge 覆盖缺口 ③：exporter 失败进入 mebsuta
// 错误处理链，而不是 stderr。
func TestOTelErrorHandlerBridge(t *testing.T) {
	var mu sync.Mutex
	var got []error
	fn := mebsuta.ErrorHandler(func(he *mebsuta.HandlerError) {
		mu.Lock()
		got = append(got, he.Err)
		mu.Unlock()
	})

	// localhost 的 1 号端口：每次导出尝试都是 connection refused。
	tel, err := Start(context.Background(), Config{
		ServiceName:      "err-svc",
		Endpoint:         "https://127.0.0.1:1",
		Signals:          Traces,
		OTelErrorHandler: fn,
	})
	require.NoError(t, err)

	_, span := tel.TracerProvider().Tracer("t").Start(context.Background(), "doomed")
	span.End()
	_ = tel.Shutdown(context.Background())

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(got) > 0
	}, 10*time.Second, 50*time.Millisecond, "export failure must reach the mebsuta error handler")
}

// TestBatchLogInterval 覆盖缺口④：短刷新节流下日志记录不经 Shutdown 即抵达。
func TestBatchLogInterval(t *testing.T) {
	r := mebsutatest.NewOTLPReceiver()
	defer r.Close()
	no := false
	tel, err := Start(context.Background(), Config{
		ServiceName:       "batch-svc",
		Endpoint:          r.URL(),
		Signals:           Logs,
		SetGlobal:         &no,
		BatchLogInterval:  50 * time.Millisecond,
		BatchLogQueueSize: 128,
	})
	require.NoError(t, err)
	defer tel.Shutdown(context.Background())

	var rec log.Record
	rec.SetBody(attribute.StringValue("flushed on cadence"))
	tel.LoggerProvider().Logger("t").Emit(context.Background(), rec)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	require.True(t, r.WaitForLogRecords(ctx, 1), "记录必须按 50ms 节流抵达而无需 Shutdown")

	neg := Config{ServiceName: "s", Endpoint: r.URL(), BatchLogQueueSize: -1}
	_, err = neg.Validate()
	require.ErrorContains(t, err, "BatchLogQueueSize")
}

// TestShutdown_ConcurrentWithEnabled 在多个 goroutine 里高频调用 Enabled，
// 同时运行 Shutdown——普通字段版本的数据竞争是早期套件从未覆盖的。
func TestShutdown_ConcurrentWithEnabled(t *testing.T) {
	r := mebsutatest.NewOTLPReceiver()
	defer r.Close()
	no := false
	tel, err := Start(context.Background(), Config{
		ServiceName: "race",
		Endpoint:    r.URL(),
		SetGlobal:   &no,
	})
	require.NoError(t, err)

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				_ = tel.Enabled()
			}
		}()
	}
	wg.Add(2)
	for range 2 {
		go func() {
			defer wg.Done()
			_ = tel.Shutdown(context.Background())
		}()
	}
	wg.Wait()
	require.False(t, tel.Enabled(), "Shutdown 后 Enabled 必须为 false")
}

// TestStart_GlobalOverwriteWarns（S2）：前一个引导未 Shutdown 时，第二次
// SetGlobal 安装必须经错误链上报覆盖告警。
func TestStart_GlobalOverwriteWarns(t *testing.T) {
	resetGlobals()
	defer resetGlobals()

	var mu sync.Mutex
	var msgs []string
	fn := mebsuta.ErrorHandler(func(he *mebsuta.HandlerError) {
		if he.Operation == "global-overwrite" {
			mu.Lock()
			msgs = append(msgs, he.Err.Error())
			mu.Unlock()
		}
	})

	r1 := mebsutatest.NewOTLPReceiver()
	defer r1.Close()
	tel1, err := Start(context.Background(), Config{
		ServiceName: "first", Endpoint: r1.URL(), Signals: Traces,
		OTelErrorHandler: fn,
	})
	require.NoError(t, err)

	r2 := mebsutatest.NewOTLPReceiver()
	defer r2.Close()
	tel2, err := Start(context.Background(), Config{
		ServiceName: "second", Endpoint: r2.URL(), Signals: Traces,
		OTelErrorHandler: fn,
	})
	require.NoError(t, err)

	require.NotEmpty(t, msgs, "覆盖安装必须产生告警")
	require.Contains(t, msgs[0], "覆盖")

	_ = tel1.Shutdown(context.Background())
	_ = tel2.Shutdown(context.Background())
}

// TestSampler_RespectsParent:比例采样器必须包 ParentBased——入站
// traceparent 的采样标志必须被服从(0.1.0-22 修复:裸采样器无视父
// span,跨服务采样率不一致时产生孤儿子 span 或断链)。never 档
// (rate < 0)保持绝对不采样,不随父标志放行。
func TestSampler_RespectsParent(t *testing.T) {
	tid, err := trace.TraceIDFromHex("0102030405060708090a0b0c0d0e0f10")
	require.NoError(t, err)
	sid, err := trace.SpanIDFromHex("0102030405060708")
	require.NoError(t, err)

	sampledParent := trace.ContextWithSpanContext(context.Background(),
		trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid, SpanID: sid, TraceFlags: trace.FlagsSampled}))
	unsampledParent := trace.ContextWithSpanContext(context.Background(),
		trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid, SpanID: sid}))
	params := func(parent context.Context) sdktrace.SamplingParameters {
		return sdktrace.SamplingParameters{ParentContext: parent, TraceID: tid, Name: "op", Kind: trace.SpanKindServer}
	}

	// 父已采样:rate 0 也必须记录。
	require.Equal(t, sdktrace.RecordAndSample, sampler(0).ShouldSample(params(sampledParent)).Decision,
		"sampled parent must be kept even at rate 0")
	// 父未采样:rate 1 也必须丢弃(跟随父标志)。
	require.Equal(t, sdktrace.Drop, sampler(1).ShouldSample(params(unsampledParent)).Decision,
		"unsampled parent must be dropped even at rate 1")
	// 根 span(无父):按比例与 always 语义。
	require.Equal(t, sdktrace.RecordAndSample, sampler(1).ShouldSample(params(context.Background())).Decision)
	require.Equal(t, sdktrace.Drop, sampler(0).ShouldSample(params(context.Background())).Decision)
	// never 档:绝对不采样。
	require.Equal(t, sdktrace.Drop, sampler(-1).ShouldSample(params(sampledParent)).Decision,
		"never arm must stay absolute regardless of parent")
}
