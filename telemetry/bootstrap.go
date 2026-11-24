package telemetry

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/database"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/log"
	lognoop "go.opentelemetry.io/otel/log/noop"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

// Telemetry 持有已启动信号的 OTel SDK provider 及其生命周期。近似零值
// （无 provider）即未配置后端时返回的 no-op 模式；所有方法在其上均安全。
// 并发安全：Shutdown 与 Enabled 可并发调用。
type Telemetry struct {
	shutdownTimeout time.Duration
	// signals 为原子字段：Shutdown 写入 None，而 Enabled 与并发的
	// Shutdown 可能读取它（第五轮审计 P3 发现——普通字段在并发
	// Shutdown 下是数据竞争，-race 当时未检出，因为没有测试覆盖该形态）。
	signals atomic.Uint32
	tp      *sdktrace.TracerProvider
	mp      *sdkmetric.MeterProvider
	lp      *sdklog.LoggerProvider
	// 数据库后端所有权：exporter 通过共享会话写入，sqlDB 在 Shutdown 中、
	// 于各 provider 冲刷完最后一批数据之后才关闭（顺序关键——先关会丢掉
	// 最后一批）。
	spanDB   *database.SpanExporter
	metricDB *database.MetricExporter
	sqlDB    *sql.DB
	// 门面 instrument 缓存(facade.go,0.1.0-29/C1):归实例所有——
	// instrument 与实例 provider 同生命周期,根包全局缓存的教训
	// (0.1.0-22)在实例形态下结构性消失。
	counterCache   sync.Map
	histogramCache sync.Map
	gaugeCache     sync.Map
}

// Start 依据 cfg 引导选定的信号并返回持有它们的 Telemetry。Endpoint 为空时
// 不报错、不触碰 otel 全局状态，直接返回 no-op Telemetry。
//
// 中途失败时（例如 metrics exporter 构建失败），先前创建的 provider 会被
// 关闭，因此 Start 要么返回完全可用的 Telemetry，要么什么都不返回。
func Start(ctx context.Context, cfg Config) (*Telemetry, error) {
	cfg, err := cfg.Validate()
	if err != nil {
		return nil, err
	}
	t := &Telemetry{
		shutdownTimeout: cfg.ShutdownTimeout,
	}
	if t.shutdownTimeout <= 0 {
		t.shutdownTimeout = DefaultShutdownTimeout
	}
	if cfg.Endpoint == "" && cfg.Database == nil {
		// no-op 模式：不触碰全局状态，且 signals 保持 None——Enabled()
		// 的语义是"有信号实际启动"，与配置了哪些信号无关（回归：禁用
		// 后端但显式设置 Signals 的调用方曾误报 Enabled）。
		return t, nil
	}
	t.signals.Store(uint32(cfg.Signals))

	// 数据库后端（模式 B）：打开会话、按需建表，并记住 sql.DB 以便
	// Shutdown 在各 provider 把最后一批数据冲刷进去之后关闭它。
	var dbExporters struct{ span, metric bool }
	if cfg.Database != nil {
		gdb, sqlDB, err := cfg.Database.openDatabase()
		if err != nil {
			return nil, fmt.Errorf("telemetry: database backend: %w", err)
		}
		t.sqlDB = sqlDB
		if cfg.Database.EnsureSchema == nil || *cfg.Database.EnsureSchema {
			if err := ensureSchemaSQLiteAware(gdb, cfg.Database); err != nil {
				t.shutdownStarted(context.Background())
				return nil, fmt.Errorf("telemetry: database backend: %w", err)
			}
		}
		if cfg.Signals&Traces != 0 {
			se, err := database.NewSpanExporter(gdb, cfg.Database.TracesTable)
			if err != nil {
				t.shutdownStarted(context.Background())
				return nil, fmt.Errorf("telemetry: database backend: %w", err)
			}
			t.spanDB = se
			dbExporters.span = true
		}
		if cfg.Signals&Metrics != 0 {
			me, err := database.NewMetricExporter(gdb, cfg.Database.MetricsTable)
			if err != nil {
				t.shutdownStarted(context.Background())
				return nil, fmt.Errorf("telemetry: database backend: %w", err)
			}
			t.metricDB = me
			dbExporters.metric = true
		}
	}

	var host string
	var insecure bool
	var tlsConf *tls.Config
	if cfg.Endpoint != "" {
		var err error
		host, insecure, err = canonicalEndpoint(cfg.Endpoint)
		if err != nil {
			t.shutdownStarted(context.Background())
			return nil, err
		}
		tlsConf, err = cfg.buildTLS()
		if err != nil {
			t.shutdownStarted(context.Background())
			return nil, err
		}
		// TLS 凭据会把裸 host:port 端点（其局域网默认为明文 HTTP）升级为
		// TLS；显式 http:// 端点搭配 TLS 凭据的情况已被 Validate 拒绝。
		if tlsConf != nil && !strings.Contains(cfg.Endpoint, "://") {
			insecure = false
		}
	}
	res := buildResource(cfg)

	if cfg.Signals&Traces != 0 {
		var spanExporters spanFanout
		if host != "" {
			exp, err := otlptracehttp.New(ctx, traceExporterOptions(host, insecure, cfg.Headers, tlsConf)...)
			if err != nil {
				t.shutdownStarted(context.Background())
				return nil, fmt.Errorf("telemetry: traces exporter: %w", err)
			}
			spanExporters = append(spanExporters, exp)
		}
		if dbExporters.span {
			spanExporters = append(spanExporters, t.spanDB)
		}
		t.tp = sdktrace.NewTracerProvider(
			sdktrace.WithSampler(sampler(cfg.SamplingRate)),
			sdktrace.WithBatcher(spanExporters),
			sdktrace.WithResource(res),
		)
	}
	if cfg.Signals&Metrics != 0 {
		var metricExporters metricFanout
		if host != "" {
			exp, err := otlpmetrichttp.New(ctx, metricExporterOptions(host, insecure, cfg.Headers, tlsConf)...)
			if err != nil {
				t.shutdownStarted(context.Background())
				return nil, fmt.Errorf("telemetry: metrics exporter: %w", err)
			}
			metricExporters = append(metricExporters, exp)
		}
		if dbExporters.metric {
			metricExporters = append(metricExporters, t.metricDB)
		}
		readerOpts := []sdkmetric.PeriodicReaderOption{}
		if cfg.MetricExportInterval > 0 {
			readerOpts = append(readerOpts, sdkmetric.WithInterval(cfg.MetricExportInterval))
		}
		if len(metricExporters) == 0 {
			metricExporters = nil // 不可达：至少配置了一个后端
		}
		t.mp = sdkmetric.NewMeterProvider(
			sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExporters, readerOpts...)),
			sdkmetric.WithResource(res),
		)
	}
	if host != "" && cfg.Signals&Logs != 0 {
		exp, err := otlploghttp.New(ctx, logExporterOptions(host, insecure, cfg.Headers, tlsConf)...)
		if err != nil {
			t.shutdownStarted(context.Background())
			return nil, fmt.Errorf("telemetry: logs exporter: %w", err)
		}
		batchOpts := []sdklog.BatchProcessorOption{}
		if cfg.BatchLogQueueSize > 0 {
			batchOpts = append(batchOpts, sdklog.WithMaxQueueSize(cfg.BatchLogQueueSize))
		}
		if cfg.BatchLogInterval > 0 {
			batchOpts = append(batchOpts, sdklog.WithExportInterval(cfg.BatchLogInterval))
		}
		t.lp = sdklog.NewLoggerProvider(
			sdklog.WithResource(res),
			sdklog.WithProcessor(sdklog.NewBatchProcessor(exp, batchOpts...)),
		)
	}

	if cfg.SetGlobal == nil || *cfg.SetGlobal {
		// 把 SDK 内部的导出错误桥接到 mebsuta 错误处理链，而不是走 otel
		// 默认的 stderr（wasat 缺口 ③）。
		fn := cfg.OTelErrorHandler
		if fn == nil {
			fn = mebsuta.DefaultErrorHandler()
		}
		otel.SetErrorHandler(otelHandlerBridge{fn: fn})
		// 覆盖告警（S2）：上一个引导安装的 TracerProvider 尚未被复位时，
		// 本次安装即覆盖全局——最常见成因是忘记 Shutdown 旧引导或二次
		// Start。经错误链上报而非静默替换（单例面地图见 docs/GLOBALS.md）。
		if t.tp != nil {
			if prev := lastInstalledTP.Load(); prev != nil && prev != t.tp {
				fn(&mebsuta.HandlerError{
					Component: "telemetry", Operation: "global-overwrite",
					Err: fmt.Errorf("otel 全局 TracerProvider 被新的引导覆盖（前一个引导未 Shutdown？）；新 endpoint=%q", cfg.Endpoint),
				})
			}
			lastInstalledTP.Store(t.tp)
		}
		if t.tp != nil {
			otel.SetTracerProvider(t.tp)
		}
		if t.mp != nil {
			otel.SetMeterProvider(t.mp)
		}
		if t.lp != nil {
			otel.SetLoggerProvider(t.lp)
		}
		otel.SetTextMapPropagator(propagator())
	}
	return t, nil
}

// 三个 OTLP/HTTP exporter 各自定义了各自的 Option 类型，因此端点+请求头的
// 接线在每个 exporter 里各写一遍。明文与 TLS 之分来自 Endpoint 的 scheme
// （见 canonicalEndpoint）；故意不使用 WithEndpointURL——对不含 path 的 URL，
// 它会把规范默认的 /v1/<signal> 导出路径替换成 "/"，在只服务规范路径的
// 接收端上返回 404。

func traceExporterOptions(host string, insecure bool, headers map[string]string, tlsConf *tls.Config) []otlptracehttp.Option {
	opts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(host)}
	if insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	if tlsConf != nil {
		opts = append(opts, otlptracehttp.WithTLSClientConfig(tlsConf))
	}
	if len(headers) > 0 {
		opts = append(opts, otlptracehttp.WithHeaders(headers))
	}
	return opts
}

func metricExporterOptions(host string, insecure bool, headers map[string]string, tlsConf *tls.Config) []otlpmetrichttp.Option {
	opts := []otlpmetrichttp.Option{otlpmetrichttp.WithEndpoint(host)}
	if insecure {
		opts = append(opts, otlpmetrichttp.WithInsecure())
	}
	if tlsConf != nil {
		opts = append(opts, otlpmetrichttp.WithTLSClientConfig(tlsConf))
	}
	if len(headers) > 0 {
		opts = append(opts, otlpmetrichttp.WithHeaders(headers))
	}
	return opts
}

func logExporterOptions(host string, insecure bool, headers map[string]string, tlsConf *tls.Config) []otlploghttp.Option {
	opts := []otlploghttp.Option{otlploghttp.WithEndpoint(host)}
	if insecure {
		opts = append(opts, otlploghttp.WithInsecure())
	}
	if tlsConf != nil {
		opts = append(opts, otlploghttp.WithTLSClientConfig(tlsConf))
	}
	if len(headers) > 0 {
		opts = append(opts, otlploghttp.WithHeaders(headers))
	}
	return opts
}

// lastInstalledTP 记录本包最近一次经 SetGlobal 安装的 TracerProvider，
// 用于覆盖告警；仅跟踪本包安装（跨库安装不可见——局限记录于
// docs/GLOBALS.md）。
var lastInstalledTP atomic.Pointer[sdktrace.TracerProvider]

// ResetGlobalTracking 复位全局安装跟踪（TEST-ONLY：mebsutatest.
// ResetOTelGlobals 调用；生产代码不得使用）。
func ResetGlobalTracking() { lastInstalledTP.Store(nil) }

// otelHandlerBridge 把 mebsuta.ErrorHandler 适配为 otel 全局
// ErrorHandler 接口。
type otelHandlerBridge struct {
	fn mebsuta.ErrorHandler
}

func (b otelHandlerBridge) Handle(err error) {
	b.fn(&mebsuta.HandlerError{Component: "telemetry", Operation: "otel", Err: err})
}

// sampler 把已校验的采样比例映射为 SDK sampler。比例与 -1 两支外，
// 一律包 ParentBased：入站 traceparent 的采样标志必须被服从——裸
// 采样器无视父 span，跨服务采样率不一致时产生孤儿子 span（父未
// 采样、子记录）或断链（父已采样、子丢弃）。比例 1（填充后的默认
// 值）走 ParentBased(AlwaysSample)，全采样但仍跟随父标志；-1 直通
// 绝对 NeverSample（接入方三态采样器的 never 档，语义是绝不记录，
// 不随父标志放行）；其余走比例采样。
func sampler(rate float64) sdktrace.Sampler {
	switch {
	case rate >= 1:
		return sdktrace.ParentBased(sdktrace.AlwaysSample())
	case rate < 0:
		return sdktrace.NeverSample()
	default:
		return sdktrace.ParentBased(sdktrace.TraceIDRatioBased(rate))
	}
}

// Enabled 报告是否真的启动了任意信号（no-op 模式下为 false）。
func (t *Telemetry) Enabled() bool {
	// #nosec G115 -- 存入的值只可能来自 uint32(Signals)（3 位位掩码），
	// 收窄不会截断。
	return t != nil && Signals(t.signals.Load()) != None
}

// TracerProvider 返回已启动的 trace provider；在 no-op 模式或未选择
// Traces 信号时返回 no-op provider。永不为 nil。
func (t *Telemetry) TracerProvider() trace.TracerProvider {
	if t == nil || t.tp == nil {
		return tracenoop.NewTracerProvider()
	}
	return t.tp
}

// MeterProvider 返回已启动的 meter provider；在 no-op 模式或未选择
// Metrics 信号时返回 no-op provider。永不为 nil。
func (t *Telemetry) MeterProvider() metric.MeterProvider {
	if t == nil || t.mp == nil {
		return metricnoop.NewMeterProvider()
	}
	return t.mp
}

// LoggerProvider 返回已启动的 log provider；在 no-op 模式或未选择
// Logs 信号时返回 no-op provider。永不为 nil。
func (t *Telemetry) LoggerProvider() log.LoggerProvider {
	if t == nil || t.lp == nil {
		return lognoop.NewLoggerProvider()
	}
	return t.lp
}

// Shutdown 在配置的超时内冲刷并释放所有已启动的 provider。对 no-op
// Telemetry 安全，且可重复调用；后续调用返回 nil。
func (t *Telemetry) Shutdown(ctx context.Context) error {
	if t == nil || !t.Enabled() {
		return nil
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.shutdownTimeout)
		defer cancel()
	}
	// 先日志、再指标、最后 trace：相互关联的记录一起冲刷，而 span——
	// 关联的目标——最后落盘。
	var errs []error
	if t.lp != nil {
		if err := t.lp.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("telemetry: logs shutdown: %w", err))
		}
	}
	if t.mp != nil {
		if err := t.mp.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("telemetry: metrics shutdown: %w", err))
		}
	}
	if t.tp != nil {
		if err := t.tp.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("telemetry: traces shutdown: %w", err))
		}
		// 本包安装的 TracerProvider 已随本次关停退出全局：清除覆盖
		// 告警的跟踪基准。"Shutdown 旧引导 → Start 新引导"的正常代次
		// 轮换此前会被误报为覆盖（lastInstalledTP 仍指向已关停的旧
		// provider）。
		lastInstalledTP.CompareAndSwap(t.tp, nil)
	}
	t.signals.Store(uint32(None))
	// 自有的数据库会话最后关闭：上面的 provider 关闭过程已把最后的
	// span/指标行冲刷进其中。
	if t.sqlDB != nil {
		if err := t.sqlDB.Close(); err != nil {
			errs = append(errs, fmt.Errorf("telemetry: database close: %w", err))
		}
	}
	return errors.Join(errs...)
}

// shutdownStarted 回滚 Start 失败前已创建的 provider，使失败的 Start
// 绝不泄漏后台冲刷循环。
func (t *Telemetry) shutdownStarted(ctx context.Context) {
	if t.lp != nil {
		_ = t.lp.Shutdown(ctx)
	}
	if t.mp != nil {
		_ = t.mp.Shutdown(ctx)
	}
	if t.tp != nil {
		_ = t.tp.Shutdown(ctx)
	}
	t.signals.Store(uint32(None))
	// 失败路径同样要关闭数据库池：Start 早期已赋值 t.sqlDB，此前回滚
	// 只关 provider——EnsureTables 等失败时每次失败启动都泄漏一个
	// 连接池（opener goroutine + 连接）。
	if t.sqlDB != nil {
		_ = t.sqlDB.Close()
		t.sqlDB = nil
	}
}
