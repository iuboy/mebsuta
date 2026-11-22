package mebsutatest

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	logspb "go.opentelemetry.io/proto/slim/otlp/collector/logs/v1"
	metricspb "go.opentelemetry.io/proto/slim/otlp/collector/metrics/v1"
	tracepb "go.opentelemetry.io/proto/slim/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/slim/otlp/common/v1"
	logsv1 "go.opentelemetry.io/proto/slim/otlp/logs/v1"
	metricsv1 "go.opentelemetry.io/proto/slim/otlp/metrics/v1"
	tracev1 "go.opentelemetry.io/proto/slim/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

// OTLPReceiver 是仅限测试的 OTLP/HTTP 接收端：一个绑定规范默认
// /v1/{traces,metrics,logs} 路径的 httptest 服务器，解码并保留每个
// protobuf 请求供断言。解码走 slim proto 模块（仅消息类型，线格式
// 相同），使本包保持 grpc-free——完整的 go.opentelemetry.io/proto/otlp
// collector 包内嵌生成的 gRPC 服务桩，会把 google.golang.org/grpc 拖进
// 每个导入 mebsutatest 的测试二进制。
//
// # 仅限测试
//
// 与 CaptureHandler 一样，它把所有内容无上限地留在内存，并对每个请求
// 都应答成功——绝不要在生产中部署任何类似的东西。用它把
// telemetry.Config.Endpoint 指向 r.URL()，并对真正上线传输的内容做断言。
//
// 典型用法：
//
//	r := mebsutatest.NewOTLPReceiver()
//	defer r.Close()
//	tel, _ := telemetry.Start(ctx, telemetry.Config{
//	    ServiceName: "test", Endpoint: r.URL(),
//	})
//	defer tel.Shutdown(context.Background())
//	// … 发一个 span …
//	if !r.WaitForSpans(ctx, 1) { t.Fatal("span never arrived") }
type OTLPReceiver struct {
	server *httptest.Server
	mux    *http.ServeMux

	mu         sync.Mutex
	traceReqs  []*tracepb.ExportTraceServiceRequest
	metricReqs []*metricspb.ExportMetricsServiceRequest
	logReqs    []*logspb.ExportLogsServiceRequest
	requests   []OTLPRequest
}

// OTLPRequest 记录一个已接收导出请求的传输层形态，
// 与其解码后的载荷无关。
type OTLPRequest struct {
	Path            string
	ContentType     string
	ContentEncoding string
	BodyBytes       int
}

// NewOTLPReceiver 在一个临时的环回监听器上启动接收端。
// 务必与 Close 配对使用。
func NewOTLPReceiver() *OTLPReceiver {
	r := &OTLPReceiver{mux: http.NewServeMux()}
	mux := r.mux
	mux.HandleFunc("/v1/traces", r.serveTrace)
	mux.HandleFunc("/v1/metrics", r.serveMetric)
	mux.HandleFunc("/v1/logs", r.serveLog)
	r.server = httptest.NewServer(mux)
	return r
}

// Handler 返回接收端的 HTTP handler，让测试可以把捕获端点挂到自己的
// 服务器上（例如用于 mTLS 校验的 httptest TLS 服务器）。
func (r *OTLPReceiver) Handler() http.Handler { return r.mux }

// Close 关闭接收端服务器。
func (r *OTLPReceiver) Close() { r.server.Close() }

// URL 返回接收端的基础 URL（"http://127.0.0.1:port"），
// 可直接用作 telemetry.Config.Endpoint。
func (r *OTLPReceiver) URL() string { return r.server.URL }

// Traces 返回每个已解码的 trace 导出请求，按到达顺序。
func (r *OTLPReceiver) Traces() []*tracepb.ExportTraceServiceRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*tracepb.ExportTraceServiceRequest, len(r.traceReqs))
	copy(out, r.traceReqs)
	return out
}

// Metrics 返回每个已解码的 metric 导出请求，按到达顺序。
func (r *OTLPReceiver) Metrics() []*metricspb.ExportMetricsServiceRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*metricspb.ExportMetricsServiceRequest, len(r.metricReqs))
	copy(out, r.metricReqs)
	return out
}

// Logs 返回每个已解码的 log 导出请求，按到达顺序。
func (r *OTLPReceiver) Logs() []*logspb.ExportLogsServiceRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*logspb.ExportLogsServiceRequest, len(r.logReqs))
	copy(out, r.logReqs)
	return out
}

// Spans 把所有已接收的请求扁平化为单个 span。
func (r *OTLPReceiver) Spans() []*tracev1.Span {
	var spans []*tracev1.Span
	for _, req := range r.Traces() {
		for _, rs := range req.ResourceSpans {
			for _, ss := range rs.ScopeSpans {
				spans = append(spans, ss.Spans...)
			}
		}
	}
	return spans
}

// MetricFamilies 把所有已接收的请求扁平化为单个指标。
func (r *OTLPReceiver) MetricFamilies() []*metricsv1.Metric {
	var ms []*metricsv1.Metric
	for _, req := range r.Metrics() {
		for _, rm := range req.ResourceMetrics {
			for _, sm := range rm.ScopeMetrics {
				ms = append(ms, sm.Metrics...)
			}
		}
	}
	return ms
}

// LogRecords 把所有已接收的请求扁平化为单个日志记录。
func (r *OTLPReceiver) LogRecords() []*logsv1.LogRecord {
	var rs []*logsv1.LogRecord
	for _, req := range r.Logs() {
		for _, rl := range req.ResourceLogs {
			for _, sl := range rl.ScopeLogs {
				rs = append(rs, sl.LogRecords...)
			}
		}
	}
	return rs
}

// Requests 返回所有已接收请求的传输层记录。
func (r *OTLPReceiver) Requests() []OTLPRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]OTLPRequest, len(r.requests))
	copy(out, r.requests)
	return out
}

// Reset 丢弃目前捕获的所有内容。服务器继续监听。
func (r *OTLPReceiver) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.traceReqs = nil
	r.metricReqs = nil
	r.logReqs = nil
	r.requests = nil
}

// WaitForSpans 轮询直到捕获了 n 个 span 或 ctx 结束。返回是否达到数量，
// 缺口由调用方自行报告。
func (r *OTLPReceiver) WaitForSpans(ctx context.Context, n int) bool {
	return r.waitFor(ctx, func() bool { return len(r.Spans()) >= n })
}

// WaitForMetrics 轮询直到捕获了 n 个指标族或 ctx 结束。
func (r *OTLPReceiver) WaitForMetrics(ctx context.Context, n int) bool {
	return r.waitFor(ctx, func() bool { return len(r.MetricFamilies()) >= n })
}

// WaitForLogRecords 轮询直到捕获了 n 条日志记录或 ctx 结束。
func (r *OTLPReceiver) WaitForLogRecords(ctx context.Context, n int) bool {
	return r.waitFor(ctx, func() bool { return len(r.LogRecords()) >= n })
}

func (r *OTLPReceiver) waitFor(ctx context.Context, ok func() bool) bool {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ok() {
			return true
		}
		select {
		case <-ctx.Done():
			return ok()
		case <-ticker.C:
		}
	}
}

func (r *OTLPReceiver) serveTrace(w http.ResponseWriter, req *http.Request) {
	body := r.read(w, req)
	if body == nil {
		return
	}
	pb := &tracepb.ExportTraceServiceRequest{}
	if err := proto.Unmarshal(body, pb); err != nil {
		http.Error(w, "bad protobuf: "+err.Error(), http.StatusBadRequest)
		return
	}
	r.mu.Lock()
	r.traceReqs = append(r.traceReqs, pb)
	r.mu.Unlock()
	writeProto(w, &tracepb.ExportTraceServiceResponse{})
}

func (r *OTLPReceiver) serveMetric(w http.ResponseWriter, req *http.Request) {
	body := r.read(w, req)
	if body == nil {
		return
	}
	pb := &metricspb.ExportMetricsServiceRequest{}
	if err := proto.Unmarshal(body, pb); err != nil {
		http.Error(w, "bad protobuf: "+err.Error(), http.StatusBadRequest)
		return
	}
	r.mu.Lock()
	r.metricReqs = append(r.metricReqs, pb)
	r.mu.Unlock()
	writeProto(w, &metricspb.ExportMetricsServiceResponse{})
}

func (r *OTLPReceiver) serveLog(w http.ResponseWriter, req *http.Request) {
	body := r.read(w, req)
	if body == nil {
		return
	}
	pb := &logspb.ExportLogsServiceRequest{}
	if err := proto.Unmarshal(body, pb); err != nil {
		http.Error(w, "bad protobuf: "+err.Error(), http.StatusBadRequest)
		return
	}
	r.mu.Lock()
	r.logReqs = append(r.logReqs, pb)
	r.mu.Unlock()
	writeProto(w, &logspb.ExportLogsServiceResponse{})
}

// maxBodyBytes 限制原始与解压后的 body 读取量：这是环回上的测试设施，
// 但喂给它一个 gzip 炸弹不应能 OOM 测试二进制（第五轮审计 P4 加固）。
const maxBodyBytes = 64 << 20

// read 消费请求 body（在客户端协商 gzip 时透明解压，受大小上限约束），
// 记录传输层请求，并返回原始 protobuf 字节。返回 nil 表示该请求已用
// 错误状态应答。
func (r *OTLPReceiver) read(w http.ResponseWriter, req *http.Request) []byte {
	body, err := io.ReadAll(io.LimitReader(req.Body, maxBodyBytes+1))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return nil
	}
	if len(body) > maxBodyBytes {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return nil
	}
	encoding := req.Header.Get("Content-Encoding")
	if encoding == "gzip" {
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			http.Error(w, "bad gzip: "+err.Error(), http.StatusBadRequest)
			return nil
		}
		body, err = io.ReadAll(io.LimitReader(zr, maxBodyBytes+1))
		if err != nil {
			http.Error(w, "read gzip: "+err.Error(), http.StatusBadRequest)
			return nil
		}
		if len(body) > maxBodyBytes {
			http.Error(w, "decompressed body too large", http.StatusRequestEntityTooLarge)
			return nil
		}
	}
	r.mu.Lock()
	r.requests = append(r.requests, OTLPRequest{
		Path:            req.URL.Path,
		ContentType:     req.Header.Get("Content-Type"),
		ContentEncoding: encoding,
		BodyBytes:       len(body),
	})
	r.mu.Unlock()
	return body
}

func writeProto(w http.ResponseWriter, msg proto.Message) {
	body, err := proto.Marshal(msg)
	if err != nil {
		http.Error(w, "marshal response: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// AttrValue 返回 key 在 OTLP 属性列表中的字符串值，用于对资源属性与
// 记录属性做断言，免得手写扫描。只呈现字符串值；非字符串属性返回
// false。
func AttrValue(attrs []*commonpb.KeyValue, key string) (string, bool) {
	for _, kv := range attrs {
		if kv.GetKey() == key && kv.Value != nil && kv.Value.GetStringValue() != "" {
			return kv.Value.GetStringValue(), true
		}
	}
	return "", false
}
