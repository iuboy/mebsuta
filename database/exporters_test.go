package database

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdkmetricdata "go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// mustSpanContext 用两半十六进制构建合法 span context。
func mustSpanContext(traceHex, spanHex string) trace.SpanContext {
	tid, err := trace.TraceIDFromHex(traceHex)
	if err != nil {
		panic(err)
	}
	sid, err := trace.SpanIDFromHex(spanHex)
	if err != nil {
		panic(err)
	}
	return trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid, SpanID: sid})
}

func newExporterDB(t *testing.T) *gorm.DB {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open(t.TempDir()+"/exporters.db"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, AutoMigrateTables(gdb, "spans", "metrics"))
	return gdb
}

func TestSpanExporter_RoundTrip(t *testing.T) {
	gdb := newExporterDB(t)
	e, err := NewSpanExporter(gdb, "spans")
	require.NoError(t, err)

	res := sdkresource.NewSchemaless(semconv.ServiceName("span-svc"))
	stub := tracetest.SpanStub{
		Name:        "db-op",
		SpanContext: mustSpanContext("0102030405060708090a0b0c0d0e0f10", "0102030405060708"),
		Parent:      mustSpanContext("0102030405060708090a0b0c0d0e0f10", "1111111111111111"),
		SpanKind:    trace.SpanKindServer,
		StartTime:   time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC),
		EndTime:     time.Date(2026, 11, 22, 12, 0, 0, 1500000, time.UTC), // 1.5ms
		Attributes:  []attribute.KeyValue{attribute.String("db.system", "postgresql")},
		Status:      sdktrace.Status{Code: codes.Error, Description: "boom"},
		Events: []sdktrace.Event{{
			Name:       "exception",
			Attributes: []attribute.KeyValue{attribute.String("exception.type", "ErrX")},
		}},
		Resource: res,
	}

	stubs := tracetest.SpanStubs{stub}
	spans := make([]sdktrace.ReadOnlySpan, len(stubs))
	for i := range stubs {
		spans[i] = stubs[i].Snapshot()
	}
	require.NoError(t, e.ExportSpans(context.Background(), spans))
	require.NoError(t, e.Shutdown(context.Background()))
	// Shutdown 幂等，shutdown 之后的导出是 no-op。
	require.NoError(t, e.Shutdown(context.Background()))
	require.NoError(t, e.ExportSpans(context.Background(), spans))

	var rows []SpanRow
	require.NoError(t, gdb.Table("spans").Find(&rows).Error)
	require.Len(t, rows, 1)
	r := rows[0]
	_, err = ulid.Parse(r.ID)
	require.NoError(t, err)
	require.Equal(t, "db-op", r.Name)
	require.Equal(t, "server", r.Kind)
	require.Equal(t, "0102030405060708090a0b0c0d0e0f10", r.TraceID)
	require.Equal(t, "0102030405060708", r.SpanID)
	require.Equal(t, "1111111111111111", r.ParentSpanID)
	require.Equal(t, 1.5, r.DurationMS)
	require.Equal(t, "Error", r.StatusCode)
	require.Equal(t, "boom", r.StatusMsg)
	require.Equal(t, "span-svc", r.ServiceName)

	var attrs map[string]string
	require.NoError(t, json.Unmarshal(r.Attributes, &attrs))
	require.Equal(t, "postgresql", attrs["db.system"])

	var events []struct {
		Name       string            `json:"name"`
		Attributes map[string]string `json:"attributes"`
	}
	require.NoError(t, json.Unmarshal(r.Events, &events))
	require.Len(t, events, 1)
	require.Equal(t, "exception", events[0].Name)
	require.Equal(t, "ErrX", events[0].Attributes["exception.type"])
}

func TestMetricExporter_RoundTrip(t *testing.T) {
	gdb := newExporterDB(t)
	e, err := NewMetricExporter(gdb, "metrics")
	require.NoError(t, err)

	res := sdkresource.NewSchemaless(semconv.ServiceName("metric-svc"))
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	gaugeVal := 7.0
	rm := &sdkmetricdata.ResourceMetrics{
		Resource: res,
		ScopeMetrics: []sdkmetricdata.ScopeMetrics{{
			Metrics: []sdkmetricdata.Metrics{
				{Name: "queue_depth", Data: sdkmetricdata.Gauge[float64]{
					DataPoints: []sdkmetricdata.DataPoint[float64]{{
						Attributes: attribute.NewSet(attribute.String("host", "a")), Value: gaugeVal, Time: now,
					}},
				}},
				{Name: "requests_total", Data: sdkmetricdata.Sum[int64]{
					Temporality: sdkmetricdata.CumulativeTemporality, IsMonotonic: true,
					DataPoints: []sdkmetricdata.DataPoint[int64]{{Value: 42, Time: now}},
				}},
				{Name: "latency_ms", Data: sdkmetricdata.Histogram[float64]{
					Temporality: sdkmetricdata.CumulativeTemporality,
					DataPoints: []sdkmetricdata.HistogramDataPoint[float64]{
						{Count: 3, Sum: 12.5, Time: now},
					},
				}},
			},
		}},
	}

	require.NoError(t, e.Export(context.Background(), rm))
	require.NoError(t, e.Shutdown(context.Background()))

	byKind := map[string][]MetricRow{}
	var rows []MetricRow
	require.NoError(t, gdb.Table("metrics").Find(&rows).Error)
	for _, r := range rows {
		byKind[r.Kind] = append(byKind[r.Kind], r)
		_, err := ulid.Parse(r.ID)
		require.NoError(t, err)
		require.Equal(t, "metric-svc", r.ServiceName)
	}

	require.Len(t, byKind["gauge"], 1)
	require.NotNil(t, byKind["gauge"][0].Value)
	require.Equal(t, 7.0, *byKind["gauge"][0].Value)
	require.Equal(t, "queue_depth", byKind["gauge"][0].Name)

	require.Len(t, byKind["sum"], 1)
	require.True(t, byKind["sum"][0].Monotonic)
	require.Equal(t, 42.0, *byKind["sum"][0].Value)
	require.Equal(t, sdkmetricdata.CumulativeTemporality.String(), byKind["sum"][0].Temporality)

	require.Len(t, byKind["histogram"], 1)
	require.Equal(t, int64(3), *byKind["histogram"][0].Count)
	require.Equal(t, 12.5, *byKind["histogram"][0].Sum)
	require.Nil(t, byKind["histogram"][0].Value)
}
