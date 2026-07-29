package mebsutatest

import (
	"log/slog"
	"testing"
	"time"
)

// AssertRecordCount asserts that the CaptureHandler captured exactly n records.
func AssertRecordCount(t testing.TB, h *CaptureHandler, n int) {
	t.Helper()
	if got := h.Len(); got != n {
		t.Fatalf("expected %d records, got %d", n, got)
	}
}

// AssertHasAttr asserts that record[index] has an attribute with the given key and value.
// The value comparison uses slog.Value.Equal, which works for all attribute types
// (string, int64, bool, float64, duration, time, etc.), not just strings.
// If multiple attributes share the same key, the LAST one is checked (matching
// slog's "last value wins" semantics for duplicate keys).
func AssertHasAttr(t testing.TB, h *CaptureHandler, index int, key string, value any) {
	t.Helper()
	records := h.Records()
	if index < 0 || index >= len(records) {
		t.Fatalf("record index %d out of range (have %d records)", index, len(records))
	}
	// Convert the expected value to a slog.Value for type-safe comparison.
	var expected slog.Value
	switch v := value.(type) {
	case string:
		expected = slog.StringValue(v)
	case int:
		expected = slog.Int64Value(int64(v))
	case int64:
		expected = slog.Int64Value(v)
	case bool:
		expected = slog.BoolValue(v)
	case float64:
		expected = slog.Float64Value(v)
	case time.Duration:
		expected = slog.DurationValue(v)
	case time.Time:
		expected = slog.TimeValue(v)
	default:
		expected = slog.AnyValue(v)
	}
	// Search from the end to match slog's "last value wins" semantics.
	for i := len(records[index].Attrs) - 1; i >= 0; i-- {
		a := records[index].Attrs[i]
		if a.Key == key {
			if !a.Value.Equal(expected) {
				t.Fatalf("attr %q: expected value %v, got %v", key, value, a.Value)
			}
			return
		}
	}
	t.Fatalf("record[%d] has no attr with key %q", index, key)
}

// AssertLevel asserts that record[index] has the given level.
func AssertLevel(t testing.TB, h *CaptureHandler, index int, level slog.Level) {
	t.Helper()
	records := h.Records()
	if index < 0 || index >= len(records) {
		t.Fatalf("record index %d out of range (have %d records)", index, len(records))
	}
	if records[index].Level != level {
		t.Fatalf("record[%d]: expected level %v, got %v", index, level, records[index].Level)
	}
}

// AssertMessage asserts that record[index] has the given message.
func AssertMessage(t testing.TB, h *CaptureHandler, index int, msg string) {
	t.Helper()
	records := h.Records()
	if index < 0 || index >= len(records) {
		t.Fatalf("record index %d out of range (have %d records)", index, len(records))
	}
	if records[index].Message != msg {
		t.Fatalf("record[%d]: expected message %q, got %q", index, msg, records[index].Message)
	}
}
