package mebsutatest

import (
	"log/slog"
	"reflect"
	"testing"
)

// AssertRecordCount asserts that the CaptureHandler captured exactly n records.
func AssertRecordCount(t testing.TB, h *CaptureHandler, n int) {
	t.Helper()
	if got := h.Len(); got != n {
		t.Fatalf("expected %d records, got %d", n, got)
	}
}

// AssertHasAttr asserts that record[index] has an attribute with the given key and value.
//
// value is a string; the captured attribute's value is compared after Resolve()
// against slog.AnyValue(value) so the comparison works across slog.Value kinds
// (string, int, bool, …) instead of only string-valued attrs. The previous
// implementation called a.Value.String() directly, which stringifies every kind
// and silently mismatches non-string attrs (e.g. an Int(42) vs the string "42").
func AssertHasAttr(t testing.TB, h *CaptureHandler, index int, key string, value string) {
	t.Helper()
	records := h.Records()
	if index < 0 || index >= len(records) {
		t.Fatalf("record index %d out of range (have %d records)", index, len(records))
	}
	want := slog.AnyValue(value).Resolve()
	for _, a := range records[index].Attrs {
		if a.Key == key {
			got := a.Value.Resolve()
			if !valueEqual(got, want) {
				t.Fatalf("attr %q: expected value %v (kind=%s), got %v (kind=%s)",
					key, want, want.Kind(), got, got.Kind())
			}
			return
		}
	}
	t.Fatalf("record[%d] has no attr with key %q", index, key)
}

// valueEqual compares two resolved slog.Values by kind and underlying value,
// so a captured string attr matches a string expectation exactly.
func valueEqual(a, b slog.Value) bool {
	if a.Kind() != b.Kind() {
		return false
	}
	switch a.Kind() {
	case slog.KindString:
		return a.String() == b.String()
	case slog.KindInt64:
		return a.Int64() == b.Int64()
	case slog.KindUint64:
		return a.Uint64() == b.Uint64()
	case slog.KindFloat64:
		return a.Float64() == b.Float64()
	case slog.KindBool:
		return a.Bool() == b.Bool()
	case slog.KindDuration:
		return a.Duration() == b.Duration()
	case slog.KindTime:
		return a.Time().Equal(b.Time())
	default:
		// a.Any()/b.Any() may return a non-comparable type (e.g. KindGroup
		// returns []slog.Attr, KindAny may hold a slice/map). Using == on such
		// dynamic values panics at runtime; fall back to reflect.DeepEqual.
		return reflect.DeepEqual(a.Any(), b.Any())
	}
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
