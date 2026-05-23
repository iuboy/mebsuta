package mebsutatest

import (
	"log/slog"
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
func AssertHasAttr(t testing.TB, h *CaptureHandler, index int, key string, value string) {
	t.Helper()
	records := h.Records()
	if index >= len(records) {
		t.Fatalf("record index %d out of range (have %d records)", index, len(records))
	}
	for _, a := range records[index].Attrs {
		if a.Key == key {
			got := a.Value.String()
			if got != value {
				t.Fatalf("attr %q: expected value %q, got %q", key, value, got)
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
	if index >= len(records) {
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
	if index >= len(records) {
		t.Fatalf("record index %d out of range (have %d records)", index, len(records))
	}
	if records[index].Message != msg {
		t.Fatalf("record[%d]: expected message %q, got %q", index, msg, records[index].Message)
	}
}
