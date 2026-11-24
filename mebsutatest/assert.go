package mebsutatest

import (
	"io"
	"log/slog"
	"testing"
	"time"
)

// AssertRecordCount 断言 CaptureHandler 恰好捕获了 n 条记录。
func AssertRecordCount(t testing.TB, h *CaptureHandler, n int) {
	t.Helper()
	if got := h.Len(); got != n {
		t.Fatalf("expected %d records, got %d", n, got)
	}
}

// AssertHasAttr 断言 record[index] 带有给定键与值的属性。
// 值比较使用 slog.Value.Equal，适用于所有属性类型
// （string、int64、bool、float64、duration、time 等），不限于字符串。
// 若多个属性同名，检查的是最后一个（与 slog 对重复键的
// "last value wins" 语义一致）。
func AssertHasAttr(t testing.TB, h *CaptureHandler, index int, key string, value any) {
	t.Helper()
	records := h.Records()
	if index < 0 || index >= len(records) {
		t.Fatalf("record index %d out of range (have %d records)", index, len(records))
	}
	// 把期望值转换为 slog.Value，做类型安全的比较。
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
	// 从末尾向前搜索，以匹配 slog 的 "last value wins" 语义。
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

// AssertLevel 断言 record[index] 的级别为给定值。
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

// AssertMessage 断言 record[index] 的消息为给定值。
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

// AssertCloseIdempotent 断言 handler 的 Close 契约(Handler 通用契约
// 第 4 条):第二次 Close 必须返回 nil。首次 Close 的 error 原样透传,
// 是否可接受由调用方裁决(排空超时等场景首关可失败)。
func AssertCloseIdempotent(t testing.TB, h io.Closer) error {
	t.Helper()
	first := h.Close()
	if err := h.Close(); err != nil {
		t.Errorf("second Close = %v, want nil (idempotent)", err)
	}
	return first
}

// AssertDroppedContract 断言丢弃契约(Handler 通用契约第 1 条):
// 触发丢弃后 Dropped() 必须递增。before 由调用方在触发前读取。
func AssertDroppedContract(t testing.TB, before, after int64) {
	t.Helper()
	if after <= before {
		t.Errorf("Dropped() = %d, want > %d (drops must be counted)", after, before)
	}
}
