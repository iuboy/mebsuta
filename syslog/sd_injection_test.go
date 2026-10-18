package syslog

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/iuboy/mebsuta"
)

// TestEscapeSDValue_ControlChars is the regression test for syslog message
// smuggling: a raw LF inside an SD-PARAM value splits the frame on LF-framed
// TCP transports, letting the second "message" be fully attacker-controlled.
// Control characters must be replaced, not passed through.
func TestEscapeSDValue_ControlChars(t *testing.T) {
	cases := map[string]string{
		"a\nb":                   "a b",
		"innocent\r\n<34>1 fake": "innocent  <34>1 fake",
		"tab\there":              "tab here",
		"nul\x00byte":            "nul byte",
		"del\x7fchar":            "del char",
		`quote"`:                 `quote\"`,
		`back\slash`:             `back\\slash`,
		"bracket]":               `bracket\]`,
	}
	for in, want := range cases {
		if got := escapeSDValue(in); got != want {
			t.Errorf("escapeSDValue(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestFormatStructuredMessage_NoFrameSplit verifies the full RFC5424 frame:
// the only newline in the rendered message must be the trailing framing LF.
func TestFormatStructuredMessage_NoFrameSplit(t *testing.T) {
	h := newTestHandler(t)
	h.cfg.RFC5424 = true

	entry := mebsuta.LogEntry{
		Time:    time.Date(2026, 8, 22, 10, 0, 0, 123456789, time.UTC),
		Level:   slog.LevelInfo,
		Message: "user input below",
		Attrs: []slog.Attr{
			slog.String("user_input", "innocent\n<34>1 2026-08-22T10:00:00Z attacker.host su - - - FAKE root session opened"),
		},
	}
	frame := h.formatStructuredMessage(entry, entry.Time.In(time.UTC), 14, "testhost", 1234)

	if n := strings.Count(frame, "\n"); n != 1 || !strings.HasSuffix(frame, "\n") {
		t.Fatalf("frame contains %d newlines, want exactly the trailing one:\n%q", n, frame)
	}
	if strings.Contains(frame, "FAKE root session") && strings.Index(frame, "FAKE root session") < strings.Index(frame, "user_input") {
		t.Fatalf("smuggled content appears before its host PARAM: %q", frame)
	}
	if !strings.Contains(frame, `user_input="innocent`) {
		t.Fatalf("param value mangled beyond control-char replacement: %q", frame)
	}
}

// TestFormatStructuredMessage_TimestampFractionDigits: RFC5424 TIME-SECFRAC
// allows at most 6 digits; RFC3339Nano emitted up to 9 and strict receivers
// reject the frame.
func TestFormatStructuredMessage_TimestampFractionDigits(t *testing.T) {
	h := newTestHandler(t)
	h.cfg.RFC5424 = true

	entry := mebsuta.LogEntry{
		Time:    time.Date(2026, 8, 22, 10, 0, 0, 123456789, time.UTC), // 9-digit nanos
		Level:   slog.LevelInfo,
		Message: "m",
	}
	frame := h.formatStructuredMessage(entry, entry.Time.In(time.UTC), 14, "testhost", 1234)

	// "<PRI>1 <timestamp> ..." — extract the timestamp field.
	fields := strings.SplitN(frame, " ", 3)
	if len(fields) < 3 {
		t.Fatalf("malformed frame: %q", frame)
	}
	ts := fields[1]
	dot := strings.IndexByte(ts, '.')
	if dot < 0 {
		t.Fatalf("timestamp has no fractional seconds: %q", ts)
	}
	frac := ts[dot+1:]
	if len(frac) != 7 { // 6 digits + 'Z'
		t.Errorf("timestamp fraction = %q, want exactly 6 digits: frame %q", frac, frame)
	}
}

// TestFormatStructuredMessage_Limits: SD params are capped in count, name
// length, and value size; excess params are summarized in one marker param.
func TestFormatStructuredMessage_Limits(t *testing.T) {
	h := newTestHandler(t)
	h.cfg.RFC5424 = true

	var attrs []slog.Attr
	for i := 0; i < maxSDParams+20; i++ {
		attrs = append(attrs, slog.String(fmt.Sprintf("k%03d", i), "v"))
	}
	entry := mebsuta.LogEntry{Time: time.Now(), Level: slog.LevelInfo, Message: "m", Attrs: attrs}
	frame := h.formatStructuredMessage(entry, entry.Time.In(time.UTC), 14, "testhost", 1234)

	if got := strings.Count(frame, "k0"); got > maxSDParams {
		t.Errorf("frame contains more than %d params", maxSDParams)
	}
	if !strings.Contains(frame, "params omitted") {
		t.Errorf("no omission marker in frame: %q", frame[:min(len(frame), 300)])
	}

	// Oversized value must be truncated, not shipped whole.
	h2 := newTestHandler(t)
	h2.cfg.RFC5424 = true
	big := strings.Repeat("x", maxSDValueBytes+1000)
	entry2 := mebsuta.LogEntry{
		Time: time.Now(), Level: slog.LevelInfo, Message: "m",
		Attrs: []slog.Attr{slog.String("blob", big)},
	}
	frame2 := h2.formatStructuredMessage(entry2, entry2.Time.In(time.UTC), 14, "testhost", 1234)
	if strings.Contains(frame2, strings.Repeat("x", maxSDValueBytes+10)) {
		t.Errorf("oversized SD value was not truncated (frame len %d)", len(frame2))
	}
}

// TestSanitizeSDName_Limits: names are capped at RFC5424's 32 characters and
// keys with no usable characters yield "" (callers skip the param).
func TestSanitizeSDName_Limits(t *testing.T) {
	long := strings.Repeat("k", 100)
	if got := sanitizeSDName(long); len(got) != maxSDNameLen {
		t.Errorf("sanitizeSDName(long) len = %d, want %d", len(got), maxSDNameLen)
	}
	if got := sanitizeSDName("///"); got != "___" {
		t.Errorf("sanitizeSDName(///) = %q, want ___", got)
	}
	if got := sanitizeSDName(""); got != "" {
		t.Errorf("sanitizeSDName(empty) = %q, want empty", got)
	}
}

// TestWriteWithRetry_StopsAfterContextCancel guards the Close-drain bound:
// once the handler ctx is cancelled, buffered messages must be skipped
// immediately instead of each costing a write timeout.
func TestWriteWithRetry_StopsAfterContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	h := &Handler{cfg: Config{RetryDelay: 50 * time.Millisecond}, ctx: ctx, cancel: cancel}
	// conn is nil: every write returns net.ErrClosed instantly anyway; the
	// point is that the ctx gate returns before any retry/sleep loop.
	cancel()
	start := time.Now()
	h.writeWithRetry([]byte("msg"))
	if elapsed := time.Since(start); elapsed > 20*time.Millisecond {
		t.Errorf("writeWithRetry took %v after ctx cancel, should return immediately", elapsed)
	}
}

// TestFormatStructuredMessage_ParamNameDedup: sanitization can collide keys
// ("a/b" and "a_b" → "a_b"); RFC5424 requires unique PARAM-NAMEs and strict
// receivers reject the whole frame on duplicates.
func TestFormatStructuredMessage_ParamNameDedup(t *testing.T) {
	h := newTestHandler(t)
	h.cfg.RFC5424 = true
	entry := mebsuta.LogEntry{
		Time:    time.Now(),
		Level:   slog.LevelInfo,
		Message: "m",
		Attrs: []slog.Attr{
			slog.String("a/b", "1"),
			slog.String("a_b", "2"),
			slog.String("_truncated", "reserved"),
		},
	}
	frame := h.formatStructuredMessage(entry, entry.Time.In(time.UTC), 14, "testhost", 1234)
	if strings.Count(frame, `a_b=`) != 1 {
		t.Errorf("duplicate PARAM-NAME after sanitization: %q", frame)
	}
	if strings.Count(frame, "_truncated=") != 1 {
		t.Errorf("truncation marker name must stay unique/reserved: %q", frame)
	}
	if !strings.Contains(frame, "params omitted") {
		t.Errorf("deduped/reserved params not accounted in marker: %q", frame)
	}
}
