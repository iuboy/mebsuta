package mbta

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/iuboy/mebsuta"
)

// TestRecordToSignal_ResolvesLogValuer: slog handlers must resolve
// LogValuer values; leaking them to the encoder serialized internal struct
// representations via fmt.
func TestRecordToSignal_ResolvesLogValuer(t *testing.T) {
	secret := secretValuer{}
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "m", 0)
	r.AddAttrs(slog.Any("cred", secret))

	sig := recordToSignal(r)
	got, ok := sig.Attributes["cred"].(string)
	if !ok {
		t.Fatalf("cred attr = %#v, want resolved string", sig.Attributes["cred"])
	}
	if got != "REDACTED-TOKEN" {
		t.Errorf("cred = %v, want REDACTED-TOKEN (resolved LogValuer)", got)
	}
}

type secretValuer struct{}

func (secretValuer) LogValue() slog.Value {
	return slog.StringValue("REDACTED-TOKEN")
}

// TestRecordToSignal_SeverityNumber: the numeric severity must track the
// level instead of always being 0.
func TestRecordToSignal_SeverityNumber(t *testing.T) {
	cases := map[slog.Level]int{
		slog.LevelDebug:    5,
		slog.LevelInfo:     9,
		slog.LevelWarn:     13,
		slog.LevelError:    17,
		mebsuta.LevelAudit: 21,
	}
	for level, want := range cases {
		r := slog.NewRecord(time.Now(), level, "m", 0)
		if got := recordToSignal(r).SeverityNumber; got != want {
			t.Errorf("SeverityNumber(%v) = %d, want %d", level, got, want)
		}
	}
}

// TestRecordToSignal_AttrBudgets: empty keys are skipped and the attr count
// is capped so one record cannot bloat every batch.
func TestRecordToSignal_AttrBudgets(t *testing.T) {
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "m", 0)
	r.AddAttrs(slog.String("", "empty key"))
	for i := 0; i < maxAttrCount+50; i++ {
		r.AddAttrs(slog.Int("k", i))
	}
	sig := recordToSignal(r)
	if _, ok := sig.Attributes[""]; ok {
		t.Error("empty-key attr was not skipped")
	}
	if len(sig.Attributes) > maxAttrCount {
		t.Errorf("attr count = %d, want <= %d", len(sig.Attributes), maxAttrCount)
	}
}

// TestSanitizeHostname: static and system hostnames are reduced to the
// [a-zA-Z0-9.-] alphabet before entering resource attributes.
func TestSanitizeHostname(t *testing.T) {
	cases := map[string]string{
		"web-01.example.com": "web-01.example.com",
		"bad host\nname":     "bad-host-name",
		"host\x00x":          "host-x",
	}
	for in, want := range cases {
		if got := sanitizeHostname(in); got != want {
			t.Errorf("sanitizeHostname(%q) = %q, want %q", in, got, want)
		}
	}
	if got := sanitizeHostname(""); got == "" || strings.ContainsAny(got, " \n\t") {
		t.Errorf("sanitizeHostname(system) = %q, want non-empty sanitized", got)
	}
}
