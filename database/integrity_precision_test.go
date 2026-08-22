package database

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"
)

// TestCanonicalBytes_NumberPrecision is the regression test for the float64
// collapse: canonicalization previously decoded into any (float64), so
// integers beyond 2^53 that round to the same double produced identical
// canonical bytes — an attacker could rewrite a stored amount/ID and the
// signature still verified.
func TestCanonicalBytes_NumberPrecision(t *testing.T) {
	now := time.Date(2026, 8, 22, 10, 0, 0, 123456000, time.UTC)

	cases := []struct {
		name string
		a, b json.RawMessage
	}{
		{"2^53 boundary", json.RawMessage(`{"amount":9007199254740993}`), json.RawMessage(`{"amount":9007199254740992}`)},
		{"20-digit uid", json.RawMessage(`{"uid":12345678901234567890}`), json.RawMessage(`{"uid":12345678901234567168}`)},
		{"int64 extremes", json.RawMessage(`{"v":9223372036854775807}`), json.RawMessage(`{"v":-9223372036854775808}`)},
		{"distinct decimals", json.RawMessage(`{"v":0.1}`), json.RawMessage(`{"v":0.2}`)},
	}
	for _, c := range cases {
		b1, err := CanonicalBytes(now, "INFO", "m", c.a)
		if err != nil {
			t.Fatalf("%s: CanonicalBytes(a): %v", c.name, err)
		}
		b2, err := CanonicalBytes(now, "INFO", "m", c.b)
		if err != nil {
			t.Fatalf("%s: CanonicalBytes(b): %v", c.name, err)
		}
		if bytes.Equal(b1, b2) {
			t.Errorf("%s: distinct values collapsed to the same canonical bytes: %s", c.name, b1)
		}
	}
}

// TestCanonicalBytes_NumberValuePreserved ensures the canonical form carries
// the exact literal — the signed bytes contain the original number, not a
// float64 re-rendering of it.
func TestCanonicalBytes_NumberValuePreserved(t *testing.T) {
	now := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	got, err := CanonicalBytes(now, "INFO", "m", json.RawMessage(`{"uid":12345678901234567890}`))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte("12345678901234567890")) {
		t.Errorf("canonical form lost the exact number: %s", got)
	}
}

// TestCanonicalBytes_DuplicateKeysRejected: duplicate object keys can only
// come from direct column tampering (the writer marshals a Go map); accepting
// them with last-wins semantics would hide {"k":orig,"k":forged} rewrites.
func TestCanonicalBytes_DuplicateKeysRejected(t *testing.T) {
	if _, err := CanonicalBytes(time.Now(), "INFO", "m", json.RawMessage(`{"a":1,"a":2}`)); err == nil {
		t.Error("expected error for duplicate top-level keys, got nil")
	}
	if _, err := CanonicalBytes(time.Now(), "INFO", "m", json.RawMessage(`{"outer":{"x":1,"x":2}}`)); err == nil {
		t.Error("expected error for duplicate nested keys, got nil")
	}
	if _, err := CanonicalBytes(time.Now(), "INFO", "m", json.RawMessage(`[{"a":1,"a":1}]`)); err == nil {
		t.Error("expected error for duplicate keys inside arrays, got nil")
	}
	// Same key in DIFFERENT objects is legal.
	if _, err := CanonicalBytes(time.Now(), "INFO", "m", json.RawMessage(`{"o1":{"k":1},"o2":{"k":2}}`)); err != nil {
		t.Errorf("same key in sibling objects must be accepted: %v", err)
	}
}

// TestCanonicalBytes_TrailingDataRejected: two JSON documents glued together
// must not verify as one.
func TestCanonicalBytes_TrailingDataRejected(t *testing.T) {
	if _, err := CanonicalBytes(time.Now(), "INFO", "m", json.RawMessage(`{"a":1} {"b":2}`)); err == nil {
		t.Error("expected error for trailing data, got nil")
	}
}

// TestVerifyRecord_AlgoBinding covers the sign_algo column check: a mismatched
// or missing algorithm must fail closed instead of verifying under whatever
// algorithm the caller happened to pass.
func TestVerifyRecord_AlgoBinding(t *testing.T) {
	h := &Handler{cfg: Config{IntegritySigner: mockSigner{}}}
	rec := newSignedRecord(t, h)
	stored := StoredRecord{Time: rec.Time, Level: rec.Level, Message: rec.Message, Fields: rec.Fields, SignAlgo: rec.SignAlgo}

	if err := VerifyRecord(stored, rec.RecordHash, rec.Signature, &mockVerifier{}); err != nil {
		t.Fatalf("matching algo should verify: %v", err)
	}

	flipped := stored
	flipped.SignAlgo = "ECDSA-SHA256"
	if err := VerifyRecord(flipped, rec.RecordHash, rec.Signature, &mockVerifier{}); !errors.Is(err, ErrAlgoMismatch) {
		t.Errorf("tampered sign_algo: got %v, want ErrAlgoMismatch", err)
	}

	cleared := stored
	cleared.SignAlgo = ""
	if err := VerifyRecord(cleared, rec.RecordHash, rec.Signature, &mockVerifier{}); !errors.Is(err, ErrUnsignedRecord) {
		t.Errorf("cleared sign_algo: got %v, want ErrUnsignedRecord", err)
	}
}

// newSignedRecord signs one record through the handler's entry path.
func newSignedRecord(t *testing.T, h *Handler) dbLogEntry {
	t.Helper()
	rec := slog.NewRecord(time.Date(2026, 8, 22, 9, 0, 0, 123000000, time.UTC), slog.LevelInfo, "audit transfer", 0)
	rec.AddAttrs(slog.Int64("amount", 9007199254740993))
	entry := h.recordToDBEntry(rec)
	if entry.RecordHash == "" || entry.Signature == nil || entry.SignAlgo == "" {
		t.Fatalf("record was not signed: %+v", entry)
	}
	return entry
}

// TestVerifyRecord_NumberTamperingDetected is the end-to-end variant of the
// precision regression: verify a stored large-int field, then flip it to its
// float64 twin — verification MUST fail now.
func TestVerifyRecord_NumberTamperingDetected(t *testing.T) {
	h := &Handler{cfg: Config{IntegritySigner: mockSigner{}}}
	entry := newSignedRecord(t, h)

	// Tamper: 2^53+1 → 2^53 (identical under float64 rounding).
	tampered := StoredRecord{
		Time:     entry.Time,
		Level:    entry.Level,
		Message:  entry.Message,
		Fields:   json.RawMessage(`{"amount":9007199254740992}`),
		SignAlgo: entry.SignAlgo,
	}
	if err := VerifyRecord(tampered, entry.RecordHash, entry.Signature, &mockVerifier{}); !errors.Is(err, ErrHashMismatch) {
		t.Errorf("float64-twin tampering not detected: got %v, want ErrHashMismatch", err)
	}
}
