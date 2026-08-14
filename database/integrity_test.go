package database

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// mockHash and the mock signer/verifier below implement the integrity
// interfaces with a trivial XOR scheme, so tests can sign and verify without
// depending on any real cryptographic library.
func mockHash(data []byte) ([]byte, error) {
	h := make([]byte, len(data))
	for i, b := range data {
		h[i] = b ^ 0x5A
	}
	return h, nil
}

func mockSignature(recordHash []byte) []byte {
	return append([]byte("sig:"), recordHash...)
}

type mockSigner struct{}

func (mockSigner) Algorithm() string { return "MOCK" }

func (mockSigner) Sign(data []byte) (recordHash, signature []byte, err error) {
	recordHash, err = mockHash(data)
	if err != nil {
		return nil, nil, err
	}
	return recordHash, mockSignature(recordHash), nil
}

type mockVerifier struct{}

func (*mockVerifier) Algorithm() string { return "MOCK" }

func (*mockVerifier) Hash(data []byte) ([]byte, error) { return mockHash(data) }

func (*mockVerifier) Verify(recordHash, signature []byte) error {
	if !bytes.Equal(signature, mockSignature(recordHash)) {
		return errors.New("mock: bad signature")
	}
	return nil
}

func TestIntegritySigner_Interface(t *testing.T) {
	var _ IntegritySigner = mockSigner{}
	var _ IntegrityVerifier = &mockVerifier{}
}

func TestCanonicalBytes_Deterministic(t *testing.T) {
	base := time.Date(2026, 8, 3, 10, 42, 23, 123456789, time.UTC)

	cases := []struct {
		name   string
		t1, t2 time.Time
		f1, f2 json.RawMessage
	}{
		{
			name: "sub-microsecond digits ignored",
			t1:   base,
			t2:   time.Date(2026, 8, 3, 10, 42, 23, 123456000, time.UTC),
		},
		{
			name: "timezone independent (same instant)",
			t1:   base,
			t2:   base.In(time.FixedZone("+08", 8*3600)),
		},
		{
			name: "fields key order and whitespace irrelevant",
			t1:   base, f1: json.RawMessage(`{"a": 1, "b": {"y": true, "x": null}}`),
			t2: base, f2: json.RawMessage(`{ "b" : { "x" : null , "y" : true } , "a" : 1 }`),
		},
		{
			name: "empty fields equals JSON null",
			t1:   base, f1: nil,
			t2: base, f2: json.RawMessage(`null`),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c1, err := CanonicalBytes(tc.t1, "INFO", "msg", tc.f1)
			if err != nil {
				t.Fatalf("CanonicalBytes #1: %v", err)
			}
			c2, err := CanonicalBytes(tc.t2, "INFO", "msg", tc.f2)
			if err != nil {
				t.Fatalf("CanonicalBytes #2: %v", err)
			}
			if !bytes.Equal(c1, c2) {
				t.Errorf("canonical forms differ:\n%q\n%q", c1, c2)
			}
			if !json.Valid(c1) {
				t.Errorf("canonical form is not valid JSON: %q", c1)
			}
		})
	}
}

func TestCanonicalBytes_DistinguishesContent(t *testing.T) {
	now := time.Date(2026, 8, 3, 10, 42, 23, 123000000, time.UTC)
	base, err := CanonicalBytes(now, "INFO", "transfer ok", json.RawMessage(`{"a":1}`))
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	// Every content change must change the canonical bytes — including the
	// delimiter-tricky message containing the old "|" separator and quotes.
	variants := []struct {
		level, msg string
		fields     json.RawMessage
	}{
		{"WARN", "transfer ok", json.RawMessage(`{"a":1}`)},
		{"INFO", "transfer ok?", json.RawMessage(`{"a":1}`)},
		{"INFO", "transfer ok", json.RawMessage(`{"a":2}`)},
		{"INFO", "msg|with|pipes and \"quotes\"", nil},
	}
	for i, v := range variants {
		got, err := CanonicalBytes(now, v.level, v.msg, v.fields)
		if err != nil {
			t.Fatalf("variant %d: %v", i, err)
		}
		if bytes.Equal(got, base) && i != 3 {
			t.Errorf("variant %d collapsed to the same canonical bytes as base", i)
		}
		if !json.Valid(got) {
			t.Errorf("variant %d produced invalid JSON: %q", i, got)
		}
	}
}

func TestCanonicalBytes_InvalidJSON(t *testing.T) {
	if _, err := CanonicalBytes(time.Now(), "INFO", "msg", json.RawMessage(`{"a":`)); err == nil {
		t.Error("expected error for invalid fields JSON, got nil")
	}
}

func TestRecordToDBEntry_SignsCanonicalForm(t *testing.T) {
	h := &Handler{cfg: Config{IntegritySigner: mockSigner{}}}
	now := time.Date(2026, 8, 3, 10, 42, 23, 123456789, time.FixedZone("+08", 8*3600))

	rec := slog.NewRecord(now, slog.LevelWarn, `msg with | pipe and "quote"`, 0)
	rec.AddAttrs(slog.String("b", "2"), slog.String("a", "1"))
	entry := h.recordToDBEntry(rec)

	if got := entry.Time.Nanosecond() % int(time.Microsecond); got != 0 {
		t.Errorf("entry.Time not truncated to canonical precision: nanosecond remainder %d", got)
	}

	canonical, err := CanonicalBytes(entry.Time, entry.Level, entry.Message, entry.Fields)
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	wantHash, err := mockHash(canonical)
	if err != nil {
		t.Fatalf("mockHash: %v", err)
	}
	if entry.RecordHash != hex.EncodeToString(wantHash) {
		t.Errorf("RecordHash = %q, want %q", entry.RecordHash, hex.EncodeToString(wantHash))
	}
	if !bytes.Equal(entry.Signature, mockSignature(wantHash)) {
		t.Errorf("Signature = %q, want %q", entry.Signature, mockSignature(wantHash))
	}
	if entry.SignAlgo != "MOCK" {
		t.Errorf("SignAlgo = %q, want MOCK", entry.SignAlgo)
	}
}

func TestRecordToDBEntry_NilSignerLeavesUnsigned(t *testing.T) {
	h := &Handler{cfg: Config{}}
	rec := slog.NewRecord(time.Now(), slog.LevelInfo, "hello", 0)
	entry := h.recordToDBEntry(rec)
	if entry.RecordHash != "" || entry.Signature != nil || entry.SignAlgo != "" {
		t.Errorf("expected unsigned entry, got hash=%q sig=%v algo=%q", entry.RecordHash, entry.Signature, entry.SignAlgo)
	}
}

func TestVerifyRecord_RoundTrip(t *testing.T) {
	h := &Handler{cfg: Config{IntegritySigner: mockSigner{}}}
	now := time.Date(2026, 8, 3, 10, 42, 23, 123456789, time.FixedZone("+08", 8*3600))
	rec := slog.NewRecord(now, slog.LevelError, "db write failed", 0)
	rec.AddAttrs(slog.String("table", "logs"), slog.Int("retries", 3))
	entry := h.recordToDBEntry(rec)

	stored := StoredRecord{Time: entry.Time, Level: entry.Level, Message: entry.Message, Fields: entry.Fields}

	if err := VerifyRecord(stored, entry.RecordHash, entry.Signature, &mockVerifier{}); err != nil {
		t.Fatalf("untampered record failed verification: %v", err)
	}

	// Simulate database-side normalization on read-back: JSON columns get
	// reordered/reformatted and Postgres returns timestamps in UTC.
	reformatted := stored
	reformatted.Fields = json.RawMessage(`{ "retries" : 3 , "table" : "logs" }`)
	if err := VerifyRecord(reformatted, entry.RecordHash, entry.Signature, &mockVerifier{}); err != nil {
		t.Fatalf("reformatted-but-equal fields failed verification: %v", err)
	}

	utcStored := stored
	utcStored.Time = stored.Time.UTC()
	if err := VerifyRecord(utcStored, entry.RecordHash, entry.Signature, &mockVerifier{}); err != nil {
		t.Fatalf("UTC read-back failed verification: %v", err)
	}
}

func TestVerifyRecord_Tampering(t *testing.T) {
	h := &Handler{cfg: Config{IntegritySigner: mockSigner{}}}
	rec := slog.NewRecord(time.Date(2026, 8, 3, 10, 42, 23, 123000000, time.UTC), slog.LevelInfo, "audit event", 0)
	rec.AddAttrs(slog.String("user", "alice"), slog.Int("amount", 100))
	entry := h.recordToDBEntry(rec)

	// Tamper with content but keep the original hash+signature: the
	// recomputed hash no longer matches, so this must be detected.
	tamperedMsg := StoredRecord{Time: entry.Time, Level: entry.Level, Message: "audit event (edited)", Fields: entry.Fields}
	if err := VerifyRecord(tamperedMsg, entry.RecordHash, entry.Signature, &mockVerifier{}); !errors.Is(err, ErrHashMismatch) {
		t.Errorf("tampered message: got %v, want ErrHashMismatch", err)
	}

	tamperedFields := StoredRecord{Time: entry.Time, Level: entry.Level, Message: entry.Message, Fields: json.RawMessage(`{"amount":1000000,"user":"alice"}`)}
	if err := VerifyRecord(tamperedFields, entry.RecordHash, entry.Signature, &mockVerifier{}); !errors.Is(err, ErrHashMismatch) {
		t.Errorf("tampered fields: got %v, want ErrHashMismatch", err)
	}

	tamperedLevel := StoredRecord{Time: entry.Time, Level: slog.LevelWarn.String(), Message: entry.Message, Fields: entry.Fields}
	if err := VerifyRecord(tamperedLevel, entry.RecordHash, entry.Signature, &mockVerifier{}); !errors.Is(err, ErrHashMismatch) {
		t.Errorf("tampered level: got %v, want ErrHashMismatch", err)
	}

	// A valid hash for the new content but a stale signature must fail the
	// signature check (an attacker cannot mint signatures without the key).
	newCanonical, err := CanonicalBytes(tamperedMsg.Time, tamperedMsg.Level, tamperedMsg.Message, tamperedMsg.Fields)
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	newHash, err := mockHash(newCanonical)
	if err != nil {
		t.Fatalf("mockHash: %v", err)
	}
	err = VerifyRecord(tamperedMsg, hex.EncodeToString(newHash), entry.Signature, &mockVerifier{})
	if err == nil || errors.Is(err, ErrHashMismatch) {
		t.Errorf("stale signature: got %v, want signature verification error", err)
	}
	if err != nil && !strings.Contains(err.Error(), "signature verification failed") {
		t.Errorf("stale signature: unexpected error %v", err)
	}
}

func TestVerifyRecord_FailClosed(t *testing.T) {
	h := &Handler{cfg: Config{IntegritySigner: mockSigner{}}}
	rec := slog.NewRecord(time.Date(2026, 8, 3, 10, 42, 23, 123000000, time.UTC), slog.LevelInfo, "msg", 0)
	entry := h.recordToDBEntry(rec)
	stored := StoredRecord{Time: entry.Time, Level: entry.Level, Message: entry.Message, Fields: entry.Fields}

	// Both columns empty, and the signature-stripped case: clearing either
	// column must not silently pass (a tamperer's easy win).
	if err := VerifyRecord(StoredRecord{}, "", nil, nil); !errors.Is(err, ErrUnsignedRecord) {
		t.Errorf("fully unsigned: got %v, want ErrUnsignedRecord", err)
	}
	if err := VerifyRecord(stored, entry.RecordHash, nil, &mockVerifier{}); !errors.Is(err, ErrUnsignedRecord) {
		t.Errorf("signature stripped: got %v, want ErrUnsignedRecord", err)
	}
	if err := VerifyRecord(stored, "", entry.Signature, &mockVerifier{}); !errors.Is(err, ErrUnsignedRecord) {
		t.Errorf("hash stripped: got %v, want ErrUnsignedRecord", err)
	}

	// Signature present but no usable verifier.
	if err := VerifyRecord(stored, entry.RecordHash, entry.Signature, nil); !errors.Is(err, ErrNilVerifier) {
		t.Errorf("nil verifier: got %v, want ErrNilVerifier", err)
	}
	var typedNil *mockVerifier
	if err := VerifyRecord(stored, entry.RecordHash, entry.Signature, typedNil); !errors.Is(err, ErrNilVerifier) {
		t.Errorf("typed-nil verifier: got %v, want ErrNilVerifier", err)
	}

	// Corrupted stored hash (not valid hex).
	if err := VerifyRecord(stored, "zzzz-not-hex", entry.Signature, &mockVerifier{}); err == nil {
		t.Error("non-hex record_hash: expected error, got nil")
	}
}
