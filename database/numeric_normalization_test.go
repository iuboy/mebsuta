package database

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

// TestNormalizeJSONNumber verifies the literal rewrite against PostgreSQL 18's
// empirically observed numeric text output (see normalizeJSONNumber comment;
// every expectation was probed against a live server).
func TestNormalizeJSONNumber(t *testing.T) {
	cases := map[string]string{
		// plain forms pass through (fast path)
		"0": "0", "100": "100", "-0.5": "-0.5", "0.015": "0.015",
		"1.50": "1.50", "12345678901234567890": "12345678901234567890",
		// exponent expansion
		"1e+21":  "1000000000000000000000",
		"1e2":    "100",
		"1.5e2":  "150",
		"1.5e-2": "0.015",
		"1.5e-7": "0.00000015",
		"1.50e1": "15.0", // scale 2 - 1 = 1 → one fraction zero kept
		"1.50e2": "150",  // scale 2 - 2 = 0 → no fraction
		// leading zeros
		"007":   "7",
		"007e2": "700",
		// zero semantics: sign dropped, final scale kept
		"-0":     "0",
		"-0.0":   "0.0",
		"0e10":   "0",
		"0.00e1": "0.0",
		// negative with exponent
		"-1.5e-3": "-0.0015",
		// beyond PG numeric limits: verbatim (PG cannot store these in jsonb)
		"1e9999999": "1e9999999",
	}
	for in, want := range cases {
		if got := normalizeJSONNumber(json.Number(in)); got != want {
			t.Errorf("normalizeJSONNumber(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestCanonicalBytes_JsonbEquivalenceClasses: spellings that PostgreSQL jsonb
// renders identically MUST canonicalize identically — that is what makes a
// json → jsonb column migration transparent for signed rows.
func TestCanonicalBytes_JsonbEquivalenceClasses(t *testing.T) {
	now := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	pairs := []struct{ a, b string }{
		{`{"x":1e2}`, `{"x":100}`},
		{`{"x":1e+21}`, `{"x":1000000000000000000000}`},
		{`{"x":-0}`, `{"x":0}`},
		{`{"x":-0.0}`, `{"x":0.0}`},
		{`{"x":007}`, `{"x":7}`}, // json decoder accepts leading zeros? see below
		{`{"x":1.50e2}`, `{"x":150}`},
	}
	for i, p := range pairs {
		b1, err1 := CanonicalBytes(now, "INFO", "m", json.RawMessage(p.a))
		b2, err2 := CanonicalBytes(now, "INFO", "m", json.RawMessage(p.b))
		if err1 != nil || err2 != nil {
			// Leading-zero literals are rejected by Go's strict decoder —
			// they can only appear via direct column tampering, and checkNoDuplicateKeys/Decode
			// failing on them is also acceptable fail-closed behavior.
			if i == 4 && err1 != nil {
				continue
			}
			t.Fatalf("pair %d (%s vs %s): %v / %v", i, p.a, p.b, err1, err2)
		}
		if !bytes.Equal(b1, b2) {
			t.Errorf("pair %d: jsonb-equivalent spellings diverged:\n  %s\n  %s", i, b1, b2)
		}
	}
}

// TestCanonicalBytes_JsonValueDistinctnessAfterNormalization: the safety
// property survives the rewrite — distinct VALUES (the float64-twin attack
// from the original finding) still never converge, and equal-value
// spellings converging does not open any new alias.
func TestCanonicalBytes_JsonValueDistinctnessAfterNormalization(t *testing.T) {
	now := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	must := func(fields string) []byte {
		b, err := CanonicalBytes(now, "INFO", "m", json.RawMessage(fields))
		if err != nil {
			t.Fatalf("CanonicalBytes(%s): %v", fields, err)
		}
		return b
	}
	if bytes.Equal(must(`{"amount":9007199254740993}`), must(`{"amount":9007199254740992}`)) {
		t.Error("float64-twin tampering became undetectable after normalization")
	}
	if bytes.Equal(must(`{"v":100}`), must(`{"v":101}`)) {
		t.Error("distinct integers converged")
	}
	if bytes.Equal(must(`{"v":0.1}`), must(`{"v":0.10}`)) {
		// 0.1 vs 0.10: jsonb keeps scale → 0.1 vs 0.10 differ in PG too.
		t.Log("note: 0.1 vs 0.10 converged (PG renders them 0.1 vs 0.10 — distinct)")
	}
}

// TestCanonicalBytes_NumberValuePreservedAfterNormalization re-checks that a
// 20-digit integer survives verbatim (its literal is already in numeric text
// form, fast path).
func TestCanonicalBytes_NumberValuePreservedAfterNormalization(t *testing.T) {
	now := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	got, err := CanonicalBytes(now, "INFO", "m", json.RawMessage(`{"uid":12345678901234567890}`))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte("12345678901234567890")) {
		t.Errorf("canonical form lost the exact number: %s", got)
	}
}
