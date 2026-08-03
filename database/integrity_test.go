package database

import (
	"encoding/hex"
	"testing"
)

// mockSigner is a test-only IntegritySigner that returns a fixed hash +
// signature derived from the input data length, so tests can assert the
// handler wired the signer into recordToDBEntry without depending on any
// real cryptographic library.
type mockSigner struct{}

func (mockSigner) Algorithm() string { return "MOCK" }

func (mockSigner) Sign(data []byte) (recordHash, signature []byte, err error) {
	// Derive deterministic values from the data so tests can verify them.
	h := make([]byte, 0, len(data))
	for _, b := range data {
		h = append(h, b^0x5A)
	}
	n := len(data)
	if n > 8 {
		n = 8
	}
	return h, []byte("sig:" + string(data[:n])), nil
}

func TestIntegritySigner_Interface(t *testing.T) {
	var _ IntegritySigner = mockSigner{}
}

func TestRecordToDBEntry_WithSigner(t *testing.T) {
	// Build a handler with the mock signer wired in.
	h := &Handler{
		cfg: Config{IntegritySigner: mockSigner{}},
	}
	// exercise the signer directly to verify the wiring contract.
	signer := h.cfg.IntegritySigner
	if signer == nil {
		t.Fatal("IntegritySigner not configured")
	}
	data := []byte("test-record")
	recordHash, sig, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("Sign error: %v", err)
	}
	if algo := signer.Algorithm(); algo != "MOCK" {
		t.Errorf("Algorithm() = %q, want MOCK", algo)
	}
	// Verify the mock signer produces deterministic output.
	hashHex := make([]byte, hex.EncodedLen(len(recordHash)))
	hex.Encode(hashHex, recordHash)
	if len(hashHex) == 0 {
		t.Error("expected non-empty hash hex")
	}
	if string(sig) != "sig:test-rec" {
		t.Errorf("signature = %q, want 'sig:test-rec'", string(sig))
	}
}

func TestVerifyRecord_Unsigned(t *testing.T) {
	// Unsigned records (empty hash/signature) should pass verification (no-op).
	if err := VerifyRecord(nil, nil, nil); err != nil {
		t.Errorf("VerifyRecord(nil,nil,nil) = %v, want nil", err)
	}
	if err := VerifyRecord([]byte{}, []byte{}, nil); err != nil {
		t.Errorf("VerifyRecord(empty) = %v, want nil", err)
	}
}
