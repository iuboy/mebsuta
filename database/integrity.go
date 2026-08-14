// Package database provides a slog-compatible handler that persists log
// records to a SQL database in batches.
//
// IntegritySigner is an optional, algorithm-agnostic hook for tamper-evidence.
// The database handler does NOT depend on any specific cryptographic library;
// callers inject a concrete signer (SM2+SM3, ECDSA+SHA256, etc.).

package database

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"
)

// Errors returned by VerifyRecord. VerifyRecord fails closed: a record
// without a hash or signature is reported as ErrUnsignedRecord instead of
// silently passing, so auditors decide explicitly how to treat unsigned rows.
var (
	// ErrUnsignedRecord indicates the stored record has no record_hash or no
	// signature. A tamperer who clears either column produces this error too.
	ErrUnsignedRecord = errors.New("mebsuta/database: record is unsigned (missing record_hash or signature)")

	// ErrNilVerifier indicates a signature is present but no verifier was
	// supplied (including a typed-nil implementation).
	ErrNilVerifier = errors.New("mebsuta/database: verifier is nil")

	// ErrHashMismatch indicates the hash recomputed from the stored record
	// content differs from the stored record_hash — the content was likely
	// tampered with after signing.
	ErrHashMismatch = errors.New("mebsuta/database: record content does not match stored hash (possible tampering)")
)

const (
	// canonicalTimeLayout renders timestamps in UTC with a fixed microsecond
	// fraction (no trailing-zero trimming), so identical instants always
	// produce identical canonical bytes.
	canonicalTimeLayout = "2006-01-02T15:04:05.000000Z07:00"

	// canonicalPrecision matches the resolution of the PostgreSQL timestamptz
	// column that stores the timestamp. Sub-microsecond digits are dropped
	// from the canonical form and from the stored value when signing is
	// enabled, so re-computing the hash from the stored row reproduces the
	// signed hash exactly.
	canonicalPrecision = time.Microsecond
)

// canonicalRecord is the deterministic shape encoded by CanonicalBytes.
// JSON encoding makes the representation unambiguous (no delimiter
// collisions with message content) and stable across Go versions.
type canonicalRecord struct {
	Time   string          `json:"t"`
	Level  string          `json:"l"`
	Msg    string          `json:"m"`
	Fields json.RawMessage `json:"f"`
}

// canonicalFields normalizes raw JSON into a deterministic form: keys sorted,
// no insignificant whitespace, Go-native escaping. PostgreSQL's json type
// preserves column text exactly, so this normalization is defense in depth —
// it keeps the canonical form stable if the column is ever migrated to jsonb
// (which normalizes documents) and converges numbers regardless of how the
// value was serialized. Both the signing side and the verification side pass
// the fields column through it instead of comparing raw bytes.
func canonicalFields(fields json.RawMessage) (json.RawMessage, error) {
	if len(fields) == 0 {
		return nil, nil
	}
	var v any
	if err := json.Unmarshal(fields, &v); err != nil {
		return nil, fmt.Errorf("mebsuta/database: fields are not valid JSON: %w", err)
	}
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("mebsuta/database: canonicalize fields: %w", err)
	}
	return data, nil
}

// CanonicalBytes returns the canonical byte representation of a record: the
// exact bytes signed by IntegritySigner at write time and re-computed by
// VerifyRecord at audit time. It is deterministic and independent of the
// storage round-trip:
//
//   - Time is converted to UTC and truncated to microsecond precision
//     (canonicalPrecision), matching the resolution of PostgreSQL
//     timestamptz columns.
//   - Fields are normalized via canonicalFields, tolerating the key
//     reordering and whitespace changes databases apply to JSON columns.
//
// Auditing tools should use this function (not a hand-rolled serialization)
// when re-computing hashes of stored records.
func CanonicalBytes(t time.Time, level, message string, fields json.RawMessage) ([]byte, error) {
	f, err := canonicalFields(fields)
	if err != nil {
		return nil, err
	}
	return json.Marshal(canonicalRecord{
		Time:   t.UTC().Truncate(canonicalPrecision).Format(canonicalTimeLayout),
		Level:  level,
		Msg:    message,
		Fields: f,
	})
}

// IntegritySigner provides per-record integrity protection (hash + signature)
// for database log entries.
//
// The handler signs the output of CanonicalBytes for each record. The
// returned recordHash and signature are persisted alongside the entry so any
// later tampering can be detected by re-computing the hash with
// CanonicalBytes and verifying via IntegrityVerifier (see VerifyRecord).
//
// Implementations may use any algorithm pair (e.g. SM2+SM3 for GM compliance,
// ECDSA+SHA256 for international). The handler is algorithm-agnostic and
// introduces no cryptographic dependencies itself.
type IntegritySigner interface {
	// Sign computes a hash of data (typically the output of CanonicalBytes)
	// and signs it, returning the raw hash and signature bytes. The hash is
	// stored hex-encoded in the record_hash column; the signature is stored
	// as raw bytes in the signature column.
	//
	// Sign must be safe for concurrent use: slog handlers may process records
	// from multiple goroutines, so the handler calls Sign concurrently.
	// Implementations that hold mutable state (HSM sessions, reused hash
	// objects, buffers) must synchronize access themselves.
	Sign(data []byte) (recordHash, signature []byte, err error)

	// Algorithm returns a short stable identifier for the algorithm pair,
	// e.g. "SM2-SM3" or "ECDSA-SHA256". Stored in the sign_algo column so
	// verifiers know which algorithm to use.
	Algorithm() string
}

// IntegrityVerifier is the mirror of IntegritySigner for verification. It is
// not required at write time; callers that need to audit stored records
// implement this and pass it to VerifyRecord.
//
// Like IntegritySigner, implementations must be safe for concurrent use.
type IntegrityVerifier interface {
	// Hash computes the record hash of canonical data (the output of
	// CanonicalBytes) using the same digest algorithm as the matching signer.
	// VerifyRecord uses it to recompute the hash of a stored record and bind
	// the stored hash to the record content.
	Hash(data []byte) ([]byte, error)

	// Verify checks that signature is valid for recordHash. Returns nil on
	// success.
	Verify(recordHash, signature []byte) error

	// Algorithm returns the algorithm identifier (must match the signer's).
	Algorithm() string
}

// StoredRecord carries the persisted columns of one log entry as read back
// from the database, for verification with VerifyRecord.
type StoredRecord struct {
	Time    time.Time       // contents of the time column.
	Level   string          // contents of the level column.
	Message string          // contents of the msg column.
	Fields  json.RawMessage // contents of the fields column; any key order or whitespace.
}

// VerifyRecord checks the integrity of a stored log entry end to end:
//
//  1. The hash recomputed from the record content (via CanonicalBytes and
//     verifier.Hash) must equal the stored record_hash — this binds the hash
//     to the content, so editing the message or fields after the fact is
//     detected even if the stored hash and signature are left untouched.
//  2. The stored signature must verify against that hash.
//
// It fails closed: records lacking a hash or signature return
// ErrUnsignedRecord rather than passing silently — a tamperer who clears the
// signature column must not get a free pass. Callers that deliberately allow
// unsigned records can match this error with errors.Is.
func VerifyRecord(rec StoredRecord, recordHashHex string, signature []byte, verifier IntegrityVerifier) error {
	if len(recordHashHex) == 0 || len(signature) == 0 {
		return ErrUnsignedRecord
	}
	if isNilVerifier(verifier) {
		return ErrNilVerifier
	}

	canonical, err := CanonicalBytes(rec.Time, rec.Level, rec.Message, rec.Fields)
	if err != nil {
		return err
	}
	expected, err := verifier.Hash(canonical)
	if err != nil {
		return fmt.Errorf("mebsuta/database: recompute record hash: %w", err)
	}

	stored, err := hex.DecodeString(recordHashHex)
	if err != nil {
		return fmt.Errorf("mebsuta/database: record_hash column is not valid hex: %w", err)
	}
	if !bytes.Equal(expected, stored) {
		return ErrHashMismatch
	}

	if err := verifier.Verify(stored, signature); err != nil {
		return fmt.Errorf("mebsuta/database: signature verification failed: %w", err)
	}
	return nil
}

// isNilVerifier reports whether verifier is an untyped nil or a typed-nil
// pointer/map/slice/func/chan value, guarding VerifyRecord against panics
// when a caller fails to construct a verifier (e.g. a nil *MyVerifier).
func isNilVerifier(verifier IntegrityVerifier) bool {
	if verifier == nil {
		return true
	}
	switch v := reflect.ValueOf(verifier); v.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return v.IsNil()
	default:
		return false
	}
}
