// Package database provides a slog-compatible handler that persists log
// records to a SQL database in batches.
//
// IntegritySigner is an optional, algorithm-agnostic hook for tamper-evidence.
// The database handler does NOT depend on any specific cryptographic library;
// callers inject a concrete signer (SM2+SM3, ECDSA+SHA256, etc.).

package database

// IntegritySigner provides per-record integrity protection (hash + signature)
// for database log entries.
//
// The handler calls Sign with a canonical byte representation of each record
// (timestamp | level | message | fields). The returned recordHash and
// signature are persisted alongside the entry so that any later tampering can
// be detected by re-computing the hash and verifying the signature.
//
// Implementations may use any algorithm pair (e.g. SM2+SM3 for GM compliance,
// ECDSA+SHA256 for international). The handler is algorithm-agnostic and
// introduces no cryptographic dependencies itself.
type IntegritySigner interface {
	// Sign computes a hash of data and signs it, returning the raw hash and
	// signature bytes. Both are stored as-is (typically hex-encoded hash +
	// raw signature bytes in the record_hash / signature columns).
	Sign(data []byte) (recordHash, signature []byte, err error)

	// Algorithm returns a short stable identifier for the algorithm pair,
	// e.g. "SM2-SM3" or "ECDSA-SHA256". Stored in the sign_algo column so
	// verifiers know which algorithm to use.
	Algorithm() string
}

// IntegrityVerifier is the mirror of IntegritySigner for verification. It is
// not required at write time; callers that need to audit/verify stored records
// implement this and pass it to VerifyRecord.
type IntegrityVerifier interface {
	// Verify checks that signature is valid for hash. Returns nil on success.
	Verify(recordHash, signature []byte) error
	// Algorithm returns the algorithm identifier (must match the signer's).
	Algorithm() string
}

// VerifyRecord checks the integrity of a stored log entry. It is a convenience
// for tooling that audits persisted records. entry is the stored record;
// verifier provides the verification logic. Returns nil if the record is
// intact (or if no signature is present — callers should check for empty
// signature before calling when they want strict verification).
func VerifyRecord(recordHash, signature []byte, verifier IntegrityVerifier) error {
	if len(recordHash) == 0 || len(signature) == 0 {
		return nil // unsigned record — nothing to verify
	}
	return verifier.Verify(recordHash, signature)
}
