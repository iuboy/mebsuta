package database

import (
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/iuboy/mebsuta"
)

// tableNameRe validates SQL table names. Allows alphanumeric characters plus
// underscore, including digits as the first character (supported by
// PostgreSQL and openGauss via quoting). Schema-qualified names
// (schema.table) are also accepted. Digits-first is explicitly allowed
// because it's a legal table name in both supported databases.
var tableNameRe = regexp.MustCompile(`^[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)?$`)

const (
	// maxBatchSize caps the batch size to prevent unbounded channel/batch
	// allocation when a caller misconfigures a very large BatchSize.
	maxBatchSize = 10000

	// DefaultMaxRecordBytes is the per-record size bound applied when
	// Config.MaxRecordBytes is unset. 256KiB accommodates rich structured
	// records (deep JSON documents) while keeping the worst-case backlog
	// footprint bounded: the backlog holds BatchSize*10 entries, so at the
	// default batch size the ceiling is 1000 × 256KiB = 256MiB — the same
	// defensive tier as the syslog handler's maxMsgSize frame bound, sized
	// up for records that legitimately carry structured documents.
	DefaultMaxRecordBytes = 256 * 1024

	// MaxRecordBytesCap caps Config.MaxRecordBytes. Generous enough for
	// jsonb-typed records, but a hard wall against "just one huge field"
	// configurations that would otherwise resurrect the unbounded-backlog
	// footprint the field exists to prevent.
	MaxRecordBytesCap = 8 * 1024 * 1024

	// MaxRetryDelay caps Config.RetryDelay, mirroring the syslog handler:
	// every failed flush attempt sleeps for RetryDelay, so a misconfigured
	// multi-minute delay multiplies into the worst-case flush time and
	// stalls Close's drain for that long per retry.
	MaxRetryDelay = 30 * time.Second
)

// Config holds configuration for database log output.
type Config struct {
	Driver        string        // Required: "postgres" or "opengauss".
	DSN           string        // Required: database connection string.
	Table         string        // Required: log table name.
	Level         slog.Leveler  // Log level filter. Defaults to slog.LevelInfo.
	BatchSize     int           // Records per batch. 0 → 100.
	BatchInterval time.Duration // Flush interval. 0 → 5s.
	// MaxConnLifetime is the maximum connection lifetime. 0 = no limit (unlike
	// other fields where 0 means "use default", this follows database/sql
	// convention where 0 means unlimited).
	MaxConnLifetime time.Duration // Max connection lifetime. 0 = no limit.
	MaxOpenConns    int           // Max open connections. 0 → 10.
	MaxIdleConns    int           // Max idle connections. 0 → 5.
	RetryDelay      time.Duration // Delay between retries. 0 → 500ms, capped at MaxRetryDelay.
	// MaxRecordBytes bounds the encoded size of a single record admitted to
	// the backlog (message length + fields JSON length). Records exceeding
	// the limit keep their message — truncated UTF-8-safe to fit — but lose
	// their fields: the fields column is replaced with the
	// {"mebsuta_truncated":true} marker, and the loss is counted in
	// Handler.Dropped and surfaced through the rate-limited drop report.
	//
	// Without this bound the backlog (BatchSize*10 entries of unbounded
	// size) can reach hundreds of gigabytes of resident memory from a single
	// oversized attribute. 0 → DefaultMaxRecordBytes; Validate clamps values
	// above MaxRecordBytesCap.
	MaxRecordBytes int
	// ErrorTimeout bounds how long an Error-or-above record may block the
	// calling goroutine when the backlog channel is full, before the record
	// is dropped. 0 → 1s. Keep this small: request handlers call slog
	// synchronously, and a long block here lets a slow database turn Error
	// spikes into whole-service stalls.
	ErrorTimeout time.Duration
	// IntegritySigner optionally provides per-record hash+signature for
	// tamper-evidence. nil disables signing (default, backward compatible).
	// When set, each record gets record_hash / signature / sign_algo columns
	// populated before batch insert. The handler is algorithm-agnostic.
	//
	// The signer must be safe for concurrent use (records are signed from
	// multiple goroutines). Signing also caps stored timestamps at microsecond
	// precision so signatures remain verifiable after the database round-trip
	// (see CanonicalBytes).
	IntegritySigner IntegritySigner
	warnNoTLS       bool // internal: set by Validate when DSN lacks TLS params.
}

// Validate checks required fields and returns a normalized copy with defaults applied.
func (c Config) Validate() (Config, error) {
	if c.Driver == "" {
		return Config{}, &mebsuta.ConfigError{Field: "Driver", Msg: "driver is required"}
	}
	if c.Driver != "postgres" && c.Driver != "opengauss" {
		return Config{}, &mebsuta.ConfigError{Field: "Driver", Msg: "unsupported driver: " + c.Driver + " (supported: postgres, opengauss)"}
	}
	if c.DSN == "" {
		return Config{}, &mebsuta.ConfigError{Field: "DSN", Msg: "data source name is required"}
	}
	if c.Table == "" {
		return Config{}, &mebsuta.ConfigError{Field: "Table", Msg: "table name is required"}
	}
	if !tableNameRe.MatchString(c.Table) {
		return Config{}, &mebsuta.ConfigError{Field: "Table", Msg: "table name must match [a-zA-Z0-9_](.[a-zA-Z0-9_])?"}
	}
	// M9: PostgreSQL's and openGauss's NAMEDATALEN-1 = 63.
	const maxTableLen = 63
	if len(c.Table) > maxTableLen {
		return Config{}, &mebsuta.ConfigError{Field: "Table", Msg: fmt.Sprintf("table name too long (max %d, got %d)", maxTableLen, len(c.Table))}
	}
	if c.Level == nil {
		c.Level = slog.LevelInfo
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 100
	} else if c.BatchSize > maxBatchSize {
		c.BatchSize = maxBatchSize
	}
	if c.BatchInterval <= 0 {
		c.BatchInterval = 5 * time.Second
	}
	if c.MaxOpenConns <= 0 {
		c.MaxOpenConns = 10
	}
	if c.MaxIdleConns <= 0 {
		c.MaxIdleConns = 5
	}
	// Ensure idle pool does not exceed the open connection limit.
	if c.MaxIdleConns > c.MaxOpenConns {
		c.MaxIdleConns = c.MaxOpenConns
	}
	if c.RetryDelay <= 0 {
		c.RetryDelay = 500 * time.Millisecond
	}
	if c.RetryDelay > MaxRetryDelay {
		c.RetryDelay = MaxRetryDelay
	}
	if c.MaxRecordBytes <= 0 {
		c.MaxRecordBytes = DefaultMaxRecordBytes
	} else if c.MaxRecordBytes > MaxRecordBytesCap {
		c.MaxRecordBytes = MaxRecordBytesCap
	}
	if c.ErrorTimeout <= 0 {
		c.ErrorTimeout = time.Second
	}

	c.warnNoTLS = !dsnHasTLS(c.DSN)

	return c, nil
}

// dsnHasTLS checks whether the DSN contains TLS/SSL connection parameters.
//
// This is a best-effort heuristic used only to decide whether to emit a
// no-TLS warning; it does not gate any security control. It can be wrong in
// both directions: an embedded "sslmode=" substring inside e.g. a password
// suppresses the warning on a connection that is actually plaintext (false
// negative), and sslmode=prefer can fall back to plaintext silently after
// the warning was skipped. Treat the warning as advisory, not proof.
func dsnHasTLS(dsn string) bool {
	// PostgreSQL key=value DSN: any sslmode except "disable" enables TLS
	// (require, verify-ca, verify-full, prefer, allow).
	dsnLower := strings.ToLower(dsn)
	if !strings.Contains(dsnLower, "sslmode=") {
		return false
	}
	return !strings.Contains(dsnLower, "sslmode=disable")
}

// Sanitize returns a copy of the configuration whose DSN has its
// credential-like segments redacted with the same rules as database error
// messages (see dsnCredRe). The copy is safe to embed in logs, error text,
// and structured output; it is NOT connectable — pass the original Config to
// NewHandler. Like the error redaction itself this is a best-effort textual
// rewrite, not a DSN parser: passwords containing '@' cannot be separated
// from the host delimiter by regex and are only partially covered.
func (c Config) Sanitize() Config {
	if c.DSN != "" {
		c.DSN = redactCredentials(c.DSN)
	}
	return c
}

// String implements fmt.Stringer with the DSN's credentials redacted, so
// printing a Config with %v or %+v cannot leak the database password. All
// other fields render normally.
func (c Config) String() string {
	level, signer := c.renderAux()
	return fmt.Sprintf(
		"{Driver:%s DSN:%s Table:%s Level:%s BatchSize:%d BatchInterval:%s MaxConnLifetime:%s MaxOpenConns:%d MaxIdleConns:%d RetryDelay:%s ErrorTimeout:%s MaxRecordBytes:%d IntegritySigner:%s}",
		c.Driver, strconv.Quote(c.Sanitize().DSN), c.Table, level,
		c.BatchSize, c.BatchInterval, c.MaxConnLifetime,
		c.MaxOpenConns, c.MaxIdleConns, c.RetryDelay, c.ErrorTimeout,
		c.MaxRecordBytes, signer,
	)
}

// GoString implements fmt.GoStringer with the same redaction as String, so
// %#v output (debuggers, error templates) cannot leak the DSN's credentials
// either. Durations are rendered in human-readable form rather than raw
// nanoseconds.
func (c Config) GoString() string {
	level, signer := c.renderAux()
	return fmt.Sprintf(
		"database.Config{Driver:%q, DSN:%s, Table:%q, Level:%q, BatchSize:%d, BatchInterval:%s, MaxConnLifetime:%s, MaxOpenConns:%d, MaxIdleConns:%d, RetryDelay:%s, ErrorTimeout:%s, MaxRecordBytes:%d, IntegritySigner:%s}",
		c.Driver, strconv.Quote(c.Sanitize().DSN), c.Table, level,
		c.BatchSize, c.BatchInterval, c.MaxConnLifetime,
		c.MaxOpenConns, c.MaxIdleConns, c.RetryDelay, c.ErrorTimeout,
		c.MaxRecordBytes, signer,
	)
}

// renderAux returns the rendered Level and IntegritySigner fields shared by
// String and GoString. A nil Leveler prints as "<nil>"; a set signer prints
// as its algorithm identifier (the signer itself is never rendered).
func (c Config) renderAux() (level, signer string) {
	level = "<nil>"
	if c.Level != nil {
		// slog.Level renders as "INFO"/"WARN"/...; custom Levelers fall
		// back to their own fmt formatting.
		level = fmt.Sprintf("%v", c.Level)
	}
	signer = "<nil>"
	if c.IntegritySigner != nil {
		signer = c.IntegritySigner.Algorithm()
	}
	return level, signer
}
