# Mebsuta Cross-Language Specification

This document defines the behavior that both the Go and Rust implementations must preserve. Language-specific APIs may differ, but observable logging behavior should stay aligned unless a section explicitly marks a language exception.

## Scope

Mebsuta is maintained as a dual-language monorepo:

- Go implementation: `go/`
- Rust implementation: `rust/`
- Repository governance, shared policy, and compatibility rules: repository root

The specification covers handler behavior, output formats, safety properties, and lifecycle semantics. It is the source of truth for cross-language consistency.

## Levels

`Required`

Both implementations must order levels by severity:

1. `Trace`
2. `Debug`
3. `Info`
4. `Warn`
5. `Error`
6. `Audit`

**Pass/fail criteria:**
- A handler configured at `Warn` must drop `Debug` and `Info` records and accept `Warn`, `Error`, and `Audit` records.
- `Audit` records must pass through a handler configured at `Error` level (Audit >= Error severity).

## Structured Records

`Required`

Records must include:

- timestamp
- level
- message
- user-provided attributes

`Recommended`

- caller/module data when supported by the implementation
- audit metadata when the record is an audit event

**Pass/fail criteria:**
- JSON output must contain `time`, `level`, and `msg` (or `message`) keys.
- User-provided attributes must appear in the output with correct values.
- Attribute keys must remain stable after handler decoration (a record passed through Sampling or Async must retain its original attributes).

## JSON Output

`Required`

JSON output must be line-delimited: one JSON object per record.

Required keys:

- `time`
- `level`
- `msg` or `message`

`Recommended`

- `event_type` for audit events
- `actor` for audit actor identity
- `success` for audit success state

**Pass/fail criteria:**
- Output parses as valid JSON (one object per line) for all supported value types including strings, integers, floats, booleans, and nil/null.
- Non-finite floating-point values (NaN, +Inf, -Inf) must not produce invalid JSON.

## Text Output

`Required`

Text output must include at least:

- timestamp or equivalent record time
- level
- message
- attributes in a readable key-value form

`Language-specific`

Text format details (key-value separator, timestamp format, attribute ordering) are not a stable machine contract. Implementations may differ.

**Pass/fail criteria:**
- Text output contains the record message string.
- Text output contains a string representation of the level.
- Text output contains at least one user-provided attribute.

## File Handler

`Required`

File handlers must:

- create parent directories when possible
- append to existing log files
- write one record at a time without interleaving bytes from concurrent writers
- use restricted file permissions on Unix-like platforms: `0600`
- keep `Close` idempotent (second and subsequent calls return nil error)
- ignore writes after close without panicking

**Pass/fail criteria:**
- After `Close()`, a second `Close()` returns nil.
- After `Close()`, calling `Handle()` returns nil (no panic).
- Concurrent `Handle()` calls from multiple goroutines/threads must not lose records.
- `stat()` on the log file must show mode `0600` on Unix.

Rotation:

`Required`

- support size-based rotation
- create a fresh active log file after rotation
- keep the fresh active log file at `0600` on Unix-like platforms
- support maximum backup count cleanup

`Recommended`

- support time-based rotation when configured
- support maximum age cleanup
- support gzip compression when configured

**Pass/fail criteria:**
- After writing beyond `MaxSizeBytes`, a backup file exists and the active file is fresh (size < MaxSizeBytes).
- Backup count must not exceed `MaxBackups`.
- Compressed backup must be valid gzip and decompress to the original content.
- The fresh active file after rotation must have `0600` permissions on Unix.

## Syslog Handler

`Required`

Messages must:

- derive priority from facility and level
- avoid invalid UTF-8 output
- truncate oversized messages without splitting UTF-8 grapheme clusters where practical

`Recommended`

- sanitize hostname and tag values to protocol-safe forms
- support RFC3164 and RFC5424 formatting where implemented

`Language-specific`

Go currently supports TLS transport and network delivery. Rust currently focuses on formatting and send behavior. Rust TLS transport is a planned feature.

**Pass/fail criteria:**
- Truncated output must be valid UTF-8 (no partial multi-byte sequences).
- Priority value must equal `facility * 8 + severity` for the configured facility and record level.

## Database Handler

`Required`

Database handlers must:

- validate table names before using them in SQL (only letters, digits, underscores; must start with letter or underscore)
- batch writes when configured
- flush queued records on close
- make `Close` idempotent
- avoid panics during concurrent close/write races
- surface internal failures through the configured error handler

`Recommended`

- include time, level, message, and structured fields in output
- include audit metadata where supported

**Pass/fail criteria:**
- Table name containing special characters (spaces, semicolons, dashes) must be rejected by `Validate()`.
- After `Close()`, all records submitted before `Close()` must be present in the database.
- After `Close()`, a second `Close()` must return nil.

## Sampling

`Required`

Sampling must:

- pass through an initial number of records in each window
- sample later records according to the configured thereafter value
- reset counters when the sampling window expires
- always preserve error-level and audit-level records unless explicitly documented otherwise

**Pass/fail criteria:**
- First `Initial` records in a window must all be delivered.
- Records beyond `Initial` must be sampled at approximately `1/Thereafter` rate.
- Error and Audit records must not be dropped regardless of sampling state.

## Async Handler

`Required`

Async handlers must:

- enqueue records into a bounded buffer
- drop rather than block indefinitely when the buffer is full
- keep `Close` idempotent
- flush queued records on close
- ignore writes after close without panicking

`Recommended`

- expose dropped-count visibility where supported

`Language-specific`

Flush may be best-effort unless the API explicitly promises persistence. Close is the persistence boundary for queued records.

**Pass/fail criteria:**
- Records written before `Close()` must be delivered to the inner handler.
- When the buffer is full, additional writes must not block (they are dropped).
- After `Close()`, calling `Handle()` returns nil (no panic).
- After `Close()`, a second `Close()` returns nil.

## Multi Handler

`Required`

Multi-output handlers must:

- fan out a record to all enabled child handlers
- isolate child handler failures where practical
- avoid mutating a shared record in a way that causes data races
- close all closeable children and aggregate errors where supported

**Pass/fail criteria:**
- Each child handler receives the same record content.
- A panic in one child handler must not prevent other children from receiving the record.
- Concurrent writes through a multi-handler must not cause data races (verified by race detector).

## Error Handling

`Required`

- A nil or disabled error handler must not cause a panic.

`Recommended`

- Internal handler errors should be reported through a configurable error handler.
- Handler write failures may be returned to the caller when the language API supports that behavior.
- Silent drops must be documented and counted where practical.

**Pass/fail criteria:**
- Setting error handler to nil must not panic on subsequent handler errors.

## Security

`Required`

Both implementations must:

- avoid logging raw database passwords in sanitized config output
- validate database table identifiers
- use restricted log file permissions on Unix-like platforms (`0600`)
- avoid invalid JSON output for unusual values

`Recommended`

- TLS certificate verification should be enabled by default when TLS is supported. Any skip-verify option must be explicit in configuration.

**Pass/fail criteria:**
- `Sanitize()` or equivalent config output must not contain raw DSN passwords.
- Table name validation must reject strings containing characters outside `[a-zA-Z0-9_]`.
- Log files must have `0600` mode on Unix.
- JSON output containing NaN, +Inf, -Inf must produce valid JSON.

## Compatibility

The shared behavior in this document is a compatibility contract. Changing it requires:

- a changelog entry
- a versioning assessment
- test updates in both languages when applicable
- documentation updates in language README files if user-facing behavior changes
