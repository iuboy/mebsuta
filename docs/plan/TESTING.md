# Testing Matrix

This matrix tracks coverage for behavior shared by the Go and Rust implementations. It is intentionally high-level: exact test names may change, but each behavior should remain covered in both languages when the implementation supports it.

## Required Checks

Before merging implementation changes, run the relevant language checks:

```bash
cd go
go test -race -count=1 ./...
go vet ./...
gofmt -s -l .
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

```bash
cd rust
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
cargo audit
```

`cargo audit` and `govulncheck` require network access to update vulnerability data.

## Cross-Language Behavior

| Behavior | Priority | Go Coverage | Rust Coverage | Status | Notes |
| --- | --- | --- | --- | --- | --- |
| JSON record contains message, level, and nested attributes | P0 | `TestFileHandler_JSONFormat`, `TestStdoutHandler_JSONFormat` | `record::to_json_basic`, `record::to_json_with_attrs` | covered | Go and Rust now share the `time/level/message/attributes` machine contract. |
| Audit JSON promotes reserved metadata fields | P0 | `TestAuditEvent_JSONContract`, `TestAudit_DefaultEventType` | `record::to_json_audit_fields` | covered | `event_type`, `actor`, and `success` are top-level metadata, not user attributes. |
| Grouped JSON attributes use dotted keys under attributes | P1 | `TestStdoutHandler_WithGroup`, `TestFileHandler_WithGroup`, `TestAsyncHandler_WithGroup` | `handler::group_handler_prefixes_keys` | covered | JSON does not create nested objects for groups. |
| Text output contains message and attributes | P1 | `TestFileHandler_ConsoleFormat`, `TestStdoutHandler_TextFormat` | `file::file_handler_writes_text`, `stdout::file_handler_writes_json` | covered | Text output is human-readable, not a strict machine contract. |
| Level filtering drops lower-severity records | P0 | `TestFileHandler_LevelFilter`, `TestStdoutHandler_LevelFilter` | `file::file_handler_level_filter`, `stdout::enabled_level_filter` | covered | Audit must pass through Error-level handler (see audit row). |
| Audit records pass through Error-level filtering | P0 | `TestWithSampling_ErrorAlwaysRecorded` | `level::audit_event_types_equal_severity` | covered | SPEC requires Audit >= Error severity. |
| File handler writes concurrently without record loss | P0 | `TestFileHandler_ConcurrentWrites` | `file::concurrent_writes_no_loss` | covered | Both Go and Rust have explicit concurrent write tests. |
| Log file permissions are restricted to `0600` on Unix | P0 | `TestFileHandler_FilePermissionsRestricted`, check in `TestFileHandler_SizeRotation` | `file::file_permissions_restricted` | covered | Required by `SPEC.md`. |
| Size-based rotation creates backups and a fresh active file | P1 | `TestFileHandler_SizeRotation` | `file::size_rotation` | covered | Active file permissions must remain restricted. |
| Backup retention by count | P1 | `TestFileHandler_MaxBackups` | `file::size_rotation` (includes cleanup) | covered | Rust and Go may differ in exact backup name format. |
| Gzip compression of rotated logs | P1 | `TestFileHandler_Compress`, `TestCompressResidual` | `file::gzip_compress` | covered | Compression should use temp file then rename. |
| Close is idempotent | P0 | `TestFileHandler_Close` | `file::close_is_idempotent` | covered | Applies to all closeable handlers. |
| Writes after close do not panic | P0 | `TestFileHandler_Close` | `file::closed_handler_ignores_writes` | covered | Applies to all closeable handlers. |
| Sampling initial and thereafter behavior | P1 | `TestWithSampling_BasicSampling`, `TestWithSampling_WarnSampled`, `TestWithSampling_WindowReset` | `sampling::initial_passes_all`, `sampling::thereafter_samples`, `sampling::window_reset` | covered | Error and audit preservation covered when supported. |
| Sampling preserves error and audit records | P0 | `TestWithSampling_ErrorAlwaysRecorded` | `sampling::error_always_passes` | covered | Required by SPEC. |
| Async handler drains queued records on close | P1 | `TestAsyncHandler_Close` | `async::async_flush_drains_channel` | covered | Close is the durable flush boundary. |
| Async drops on full buffer without blocking | P0 | `TestAsyncHandler_DropOnFull` | `async::async_channel_full_drops` | covered | Must not block indefinitely. |
| Async close is idempotent | P0 | `TestAsyncHandler_Close` | `async::async_close_is_idempotent` | covered | |
| Async ignores writes after close | P0 | `TestAsyncHandler_Close` | `async::async_closed_ignores_writes` | covered | No panic after close. |
| Multi handler isolates failures and panics | P0 | `TestSafeMultiHandler_PanicRecovery` | `multi::panic_recovery`, `multi::swallows_handler_errors` | covered | Child failures should not crash unrelated outputs. |
| Multi handler does not cause data races | P0 | `TestSafeMultiHandler_AllEnabled` (with race detector) | `multi::fan_out_two_handlers`, `multi::fan_out_four_handlers` | covered | Go verified with `-race`. Rust verified by thread safety. |
| Syslog RFC formatting | P2 | `TestSyslogHandler_WithAttrs`, `TestSyslogHandler_GroupPrefix` | `syslog::rfc3164_format`, `syslog::rfc3339_format` | covered | Go supports network delivery; Rust currently focuses on formatting. |
| Syslog UTF-8 sanitization and truncation | P0 | `TestSafeMessageForLog`, `TestCleanHostname` | `syslog::truncate_*`, `syslog::sanitize_*`, `syslog::grapheme_*` | covered | Must avoid invalid UTF-8. Rust has extensive grapheme-aware truncation tests. |
| Database table name validation | P0 | config tests in `config_test.go` | `config::validate_table_names`, `database::database_rejects_bad_table_name` | covered | Prevent SQL injection through table identifiers. |
| Database close flushes queued records | P1 | `TestCloseAll_*` (indirect) | `database::database_writes_records`, `database::database_close_idempotent` | covered | Close should flush queued records before returning. |
| Database concurrent close/write safety | P0 | `TestSafeMultiHandler_*` (multi wrapper) | `database::database_closed_ignores_writes` | covered | Must not panic on concurrent close/write. |
| Sensitive DSN masking | P0 | config sanitizer tests in `config_test.go` | `config::mask_dsn*` | covered | Sanitized config output must not reveal raw passwords. |
| Nil error handler does not panic | P0 | `TestErrorHandler_NilSilent` | `handler::tests` (single_handler_also_swallows_errors) | covered | Setting error handler to nil must not cause panic. |
| Non-finite floats produce valid JSON | P0 | `TestFileHandler_JSONFormat_NonFiniteFloats` | `record::to_json_nonfinite_floats_valid` | covered | Both languages have explicit NaN/Inf JSON tests. |

## Priority Definitions

- **P0**: Security and correctness invariants. Must be covered before merge. Missing P0 coverage is a release blocker.
- **P1**: Lifecycle and durability behavior. Should be covered. Missing P1 coverage must be tracked as a follow-up issue.
- **P2**: Protocol details and integrations. Nice to have. Gaps are documented.

## Coverage Status

- **covered**: Both Go and Rust have test coverage for this behavior.
- **partial**: One or both languages have incomplete coverage (noted in Notes).
- **missing**: No test coverage exists for this behavior in one or both languages.
- **not applicable**: This behavior does not apply to one language.

## Go Coverage (commit 82d81c0 + round 2)

| Package | Coverage | Date |
| --- | --- | --- |
| go/ (main) | 80.7% | 2026-05-20 |
| go/config/ | 91.5% | 2026-05-20 |
| go/database/ | 76.5% | 2026-05-20 |
| go/metrics/ | 90.6% | 2026-05-20 |

### Key improvements (round 2)
- Main package: 68.4% → 80.7% (+12.3pp)
- Database: 47.0% → 76.5% (+29.5pp)
- Syslog: 0% → 79.2% (Handle/Close/formatMessage/reconnect all tested)
- 8 handler chain integration tests added
- 5 runnable examples added (examples/)

## Open Coverage Gaps

No open P0 coverage gaps are currently tracked.

## Adding New Shared Behavior

When adding a new feature to one language:

1. Update `SPEC.md` if the behavior should become a cross-language contract.
2. Add the language-specific tests.
3. Add a row to this matrix.
4. Mark unsupported language behavior explicitly instead of leaving it implicit.
5. Update `CHANGELOG.md` and language README files if the feature is user-facing.
