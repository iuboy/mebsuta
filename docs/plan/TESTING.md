# Testing Matrix

本矩阵追踪 Mebsuta Go 实现的行为覆盖。每个行为应保持充分测试。

## Required Checks

合并前必须运行：

```bash
go test -race -count=1 ./...
go vet ./...
gofmt -s -l .
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

`govulncheck` 需要联网更新漏洞数据。

## Behavior Coverage

| Behavior | Priority | Go Coverage | Status | Notes |
| --- | --- | --- | --- | --- |
| JSON record contains message, level, and nested attributes | P0 | `TestFileHandler_JSONFormat`, `TestStdoutHandler_JSONFormat` | covered | `time/level/message/attributes` 契约 |
| Audit JSON promotes reserved metadata fields | P0 | `TestAuditEvent_JSONContract`, `TestAudit_DefaultEventType` | covered | `event_type`, `actor`, `success` 为顶层字段 |
| Grouped JSON attributes use dotted keys under attributes | P1 | `TestStdoutHandler_WithGroup`, `TestFileHandler_WithGroup`, `TestAsyncHandler_WithGroup` | covered | JSON 不为 group 创建嵌套对象 |
| Text output contains message and attributes | P1 | `TestFileHandler_ConsoleFormat`, `TestStdoutHandler_TextFormat` | covered | Text 输出为人可读格式 |
| Level filtering drops lower-severity records | P0 | `TestFileHandler_LevelFilter`, `TestStdoutHandler_LevelFilter` | covered | Audit 必须通过 Error-level handler |
| Audit records pass through Error-level filtering | P0 | `TestWithSampling_ErrorAlwaysRecorded` | covered | SPEC 要求 Audit >= Error severity |
| File handler writes concurrently without record loss | P0 | `TestFileHandler_ConcurrentWrites` | covered | 显式并发写入测试 |
| Log file permissions are restricted to `0600` on Unix | P0 | `TestFileHandler_FilePermissionsRestricted`, check in `TestFileHandler_SizeRotation` | covered | `SPEC.md` 要求 |
| Size-based rotation creates backups and a fresh active file | P1 | `TestFileHandler_SizeRotation` | covered | 活跃文件权限必须保持受限 |
| Backup retention by count | P1 | `TestFileHandler_MaxBackups` | covered | |
| Gzip compression of rotated logs | P1 | `TestFileHandler_Compress`, `TestCompressResidual` | covered | 使用临时文件后 rename |
| Close is idempotent | P0 | `TestFileHandler_Close` | covered | 适用于所有 closeable handler |
| Writes after close do not panic | P0 | `TestFileHandler_Close` | covered | 适用于所有 closeable handler |
| Sampling initial and thereafter behavior | P1 | `TestWithSampling_BasicSampling`, `TestWithSampling_WarnSampled`, `TestWithSampling_WindowReset` | covered | |
| Sampling preserves error and audit records | P0 | `TestWithSampling_ErrorAlwaysRecorded` | covered | SPEC 要求 |
| Async handler drains queued records on close | P1 | `TestAsyncHandler_Close` | covered | Close 是持久化边界 |
| Async drops on full buffer without blocking | P0 | `TestAsyncHandler_DropOnFull` | covered | 不能无限阻塞 |
| Async close is idempotent | P0 | `TestAsyncHandler_Close` | covered | |
| Async ignores writes after close | P0 | `TestAsyncHandler_Close` | covered | Close 后不 panic |
| Multi handler isolates failures and panics | P0 | `TestSafeMultiHandler_PanicRecovery` | covered | 子 handler 失败不影响其他输出 |
| Multi handler does not cause data races | P0 | `TestSafeMultiHandler_AllEnabled` (with race detector) | covered | `-race` 验证 |
| Syslog RFC formatting | P2 | `TestSyslogHandler_WithAttrs`, `TestSyslogHandler_GroupPrefix` | covered | |
| Syslog UTF-8 sanitization and truncation | P0 | `TestSafeMessageForLog`, `TestCleanHostname` | covered | 避免 invalid UTF-8 |
| Database table name validation | P0 | config tests in `config_test.go` | covered | 防止 SQL 注入 |
| Database close flushes queued records | P1 | `TestCloseAll_*` (indirect) | covered | |
| Database concurrent close/write safety | P0 | `TestSafeMultiHandler_*` (multi wrapper) | covered | 不能 panic |
| Sensitive DSN masking | P0 | config sanitizer tests in `config_test.go` | covered | 不泄露密码 |
| Nil error handler does not panic | P0 | `TestErrorHandler_NilSilent` | covered | |
| Non-finite floats produce valid JSON | P0 | `TestFileHandler_JSONFormat_NonFiniteFloats` | covered | NaN/Inf 处理 |

## Priority Definitions

- **P0**: Security and correctness invariants. Must be covered before merge. Missing P0 coverage is a release blocker.
- **P1**: Lifecycle and durability behavior. Should be covered. Missing P1 coverage must be tracked as a follow-up issue.
- **P2**: Protocol details and integrations. Nice to have. Gaps are documented.

## Coverage Status

- **covered**: 有完整测试覆盖
- **partial**: 覆盖不完整（见 Notes）
- **missing**: 无测试覆盖

## Go Coverage (latest)

| Package | Coverage | Date |
| --- | --- | --- |
| mebsuta (main) | 80.7% | 2026-05-21 |
| database/ | 76.5% | 2026-05-21 |
| metrics/ | 90.6% | 2026-05-21 |

## Open Coverage Gaps

No open P0 coverage gaps are currently tracked.

## Adding New Behavior

当添加新功能时：

1. 更新 `SPEC.md` 如果行为应成为契约的一部分
2. 添加测试
3. 在本矩阵中添加一行
4. 更新 `CHANGELOG.md`
