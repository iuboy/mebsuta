# Migration Guide

当前世系自 v0.1.0-0 重新起算（2026-11-08），版本恒为 `v0.1.<patch>-<rev>`；
旧世系（v0.1.0–v0.8.0 及 monorepo 时代）无兼容关系，迁移说明见 CHANGELOG
末尾的历史记录。

## 当前破坏性变更迁移（v0.1.0-21…31）

### v0.1.0-22：错误处理器形态
- `DefaultErrorHandler` 读写改函数：读 `DefaultErrorHandler()`、写
  `SetDefaultErrorHandler(fn)`（nil 恢复 stderr 写入）。

### v0.1.0-24：保留窗语义
- `filerotate.Writer.SetMaxAgeDays` / `mebsuta.SetFileMaxAge`：0 与其他
  负值拒绝；关闭按龄清理传 `filerotate.UnlimitedAge(-1)`。

### v0.1.0-25：syslog 默认格式
- `syslog.Config.RFC5424 bool` 更名 `RFC3164 bool` 且语义反转：默认
  RFC5424。原 `RFC5424: true` 直接删除该字段；显式 RFC3164 传
  `RFC3164: true`。

### v0.1.0-26：契约统一
- `mebsuta.SetLevel`/`SetFileMaxAge` 首参 `*slog.Logger` →
  `slog.Handler`（传 `logger.Handler()`）。
- `AsyncDropped` 删除 → `mebsuta.Dropped`（walk 对全图求和）。
- 根包 handler 的 `setErrorHandler` → 导出 `SetErrorHandler`。
- `mebsuta.Info/Debug/Warn/Error` 及 Context 版删除（直接用 slog）。
- syslog/mbta 关闭后 `Handle` 返回 error（此前 nil）；越界
  `BufferSize`/`RetryDelay` 以 `*ConfigError` 拒绝（此前钳制）。

### v0.1.0-27：metrics 收敛
- `metrics.Metrics` 仅保留 `NewMetrics` + HandlerMetrics 三方法；
  `IncLogWrite`/`IncBatchWrite`/`SetBufferUsage` 等 13 个 mutator 删除。

### v0.1.0-29：遥测门面
- `mebsuta.StartSpan/Counter/Histogram/Gauge` 删除 →
  `telemetry.Telemetry` 同名实例方法（`tel.StartSpan(...)` 等）。

### v0.1.0-30：TLS 共享结构
- `syslog.Config.Secure/TLSSkipVerify` → `TLS *mebsuta.TLSConfig`。
- `telemetry.Config.TLSCAFile/TLSCertFile/TLSKeyFile/TLSServerName` →
  `TLS *mebsuta.TLSConfig`。
- `mbta.Config.CAFile/CertFile/KeyFile/ServerName/InsecureSkipVerify` →
  `TLS *mebsuta.TLSConfig`。

完整的逐版本明细见 [CHANGELOG](../CHANGELOG.md)。
