# Mebsuta Behavior Specification

本文档定义 Mebsuta Go 实现必须保持的行为契约。

## Scope

Mebsuta 是基于 `log/slog` Handler 构建的 Go 结构化日志库。核心差异化：审计级别 (LevelAudit) + 合规输出格式 (GB/T 22239, GM/T 0054)。

规范覆盖 handler 行为、输出格式、安全属性和生命周期语义。

## API Contract Design Notes

JSON 契约使用一个稳定的 envelope：

- `time`, `level`, `message`, `attributes` 为必选字段
- `event_type`, `actor`, `success` 为审计可选字段
- Mebsuta 使用 `message` 而非 `msg`，与 OpenTelemetry Logs Data Model 对齐
- RFC 5424 syslog transport 保持独立；嵌入 syslog 的 JSON 使用相同契约

## Contract Evolution

`Required`

机器可读契约仅在 major version 时可变更。包括 JSON 字段名、级别顺序、数据库列名和 syslog JSON payload 格式。

`Allowed without a major version`

- 添加可选的顶层字段
- 添加可选的 attributes
- 添加新的 `event_type` 值
- 添加新的 handler 配置选项（带保留行为的默认值）

`Requires a major version`

- 删除或重命名必选 JSON 字段
- 在顶层 JSON 和 `attributes` 之间移动字段
- 改变级别顺序或过滤语义
- 改变 close/flush 持久化保证
- 改变数据库 schema 列

## Levels

`Required`

级别按严重性排序：

1. `Trace`
2. `Debug`
3. `Info`
4. `Warn`
5. `Error`
6. `Audit`

**Pass/fail criteria:**
- 配置为 `Warn` 的 handler 必须丢弃 `Debug` 和 `Info` 记录，接受 `Warn`、`Error` 和 `Audit` 记录
- `Audit` 记录必须通过配置为 `Error` 级别的 handler（Audit >= Error severity）

## Structured Records

`Required`

记录必须包含：

- timestamp
- level
- message
- 用户提供的 attributes

`Recommended`

- caller/module 数据
- 审计元数据

**Pass/fail criteria:**
- JSON 输出必须包含 `time`, `level`, `message`, `attributes` 键
- 用户提供的 attributes 必须出现在 `attributes` 下且值正确
- 通过 Sampling 或 Async 后 attributes 保持不变

## JSON Output

`Required`

JSON 输出必须是 line-delimited：每条记录一个 JSON 对象。

Required keys:

- `time`
- `level`
- `message`
- `attributes`

Optional top-level keys:

- `event_type` for audit events
- `actor` for audit actor identity
- `success` for audit success state

顶层键由 Mebsuta 保留。具有预留名称的用户 attributes 在类型匹配时提升为顶层字段：

- `event_type`: string
- `actor`: string
- `success`: boolean

其他用户 attributes 必须保留在 `attributes` 下。分组 attributes 使用点分隔键扁平化，例如 `request.id`。

### JSON Schema

Canonical log record shape:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://mebsuta.dev/schemas/log-record.v1.json",
  "type": "object",
  "required": ["time", "level", "message", "attributes"],
  "additionalProperties": true,
  "properties": {
    "time": { "type": "string", "format": "date-time" },
    "level": { "type": "string", "enum": ["TRACE", "DEBUG", "INFO", "WARN", "ERROR", "AUDIT"] },
    "event_type": { "type": "string" },
    "message": { "type": "string" },
    "source": { "type": "string" },
    "actor": { "type": "string" },
    "success": { "type": "boolean" },
    "attributes": {
      "type": "object",
      "additionalProperties": true
    }
  }
}
```

### Examples

Normal record:

```json
{"time":"2026-05-21T14:00:00Z","level":"INFO","message":"request completed","attributes":{"request.id":"abc","status":200}}
```

Audit record:

```json
{"time":"2026-05-21T14:00:00Z","level":"AUDIT","event_type":"login","message":"user login","actor":"user:42","success":true,"attributes":{"ip":"127.0.0.1"}}
```

**Pass/fail criteria:**
- 输出解析为有效 JSON（每行一个对象），支持 string, int, float, bool, nil
- 非有限浮点值（NaN, +Inf, -Inf）不能产生 invalid JSON
- Audit helpers 必须设置 `event_type`；兼容 helpers 默认为 `system`

## Text Output

`Required`

Text 输出必须包含：

- timestamp
- level
- message
- attributes（可读的 key-value 形式）

Text 格式细节（分隔符、时间戳格式、attribute 排序）不是稳定的机器契约。

**Pass/fail criteria:**
- Text 输出包含记录消息字符串
- Text 输出包含级别字符串表示
- Text 输出包含至少一个用户提供的 attribute

## File Handler

`Required`

File handler 必须：

- 尽可能创建父目录
- 追加到现有日志文件
- 每次写入一条记录，并发写入不交错
- Unix 平台使用受限文件权限：`0600`
- `Close` 幂等（后续调用返回 nil error）
- 关闭后忽略写入，不 panic

**Pass/fail criteria:**
- `Close()` 后，第二次 `Close()` 返回 nil
- `Close()` 后，`Handle()` 返回 nil（不 panic）
- 多 goroutine 并发 `Handle()` 不丢失记录
- `stat()` 日志文件在 Unix 上显示 mode `0600`

Rotation:

`Required`

- 支持按大小轮转
- 轮转后创建新的活跃日志文件
- 新活跃文件保持 `0600` 权限
- 支持最大备份数清理

`Recommended`

- 支持按时间轮转
- 支持最大保留天数
- 支持 gzip 压缩

**Pass/fail criteria:**
- 写入超过 `MaxSizeBytes` 后，存在备份文件且活跃文件是新的（size < MaxSizeBytes）
- 备份数不超过 `MaxBackups`
- 压缩备份必须是有效 gzip 并解压为原始内容
- 轮转后的新文件在 Unix 上有 `0600` 权限

## Syslog Handler

`Required`

消息必须：

- 从 facility 和 level 推导 priority
- 避免 invalid UTF-8 输出
- 截断超长消息时不破坏 UTF-8

`Recommended`

- 清理 hostname 和 tag 值为协议安全形式
- 支持 RFC3164 和 RFC5424 格式化

Go 支持 TLS 传输和网络发送。

**Pass/fail criteria:**
- 截断输出必须是有效 UTF-8
- Priority 值必须等于 `facility * 8 + severity`

## Database Handler

`Required`

Database handler 必须：

- 使用前验证表名（仅允许字母、数字、下划线，必须以字母或下划线开头）
- 配置时批量写入
- 关闭时刷新队列中的记录
- `Close` 幂等
- 并发 close/write 时避免 panic
- 通过配置的 error handler 上报内部失败

`Recommended`

- 输出包含 time, level, message, 结构化字段
- 支持审计元数据

**Pass/fail criteria:**
- 包含特殊字符的表名必须被 `Validate()` 拒绝
- `Close()` 后，所有在 `Close()` 前提交的记录必须存在于数据库（前提：数据库可达。若数据库不可达且 flush 重试耗尽，记录通过 ErrorHandler 报告丢失）
- `Close()` 后，第二次 `Close()` 返回 nil

## Sampling

`Required`

Sampling 必须：

- 每个窗口中通过初始数量的记录
- 按配置的 thereafter 值采样后续记录
- 窗口过期时重置计数器
- 始终保留 error-level 和 audit-level 记录

**Pass/fail criteria:**
- 窗口中前 `Initial` 条记录必须全部送达
- 超过 `Initial` 的记录以约 `1/Thereafter` 的速率采样
- Error 和 Audit 记录无论采样状态都不被丢弃

## Async Handler

`Required`

Async handler 必须：

- 将记录入队到有界缓冲区
- 缓冲区满时丢弃而非无限阻塞
- `Close` 幂等
- 关闭时刷新队列中的记录
- 关闭后忽略写入，不 panic

`Recommended`

- 提供丢弃计数可见性

**Pass/fail criteria:**
- `Close()` 前写入的记录必须送达 inner handler
- 缓冲区满时，额外写入不阻塞（被丢弃）
- `Close()` 后，`Handle()` 返回 nil（不 panic）
- `Close()` 后，第二次 `Close()` 返回 nil

## Multi Handler

`Required`

Multi-output handler 必须：

- 将记录扇出到所有启用的子 handler
- 隔离子 handler 失败
- 不以导致数据竞争的方式修改共享记录
- 关闭所有可关闭的子 handler 并聚合错误

**Pass/fail criteria:**
- 每个子 handler 接收相同的记录内容
- 一个子 handler 的 panic 不阻止其他子 handler 接收记录
- 通过 multi-handler 的并发写入不导致数据竞争（race detector 验证）

## Handler Chain Composition

`Required`

当多个 handler 装饰器组合时，它们的顺序决定缓冲、采样和送达保证的正确性。

### Recommended Chain Order

Standard chain (File/Stdout destination):

```
safeMulti → Metrics → Sampling → Async → File|Stdout
```

Syslog/Database destination (no Async wrapping):

```
safeMulti → Metrics → Sampling → Syslog|Database
```

每个装饰器将下一个作为 inner handler 包装。记录通过 `Handle()` 从外到内流动；`Close()` 通过 `CloseAll` 从内到外传播。

### Prohibited Combinations

`Required`

以下装饰器组合被禁止，必须在运行时警告或构建时检查：

1. **Async wrapping Syslog (`Async → Syslog`)**: Syslog handler 维护自己的内部网络缓冲和发送队列。用 Async 包装 Syslog 会创建双重缓冲。`Close()` 时，Async 排干 channel 到 Syslog，但如果 Syslog 自己的缓冲也在刷新，记录可能在 Async channel 排干和 Syslog 网络刷新之间丢失。

2. **Async wrapping Database (`Async → Database`)**: Database handler 维护自己的批量缓冲并在关闭时刷新。用 Async 包装 Database 会创建双重缓冲，有相同的丢失场景。

两种情况共享同一根本原因：inner handler 已提供异步缓冲，外层 Async 增加延迟而不增加可靠性。

### Audit Level Semantics in Chains

`Required`

Audit-level 记录 (`LevelAudit = Error + 4`) 在每个装饰器中受到特殊处理：

| Decorator | Audit Behavior | Mechanism |
|-----------|---------------|-----------|
| Sampling | 始终记录，从不采样 | `r.Level >= slog.LevelError` 绕过计数器检查 |
| Async | 阻塞发送带 5s 超时，永不丢弃 | `ar.Level >= slog.LevelError` 使用阻塞 channel send |
| Metrics | 像其他记录一样记录 | 无级别特殊处理 |
| safeMulti | 扇出到所有子 handler | 无级别特殊处理 |

Audit 记录**不**完全绕过 Async 缓冲 — 它们进入同一个 channel 但使用阻塞发送策略。

### Close() Propagation

`Required`

`CloseAll` 通过 `handlerUnwrapper` 接口递归解包装饰器链，对每层实现 `io.Closer` 的调用 `Close()`，从最外层到最内层：

1. **Async**: 设置 closed 标志，取消 background context，关闭 channel，等待后台 goroutine 排干剩余记录，然后传播到 inner handler。
2. **Sampling**: 停止 reset ticker，通知后台 reset goroutine 退出，等待 goroutine 完成。
3. **Metrics**: 无 `Close()` 实现。对 close 传播透明。
4. **safeMulti**: 对每个子 handler 调用 `CloseAll()`，聚合错误。

`CloseAll` 在递归到 unwrapped inner handler 前访问每个装饰器自己的 `Close()`。这确保外层（Async drain）在内层（File/Database flush）关闭前完成。

**Pass/fail criteria:**
- `CloseAll()` 前写入的记录必须送达最终目标 handler
- `Async → Syslog` 和 `Async → Database` 组合必须产生警告或被拒绝
- Audit-level 记录无论采样状态都不被 Sampling 丢弃
- 通过 Async 发送的 Audit-level 记录必须被送达（阻塞发送），不静默丢弃
- 链上的 `CloseAll()` 返回遇到的第一个错误但不跳过剩余关闭
- 每个装饰器的 `Close()` 必须幂等（第二次调用返回 nil）

## Error Handling

`Required`

- nil 或禁用的 error handler 不能导致 panic

`Recommended`

- 内部 handler 错误应通过可配置的 error handler 报告
- Handler 写入失败可在 API 支持时返回给调用方
- 静默丢弃必须有文档记录并尽可能计数

**Pass/fail criteria:**
- 设置 error handler 为 nil 后续 handler 错误不 panic

## Security

`Required`

- 避免 sanitized config 输出中记录原始数据库密码
- 验证数据库表标识符
- Unix 平台使用受限日志文件权限 (`0600`)
- 避免异常值产生 invalid JSON

`Recommended`

- TLS 证书验证默认启用。任何 skip-verify 选项必须在配置中显式声明

**Pass/fail criteria:**
- `Sanitize()` 或等效 config 输出不能包含原始 DSN 密码
- 表名验证必须拒绝包含 `[a-zA-Z0-9_]` 外字符的字符串
- 日志文件在 Unix 上必须有 `0600` mode
- 包含 NaN, +Inf, -Inf 的 JSON 输出必须产生有效 JSON

## Compatibility

本文档中的行为是兼容性契约。修改需要：

- changelog 条目
- 版本评估
- 测试更新
- 用户可见行为变更时的文档更新
