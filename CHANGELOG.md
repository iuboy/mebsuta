# 更新日志

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
版本策略参见 [VERSIONING.md](docs/VERSIONING.md)。

## 版本策略（2026-11-08 起）

库版本自 **v0.1.0-0 重新起算**（世系重置）：此前的 v0.1.0–v0.8.0 及 latest
标签已从仓库（本地与远程）移除，其变更条目保留在本文档末尾仅作历史记录。
新世系版本号恒为 `v0.1.<patch>-<rev>`：只有 patch 与 rev 递增；默认进行
破坏性变更、无兼容要求（详见 [VERSIONING.md](docs/VERSIONING.md)）。目标
版本号已被占用即视为重复：rev 向后延续至下一个未占用值，已发布版本号永不
重用或覆盖。

## [0.1.0-0] - 2026-11-08

> 本节聚合世系重置前 v0.8.0 之后的全部未发布变更，以及 2026-11-08 第四轮
> 对抗性安全审计（四维度并行：并发生命周期/注入解析/资源 DoS/泄漏配置）的
> 全部修复。

### ⚠️ BREAKING CHANGES

- **metrics**: `HandlerMetrics.IncDropped(name)` → `IncDroppedN(name string, n int64)`——丢弃观测按量级而非次数计数（此前两次观测间丢 500 条只 +1）；自定义实现随签名更新
- **database**: `Config` 新增 `MaxRecordBytes`（默认 256KiB、上限 8MB）——超限记录截断 Fields 为 `_truncated` 占位并计 dropped；`RetryDelay` 钳制 30s 封顶（对齐 syslog/mbta）
- **mbta**: `Config.BatchSize` 钳制 10000；新增 `OnResult` 回调（RESULT 拒绝/释放对调用方可见）
- **async**: `AsyncConfig.BufferSize` 上限 10000（超限构造期 fail-fast，对齐 syslog/database 子包）
- **filerotate**: `RotateInterval` 下限 1s（更小值构造期报错——实测 1ns 致每次写完整轮转 ~1700× 慢化）
- **jwt/审计契约**：AUDIT 级记录的 record 级 `event_type/actor/success` 现提升到顶层 JSON（恢复 SPEC/README 声明的契约；非 AUDIT 维持 preset-only——防伪造裁决保留）

### 修复（安全）

- **[P1] database**：gorm 默认 logger 静音（`logger.Discard`）——DB 降级/慢查询时默认 logger 将整批日志字段值内插渲染到 stdout（内存 ×2 峰值 + 敏感数据绕过全部脱敏）；flush 驱动错误上报前过 `sanitizeDBError`（与 connect 路径对称）
- **[P1] mbta**：record→signal 按 mbta-go wire schema 预过滤（attrs ≤128 / 键 ≤256B / 控制字符替换）+ 发送前 `Validate()` 门 + `OnResult` 使服务端拒绝可见——此前超限批次被服务端整批拒收而客户端无感知（审计日志静默丢失）
- **[P2] 四个缓冲 handler**（async/database/syslog/mbta）：丢弃/错误报告移出 `sendMu` 锁外——用户 ErrorHandler 重入 Close 此前永久死锁（filerotate M4 同类，-race 实证复现）
- **[P2] sampling**：`Enabled` 无条件放行 Error+ 绕过内层级别过滤（审计专用 sink 被污染、动态调级失效）——恢复「Enabled 诚实、Handle 豁免」分层
- **[P2] syslog**：RFC5424 SD-PARAM 路径 Resolve LogValuer 并展开 Group（此前输出 Go 结构体内部表示——经 LogValuer 做脱敏的字段被绕过外泄，SD 与 JSON 同记录不一致）
- **[P2] mbta**：嵌套 group 展平为点分键（此前降级为有损字符串化）；Config 脱敏输出（Token `***`）
- **[P2] database**：记录尺寸上限 + 超限占位标记；深嵌套 sign-skip 计数可见；flush ctx-abort 分支不再静默吞批
- **[P2] async**：process 错误 1/s 限频（此前 inner 恒错时每条记录 1:1 stderr 放大）；`KindAny` []byte 属性快照拷贝
- **[P2] filerotate**：轮转压缩并发上限 4（此前每次轮转无界 spawn）

### 修复（正确性/观测/卫生）

- **关闭语义**：四个缓冲 handler + mbta 的二次 Close 改为等待首次排空完成（幂等）；asyncGroup 关闭丢弃计数；syslog/mbta closing 窗口丢弃计数；mbta 排空超时的 in-flight 丢失计入 dropped
- **mbta Close**：排空后等待最终批 RESULT 终态再发 CLOSE——control/data 流无跨流序，此前 CLOSE 可先于在途 BATCH 被服务端处理致连接提前拆除、末批静默丢失；Connect 串行化（并发 Connect 触发 mbta-go binding 双连收敛、败者清理关闭胜者连接）
- **mbta-go v0.6.0 → v0.1.0-0 升级随动**：`SignalRecord` 时间字段毫秒→纳秒迁移；依赖 pollux-go v0.1.2-3
- **观测**：MetricsHandler 丢弃按 delta 量级上报；attrutil 截断标记 `_truncated` 接线 JSON/database 路径（对齐 syslog 先例）
- **syslog**：SD 预算 escape 后计长（单参数 ~8KB 膨胀封堵）；marshal 错误回显 512B 截断；Error 级 send fast-path + ctx gate
- **配置校验**：表名 digits-first 的 SPEC 漂移、Sampling Close 描述、Async 超时语义多处文档对齐实现
- **CI/供应链**：security-scan 新增 gosec + gitleaks；govulncheck pin v1.1.4 → v1.9.0；全部 actions 改 SHA pin；examples/database 改 postgres（sqlite 仅测试依赖）
- **杂项**：safeMulti errorHandler 原子化；mebsutatest 包 TEST-ONLY 警示；README 补 SIGPIPE 与异步缓冲说明；filerotate 单写者约束文档化

### 修复

- **安全**：go 指令 1.26.9 + x/net v0.60.0——修复 6 个可达漏洞（commit 9f5b66d）
- **安全**：二轮安全审查修复 1 High / 7 Medium / 6 Low，全部附回归测试（commit 2451500）

### 新特性

- 遗留项清零：jsonb 迁移透明化 + metrics 丢弃观测接线 + 周期安全扫描（commit 3a5d591）

### 依赖

- 全部依赖升级至最新版本（commit 5ad54ab）

## [v0.8.0] - 2026-08-22

> 以下 v0.1.0–v0.8.0 条目属旧世系，仅作历史记录保留——对应标签已移除。

全面对抗性安全审查修复（9 High / 15 Medium / 12 Low），全部附回归测试。

### ⚠️ BREAKING CHANGES

- **database**: 移除 MySQL 支持（v0.7.x 后的 `refactor(database)!` 延续），仅保留 PostgreSQL 与 openGauss
- **database**: `VerifyRecord` 现在 fail-closed 校验 `sign_algo` 列 — `StoredRecord` 新增 `SignAlgo` 字段；缺失该列、或与 verifier 算法不符时返回 `ErrUnsignedRecord` / `ErrAlgoMismatch`（新增），不再静默通过。旧调用方需在读回行时填充该字段
- **JSON 输出**: `actor`/`event_type`/`success` 审计字段只从 preset attrs（`WithAttrs`）提升；record 级同名 attr 留在 `attributes` 内（此前可被日志调用点伪造信任锚点字段）
- **Error 级背压**: async/database/mbta 的 Error+ 记录满缓冲阻塞从硬编码 5s 改为可配置（`ErrorTimeout`，默认 1s）

### Security

- **database**: `CanonicalBytes` 数字精度修复 — 此前 canonical 化经 float64（53 位），≥2^53 的整数（金额、ID）可被篡改为 float64 舍入孪生值而签名仍验证通过。现用 `json.Number` 保留精确字面值，并拒绝含重复对象键或尾部多余数据的 fields 列（防 `{"k":orig,"k":forged}` 重写）。**升级后重算哈希即可检测历史行是否被此类手法篡改过**
- **syslog**: RFC5424 SD-PARAM 值过滤控制字符 — 此前 attr 值中的 LF 可在 LF 分帧 TCP 上走私完整伪造 syslog 消息（伪造 facility/HOST/APP-NAME）
- **filerotate**: `openAppend` 加 `O_NOFOLLOW`（Unix）— 封堵轮转 rename 窗口内植入 symlink 导致日志追加写入任意文件；移除不可达的 fstat symlink 假防线
- **filerotate**: `compressResidual` 严格匹配轮转备份命名（`isBackupName`，含 `.gz.tmp` 清理分支）— 此前默认配置下启动即压缩并**删除**同前缀无关文件（如 `app.log.notes`）
- **filerotate**: 压缩临时文件改用 `O_EXCL` — 预植 `<backup>.gz.tmp` symlink 无法再被 O_TRUNC 跟随清空任意文件
- **mbta**: `Close` 先排空再取消 context — 此前关机时最终 flush 拿到已取消的 ctx，**静默丢弃全部缓冲日志**（端到端复现 0/5 送达，现 5/5）
- **mebsuta**: JSON Marshal 失败降级输出 ERROR 兜底记录 — 此前嵌套 NaN/chan/func attr 导致整条记录无声消失（slog 吞掉错误）
- **mebsuta**: `WithErrorHandler` 现可到达子包 handler（database/syslog/mbta 新增导出 `SetErrorHandler`，实现新的 `ErrorHandlerSetter` 接口）— 此前注入接口未导出，自定义错误处理对全部子包静默失效

### Added

- **database**: openGauss 支持（官方 `gorm.io/driver/gaussdb`，sha256 认证）
- **database**: `CanonicalBytes` 导出为审计工具的规范重算入口；`VerifyRecord` 绑定算法列；批量 INSERT 按 1000 行/语句分块（修复 10000 行 × 7 列超 PostgreSQL 65535 绑定参数上限导致整管线失败）
- **syslog**: RFC5424 结构化数据预算（128 参数 / SD-NAME 32 字符 / PARAM-VALUE 4KB / 总量 32KB，超限打 `_truncated` 标记）；RFC5424 时间戳固定 6 位小数（符合 ABNF，严格接收端不再拒收）
- **mbta**: `Reconnect` 配置真正生效（会话非 READY 时在重试间重拨）；`CloseTimeout`（默认 5s）有界关闭 — `client.Close` 内部 drain 恒等 30s，此前无界阻塞关机直至被 SIGKILL
- **mebsuta**: async 后台 goroutine panic 恢复；`AsyncConfig.ErrorTimeout`；丢弃报告限频（每秒至多 1 条含累计数，洪泛不再 1:1 放大 stderr）
- **mbta**: `SeverityNumber` 按 OTel 数值映射（此前恒 0）；attr 预算与 LogValuer 解析；hostname 清洗

### Changed

- **Close 语义统一**: async/mbta 均改为 close → drain → cancel 顺序（与 syslog/database 一致），排空阶段下游 ctx 不再被取消；async 记录以 `context.WithoutCancel` 入队
- **syslog**: `Close` 有界排空（10s，超时报告丢弃数）；`RetryDelay` 封顶 30s（`MaxRetryDelay`）；`Flush(≤0)` 默认 5s
- **database**: 批次彻底失败时 `Close` 透出 flush 错误（不再静默返回 nil）；`dsnHasTLS` 文档修正假阴性方向
- **mebsuta**: `LogErrorHandler` 写入加锁；multi 错误聚合统一 `errors.Join`；unwrap 链递归深度封顶；`contractJSONHandler.WithGroup("")` 不再重置已有分组
- **依赖**: Go 工具链 1.26.5 → **1.26.6**（修复 crypto/tls GO-2026-6090、encoding/xml GO-2026-6088、encoding/asn1 GO-2026-5972 三个可达标准库漏洞，govulncheck 现零告警）

### Fixed

- filerotate `Close` 在锁外报告轮转错误（`OnError` 重入回调不再死锁）；`MaxSizeMB` 溢出校验（1 PiB 上限）
- async `asyncAttrsHandler` 克隆 record（不再变异调用方记录）；Close 后丢弃计数
- mbta `safeSend` recover 分支正确返回错误
- syslog RFC3164 非 JSON 模式丢弃 attrs 的一次性告警；空 SD-NAME 参数跳过

## [v0.7.1] - 2026-08-03

### Added

- **database**: `IntegritySigner` — 可选的每记录哈希+签名防篡改（算法无关接口，`record_hash`/`signature`/`sign_algo` 列）

### Fixed

- CI: staticcheck `@latest` → `@v0.7.0`（Go 1.26 兼容）；actions 版本升级 + paths-filter v4.0.2 修复 main 分支 CI

## [v0.7.0] - 2026-07-29

### Fixed

- **audit**: 全项目代码审查修复与架构优化
- **deps**: 升级多个依赖
- 代码逻辑审查修复（2 Medium + 2 Low）

## [v0.6.1] - 2026-07-16

### Changed

- CI: actions/setup-go v5 → v7.0.0（Node.js 24 runtime）

## [v0.6.0] - 2026-07-16

### Added

- **Timezone 配置**: 日志时间展示时区（`FileConfig`/`StdoutConfig`/syslog `TimeZone`）

### Fixed

- **audit**: 全项目代码审查修复（16 条发现）
- **mebsutatest**: `valueEqual` default 分支改用 `reflect.DeepEqual`
- **deps**: mbta-go v0.3.2 → v0.4.2、pollux-go v0.2.1 → v0.2.8

### Changed

- CI: actions/checkout v4 → v5.0.1、dorny/paths-filter v3.0.2 → v4.0.2（Node.js 24 runtime）

## [v0.5.0] - 2026-06-28

### Added

- `mbta/` 子包：通过 MBTA 二进制协议将日志直送 forwarder 的 `slog.Handler`，内置异步缓冲、批量刷新与重试，`UseMBTA()` 便捷 Option

### Security

- **mbta**: 透传完整 TLS 凭据（`CAFile`/`CertFile`/`KeyFile`/`ServerName`）。此前 `NewHandler` 仅转发 `InsecureSkipVerify`，导致 mTLS 双向认证与自定义 CA 被静默忽略；`InsecureSkipVerify=true` 时现发出 MITM 警告
- **mbta**: `recordToSignal` 用安全的 UUID 生成替代 `uuid.Must`，避免日志热路径在系统 PRNG 不可用时 panic
- **database**: `BatchSize` 加上限（10000），防止无界 channel/批量分配导致的资源耗尽
- **filerotate**: `OpenFile` 后做 inode 一致性校验（`os.SameFile`），防御 symlink 替换攻击（TOCTOU）
- **filerotate**: cleanup 严格匹配轮转备份命名（时间戳/序号/`.gz`），避免误删同目录同前缀文件
- **database**: 增强 DSN 凭据脱敏，覆盖 `sslpassword`/`pwd` 等 key=value 形式

### Changed

- **handler identity 架构重构**：防环改用递归深度上限（`maxUnwrapDepth`），内置 handler 用稳定 id 计数器去重，**全链路移除 `unsafe`**。第三方 handler 不再依赖运行时探测，靠 `Close` 幂等契约（标准 `io.Closer` 契约）
- **go.mod 自包含**：补全 `mbta-go` 依赖；`go.work` 加入 `.gitignore`，发布形态可脱离 workspace 独立构建
- 全链路性能优化，减少热路径内存分配与调度开销

### Fixed

- Go 最佳实践修复（errcheck / staticcheck 清零）
- CI workflow 适配根目录结构与 Go 版本要求

## [v0.4.0] - 2026-05-24

### ⚠️ BREAKING CHANGES

- **Module path 变更**: `github.com/iuboy/mebsuta/go` → `github.com/iuboy/mebsuta`。所有 import 路径需更新。
- **项目结构重组**: Go 代码从 `go/` 子目录提升到项目根目录。`config/` 子包已删除，Config 类型提升到主包。
- **FileConfig 拆分**: 轮转配置（Path、MaxSizeMB、MaxBackups 等）移至 `filerotate.Config`，`FileConfig` 仅保留 `Level` 和 `Format`。`UseFile` 签名变为 `UseFile(rotateCfg filerotate.Config, cfg FileConfig)`。
- **审计功能移至独立模块**: `LevelAudit`、`EventType`、`AuditEvent` 等移至 `mebsuta/audit` 子模块（独立 Go module）。root 包不再导出审计类型。
- **删除接口**: `LevelHandler` struct、自定义 `Handler` interface、`FullHandler`/`Flusher` 接口已移除。
- **Rust 独立**: 项目从双语言 monorepo 拆分为独立 Go 仓库（Rust 版本移至 mebsuta-rust）。

### Added

- `filerotate/` 子包：独立 io.Writer + io.Closer 轮转文件写入器，可脱离 mebsuta 单独使用
- `audit/` 独立 Go module：`LevelAudit`、`EventType`、`AuditEvent`/`AuditContext` 等合规审计功能，仅依赖标准库
- `scripts/release-mod.sh`：发布时移除 replace 指令并设置版本号
- `scripts/update-mod.sh`：批量更新子模块依赖
- API 契约优化：Config exported 字段 + `Validate()` 返回规范化副本
- `New()` 零配置默认 stdout JSON 输出，`Init()` 同步设置 `slog.SetDefault()`
- `UseFile`/`UseStdout`/`UseAsync`/`UseSampling`/`UseMetrics`/`UseContextExtractor` Option
- Handler 存储 `slog.Leveler`（支持 `*slog.LevelVar` 动态级别调整）
- `CloseAll` 使用 visited map 防止共享 handler 双重关闭
- `HandlerError` 结构化错误（Dropped/Retryable/Records/Time 字段）

### Changed

- `FileHandler` 重构为薄包装：轮转逻辑由 `filerotate.Writer` 处理，handler 仅负责 slog 集成和级别过滤
- `contractJSONHandler` 保留审计字段提升（event_type/actor/success），但 LevelAudit 引用改为内联常量
- `syslog` 和 `database` 子模块新增 `mebsuta/audit` 依赖

### Fixed

- 限制文件日志权限为 Unix `0600`，并补充权限测试
- 移除 Syslog handler 中未真正约束重连行为的跨进程文件锁依赖
- 修复 Async Error/Audit blocking send 使用重试循环替代单次超时，失败时返回 error
- 修复 Syslog connect/reconnect 先建新连接后关旧连接，避免 dial 失败时无连接可用
- 增强 Database flush 重试耗尽后的错误报告，明确记录丢失条数
- 加固表名验证添加 64 字符长度限制

## [0.3.3] - 2026-04-16

### 修复

- 修复 `errorHandler` 字段非原子读写导致数据竞争（全部改为 `atomic.Pointer[ErrorHandler]`）
- 修复 `SamplingHandler` WaitGroup 非指针共享导致 `Close()` 无法等待 goroutine 退出
- 修复 `FileHandler.Handle` 始终返回 `nil` 导致调用方无法感知写入失败
- 修复 `syslog_handler` 重连指数退避 `math.Pow` 无上限溢出风险（rc 上限 20）
- 修复 `database_handler` 批量写入 `batch[:0]` 保留底层数组阻止 GC 回收
- 修复 `metrics.Register()` 使用局部 `err` 变量导致首次注册错误被后续调用隐藏
- 修复 `DatabaseHandler.Handle()` 并发 `Close()` 时 send on closed channel panic（添加 recover）
- 修复 `DatabaseHandler.Close()` 可能丢失缓冲区日志条目（调整 close/wait/cancel 顺序）
- 修复 `DatabaseConfig.Validate()` 未约束 `MaxIdleConns <= MaxOpenConns`
- 修复 `SyslogConfig.Validate()` 未填充 `BufferSize` 默认值
- 修复 9 个测试 goroutine 泄漏（SamplingHandler/AsyncHandler 未调用 Close）
- 移除 `concurrentHandler` 测试辅助类型中未使用的 `mu sync.Mutex` 字段

### 改进

- `FileHandler.errorHandler` 移入 `fileState` 共享结构体，消除 `WithAttrs`/`WithGroup` 中的 atomic.Pointer 拷贝（go vet copylocks 警告）
- `math/rand` 升级为 `math/rand/v2`，使用 `rand.Int64N` 替代已弃用的 `rand.Int63n`
- `safeMulti.Handle` 添加 `r.Clone()` 性能注释，说明无 Attr 快速路径
- `SyslogHandler.fileLock.Unlock()` 错误通过 `errorHandler` 上报而非静默忽略
- `SyslogHandler`/`SamplingHandler` 补充 `var _ slog.Handler` 编译期断言
- 移除未使用的 `config.SyslogConfig.Structured` 字段
- 测试文件中 `SyslogHandler` 直接构造适配 `atomic.Pointer[ErrorHandler]` 模式

## [0.3.2] - 2026-04-16

### 修复

- 修复 `safeMultiHandler` 多 handler 并发分发时 `slog.Record` 数据竞争（添加 `r.Clone()`）
- 修复 `config.Validate()` 在验证失败时修改调用者 config 对象的副作用（DatabaseConfig 默认值填充移至验证通过后）
- 修复 RFC5424 SD-ELEMENT PARAM-VALUE 未转义 `"` `\` `]` 字符导致协议违反

### 改进

- 移除 `safeMultiHandler` 中冗余的 `slog.NewMultiHandler` 包装层，直接实现 Enabled/WithAttrs/WithGroup
- 导出 `ReportError` 函数，消除 database 子包中重复的 `reportError` 方法
- 移除 `DatabaseHandler.SetErrorHandler` 导出方法，消除竞态风险（通过 `mebsuta.New()` + `WithErrorHandler` 设置）
- 构造函数统一调用 `cfg.Validate()`，去重 FileHandler/SyslogHandler/DatabaseHandler 中的验证逻辑
- `config.SyslogConfig.Validate()` 空 Tag 填充默认值而非报错，`RetryDelay` 改用 `<= 0` 检查
- `config.DatabaseConfig.Validate()` 空 TableName 填充默认值 `"logs"`，零值检查统一为 `<= 0`

## [0.3.0] - 2026-04-16

### 新增

- `mebsuta.ErrorHandler` 类型 — Handler 内部错误处理函数，可自定义输出目标
- `mebsuta.WithErrorHandler(fn ErrorHandler) HandlerOption` — 注入自定义错误处理
- `mebsuta.DefaultErrorHandler` — 默认错误处理（写入 os.Stderr）
- `errorHandlerSetter` 内部接口 — 自动传播 ErrorHandler 到所有子 handler
- `database/` 子包隔离 — DatabaseHandler 独立子包，消除循环引用
- `database.SetErrorHandler(fn)` — 供用户手动设置 database handler 的错误处理

## [0.3.1] - 2026-04-16

### 修复

- 修复 `reportError` 未统一使用导致 `WithErrorHandler(nil)` 时 panic（5 处）
- 修复 `compressFile` 未 nil 检查 errorHandler 导致异步压缩 panic
- 修复 `syslog_handler.go` RFC5424 格式缺失 MSGID 字段
- 修复 `syslog_handler.go` 指数退避 retryCount 无上限导致 int64 溢出 panic
- 修复 `database_handler.go` flush 重试 context 共享导致重试机制失效
- 修复 `metrics/metrics.go` Register 使用 MustRegister 导致无法捕获重复注册
- 修复 `WithAttrs().WithGroup()` 链式调用时已累积属性被静默丢弃（Syslog/Async/Database）

### 改进

- `safeMultiHandler` panic recovery 在 nil errorHandler 时回退到 DefaultErrorHandler
- `propagateErrorHandler` 递归解包装饰器链，自动注入到所有支持的 handler
- `config/sanitizer.go` 移除死代码 `reflect` 依赖
- `config/types.go` 移除无用的 `validate:"..."` struct tags
- 测试文件 for 循环现代化为 Go 1.26 range 语法

## [0.2.0] - 2026-04-15

### 破坏性变更

- 全面从 `go.uber.org/zap` 迁移到 `log/slog` Handler 插件架构
- `mebsuta.New()` 返回 `*slog.Logger`，不再返回自定义 Logger 类型
- `mebsuta.Init(cfg)` / `mebsuta.InitWithDetails(cfg)` / `mebsuta.CreateLogger(cfg)` / `mebsuta.NewFromConfig(cfg)` 移除
- `mebsuta.GetLogger()` / `mebsuta.SetLogger()` / `mebsuta.IsInitialized()` 全局状态函数移除
- `logger.Zl()` / `logger.Sugar()` / `logger.Sync()` / `logger.With()` / `logger.WithContext()` 移除
- `mebsuta.SetContextExtractor(fn)` 移除，改为 `WithContextExtractor` 装饰器
- `mebsuta.OnError` / `mebsuta.OnInitError` / `mebsuta.Try` / `mebsuta.RetryWithBackoff` / `mebsuta.SetGlobalContext` 移除
- `core/` / `internal/adapter/` / `errors/` / `examples/` / `integration/` 包移除
- `config.LoggerConfig` / `config.InitConfig` / `config.Builder` 移除
- `mebsuta.EncodingType` 从 config 包移到根包，`config.FileConfig.Format` 改为 `string` 类型
- `config.SamplingConfig` / `config.SyslogConfig` / `config.DatabaseConfig` / `config.FileConfig` 保留在 `config` 包
- `mebsuta.AsyncConfig.DropOnFull` 字段移除（始终丢弃）

### 新增

- `mebsuta.New(opts ...HandlerOption) (*slog.Logger, error)` — 基于 functional options 创建 logger
- `mebsuta.WithHandler(h slog.Handler) HandlerOption` — 添加输出 handler
- `mebsuta.CloseAll(handler slog.Handler) error` — 递归关闭所有 io.Closer（支持装饰器链解包）
- `mebsuta.NewStdoutHandler(level slog.Level, format EncodingType) *StdoutHandler` — stdout 输出
- `mebsuta.NewFileHandler(cfg config.FileConfig, level slog.Level) (*FileHandler, error)` — 文件输出，内置轮转
- `mebsuta.NewSyslogHandler(cfg config.SyslogConfig, level slog.Level) (*SyslogHandler, error)` — syslog 输出
- `mebsuta.NewDatabaseHandler(cfg config.DatabaseConfig, level slog.Level) (*DatabaseHandler, error)` — 数据库批量写入
- `mebsuta.WithSampling(inner slog.Handler, cfg config.SamplingConfig) slog.Handler` — 时间窗口采样装饰器
- `mebsuta.WithAsync(inner slog.Handler, cfg AsyncConfig) slog.Handler` — 异步写入装饰器
- `mebsuta.WithMetrics(inner slog.Handler, m HandlerMetrics, name string) slog.Handler` — 指标收集装饰器
- `mebsuta.WithContextExtractor(inner slog.Handler, extract ContextExtractor) slog.Handler` — 上下文字段提取装饰器
- `mebsuta.HandlerMetrics` 接口 — 指标收集抽象
- `mebsuta.AsyncConfig` — 异步写入配置（BufferSize）
- `mebsuta.AsyncDropped(h slog.Handler) int64` — 查询异步丢弃数量
- `mebsuta.LogEntry` / `mebsuta.RecordToLogEntry(r slog.Record) LogEntry` — 通用日志条目
- 文件轮转：时间 + 大小双策略，gzip 压缩，原子 rename，崩溃恢复
- `safeMultiHandler` 包装 `slog.NewMultiHandler`，per-handler panic recovery
- `levelHandler` 嵌入提供通用 Enabled 级别过滤
- `config.DefaultSyslogNetwork` / `config.DefaultSyslogTag` 常量

### 改进

- `safeMultiHandler.WithAttrs` / `WithGroup` 正确传播到所有子 handler
- `safeMultiHandler.Close()` 递归关闭所有子 handler
- `CloseAll` 通过 `handlerUnwrapper` 接口递归解包装饰器链
- `*metrics.Metrics` 实现 `HandlerMetrics` 接口（ObserveHandle/IncError/IncDropped）
- FileHandler.doRotate 在 os.Create 失败后设置 closed 状态，避免静默日志丢失
- safeMultiHandler 单 handler 时串行调用，避免不必要的 goroutine 开销
- config 包作为配置类型的唯一位置，移除根包中的重复定义
- `errors.Join` 替代自定义 `joinErrors`
- 移除未使用的 contextKey 常量和 DropOnFull 死代码

### 移除

- `go.uber.org/zap` / `go.uber.org/zapcore` 依赖
- `github.com/natefinch/lumberjack` 依赖
- `core/` / `internal/adapter/` / `errors/` / `examples/` / `integration/` 包
- `config.LoggerConfig` / `config.InitConfig` / `config.Builder`
- `AsyncConfig.DropOnFull` 字段和 `DropOnFull()` 函数
- `contextKey` 类型和 RequestContextKey/UserContextKey/TraceIDContextKey/CustomIDContextKey 常量

## [0.1.0] - 2024-12-XX

### 新增

- 支持多种输出目标：控制台、文件、SQL 数据库、InfluxDB、Syslog
- 高性能异步批量写入
- 内置 Prometheus 指标监控
- 动态日志采样功能
- 结构化日志支持
- 上下文感知日志
- JSON 和 Console 两种编码格式
- 日志轮转和压缩
- 连接池管理
- 配置验证和默认值

### 文档

- 完整的中文 README
- API 文档和示例代码
- 版本规范说明

---

## 变更类型说明

- **新增**: 新功能
- **改进**: 现有功能的改进
- **修复**: Bug 修复
- **变更**: 重大变更或破坏性变更
- **弃用**: 即将移除的功能
- **移除**: 已移除的功能
- **安全**: 安全相关的修复或改进
