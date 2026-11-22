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

## [0.1.0-20] - 2026-11-22

### Changed — 项目整理第四轮：覆盖回归修复 + 文档/依赖一致性 + 零引用导出裁决

- **补 internal/handlerkit 单元测试**（13 个）：MergeAttrs/RecordWithGroupAttrs（前两轮收敛时自根包删除的专属测试在此重建——覆盖回归修复）、AttrsSub 不改调用方记录/WithGroup("") no-op、GroupSub 前缀语义、SafeLevel/IsNilLeveler 类型化 nil 边界、LevelGate 门限与热调、ErrorSlot 热换与零值 Report 不 panic、RateGate 冷启放行与并发单胜者。
- **文档一致性**：README `WithErrorHandler` 示例修正 `func(he mebsuta.HandlerError)` → `func(he *mebsuta.HandlerError)`（照抄原示例无法编译）；docs/BENCHMARKS.md 全表刷新至当前代码（环境标注 Go 1.24 → 1.27，SafeMulti 表附 0.1.0-17 顺序化注记，补 WithAttrs/AsyncHandler 行）。
- **go.mod 一致性**：`go mod tidy` 把 prometheus/client_model 自 indirect 转正（prombridge/bridge.go 直接引用，此前分类漂移）。
- **零引用导出扫描与裁决**（图 + 全仓文本引用计数，37 个候选）：删除 `metrics.Metrics.ObserveWriteLatency`（已被 HandlerMetrics 接口的 ObserveHandle 取代，全仓零调用）；`mbta.MaxMaxRetries` 更名 `MaxRetriesLimit`（叠词命名）。其余 35 个裁决保留：JSON 契约 tag 字段、OTel/Prometheus 接口实现（Aggregation/Describe 等）、mebsutatest 公共测试辅助、README 记录的默认值常量、鸭子类型接口 LevelVarSetter、对称门面（DebugContext 等）。

### 破坏性变更

- `metrics.Metrics.ObserveWriteLatency` 移除——与 `ObserveHandle`（mebsuta.HandlerMetrics 接口方法）观测同一直方图的旧形式，零调用残留。
- `mbta.MaxMaxRetries` 更名 `mbta.MaxRetriesLimit`。

## [0.1.0-19] - 2026-11-22

### Changed — 结构收敛第三轮（GitNexus 图驱动）：单消费者符号下沉

以代码知识图（跨包同名函数/方法查询 + 消费者分布映射）定位剩余重复：

- **`LogEntry`/`RecordToLogEntry` 下沉 syslog**：消费者映射显示二者自根包导出、再移入 handlerkit 的整个历史中始终只有 syslog 一个消费者——最终归属消费者包，成为未导出的 `logEntry`/`recordToLogEntry`；`internal/handlerkit/entry.go` 删除。handlerkit 回归"多包共享管线"的纯粹定位。
- **`truncateUTF8` 转发包装删除**（database、syslog 各一份）：调用点直调 `textutil.TruncateUTF8`，消除一层无语义的间接。
- **图侦查后裁决不收敛**（差异是本质的，记录备查）：telemetry `spanFanout`/`metricFanout` 与 database `SpanExporter`/`MetricExporter` 同名源于实现同一 OTel 接口（fanout 是方式 A+B 双写机制）；telemetry/config、mbta/config、database/config 三家的 `String`/`GoString`/`Sanitize` 脱敏策略有意不同（整体掩码 vs 子串脱敏，第五轮审计裁决）；syslog `flattenAttr` 携带 mbta 协议特有的 attrStats 契约，与 attrutil 的截断标记语义不同；mbta/syslog/database/async 四处发送队列同构但错误文案是运维契约（测试逐字断言）、附加计数与 ctx 语义各异，泛型化需 8+ 参数反而伤可读性。

### 破坏性变更

- 无公开 API 变化（LogEntry 此前已在 0.1.0-17 移出公共面；本轮进一步移出 handlerkit）。

## [0.1.0-18] - 2026-11-22

### Changed — 结构收敛第二轮：LevelGate 级别门限 + async 快照提取 + 死代码清除

- **`handlerkit.LevelGate`**：`SetLevel` 的"仅 \*slog.LevelVar 生效"判定（stdout/file/syslog/database/mbta 五份逐字拷贝）与 `Enabled` 的 SafeLevel 比较（四份）收敛为单一门限类型；四个 handler 的 `leveler slog.Leveler` 字段改为 `level handlerkit.LevelGate`，`SetLevel`/`Enabled` 各成一行委托。
- **async 快照提取**：`AsyncHandler.Handle` 与 `asyncGroupHandler.Handle` 重复的"取消剥离 + asyncRecord 构建 + 属性快照 + 入队"序列提取为共用 `enqueueSnapshot`；冗余的 `sendRecord` 快路径 closed 检查删除（入口早退 + 锁内权威检查已覆盖），closed 检查 4 → 3 处。
- **死代码清除**：子包未导出的 `setErrorHandler`（database）与 `setErrorhandler`（syslog）在生产代码零调用——是 `ErrorHandlerSetter` 导出接口出现前的遗留（根包从未能跨包触达它们）；删除并让测试改用 `SetErrorHandler`。根包 `isNilLeveler` 纯转发包装删除（直接用 `handlerkit.IsNilLeveler`）。

### 破坏性变更

- 无公开 API 变化（`LevelGate`/`enqueueSnapshot` 均为 internal/未导出；子包删除的是未导出方法）。

## [0.1.0-17] - 2026-11-22

### Changed — 结构收敛重构:统一 handler 图遍历 + internal/handlerkit 实现缝 + ErrorSlot/RateGate + slogtest 认证

- **统一 handler 图遍历**：closeAll / setLevelHandler / setFileMaxAgeHandler / findSelfBuffered / findDroppedCounter 五份重复遍历（三种风格：递归+去重×3、递归无去重、迭代式）收敛为单一 `walkHandlers`（unwrap 链 + safeMulti fanout + 稳定 id 去重 + maxUnwrapDepth 环保护）；CloseAll / SetLevel / SetFileMaxAge 各缩为一段 visit 闭包，新增运维面只需挂 visit；visited 由 `sync.Map` 改为普通 map（单 goroutine 一次性遍历）。跨包装饰器识别经导出的 `UnwrapHandler` 方法双检（未导出接口无法跨包满足）。
- **新增 `internal/handlerkit` 实现缝**（根包与 database/syslog/mbta 共享、非消费面）：`AttrsSub`/`GroupSub`、`LogEntry`/`RecordToLogEntry`、`SafeLevel`、`ReportError`/`LoadErrorHandler`、`MergeAttrs`/`RecordWithGroupAttrs` 自根包移入；`mebsuta.HandlerError`/`mebsuta.ErrorHandler` 改为该包类型的**别名**，公共契约与签名不变。
- **ErrorSlot / RateGate 收敛**：9 处 `atomic.Pointer[ErrorHandler]` + Load/Store + 双份 SetErrorHandler 样板（根包 5 类型 + database/syslog/mbta/exporters）收敛为 `handlerkit.ErrorSlot`（跨克隆共享槽位，`Report` 一体）；5 处"每秒至多一次"CAS 上报限流（AsyncHandler 双闸、syslog、database、mbta）收敛为 `handlerkit.RateGate`。
- **slogtest 一致性认证**：`testing/slogtest.Run` 全量用例认证 SamplingHandler / MetricsHandler / ContextExtractor / safeMulti 四个转发面（标准库 JSONHandler 作契约完美 Sink——装饰器若改记录/丢属性/group 处理错，Sink 输出即偏离期望）。contractJSONHandler（自有输出契约）、AttrsSub/GroupSub（group 扁平前缀语义）、AsyncHandler（异步可见性）不纳入的原因在 `slogtest_conformance_test.go` 顶部注明。
- **safeMulti 顺序分发**：移除 ≥4 handler 的 goroutine-per-record fanout——基准 10.8–28.6µs/op（3 倍波动）/65 allocs → **3.2µs/op（稳定）/52 allocs**；2-handler 路径亦因去掉中间 `enabled` 切片小赚（~2.0µs → ~1.8µs）。慢消费者解耦的正确位置是 `UseAsync`；errors.Join 顺序随之确定。
- 小项：`BoolPtr`/`IntPtr` → 泛型 `Ptr[T]`；defaultErrorHandler/LogErrorHandler 复用 `HandlerError.Error()`（`Fprintln`）消除格式串第二份拷贝；`promoteStringField`/`promoteBoolField` → 泛型 `promoteField[T]`；fallbackEntry 的 `msg[:1024]` 裸字节截断改用 `textutil.TruncateUTF8`（不再切开 UTF-8 rune）。

### 破坏性变更

- **公共 API 移除**（全部移入 `internal/handlerkit`，同模块子包随版本同步修正）：`AttrsSub`、`GroupSub`、`LogEntry`、`RecordToLogEntry`、`SafeLevel`、`ReportError`、`LoadErrorHandler`、`MergeAttrs`、`RecordWithGroupAttrs`。`HandlerError`/`ErrorHandler` 保留（别名，签名不变）。
- `BoolPtr`/`IntPtr` 移除，由泛型 `Ptr[T any](v T) *T` 取代。
- **findSelfBuffered 穿透 fanout**（缺陷面修正）：`WithAsync` 此前检测不到多输出（safeMulti）内部的自缓冲 handler（database/syslog/mbta），会静默构成双重缓冲；现在对这类链拒绝包裹（上报后原样返回 inner）。
- **findDroppedCounter 穿透 fanout**：`UseMetrics` 此前发现不了 fanout 内 AsyncHandler 的丢弃计数（缓冲满洪峰对 Prometheus 不可见）；现在按 handler 图接入首个计数器。
- **CloseAll 去重口径全局化**：同一 handler 实例出现在多个 safeMulti 分支时，此前各分支各关一次（依赖 Close 幂等）；现在整图恰好关闭一次。
- **safeMulti ≥4 handler 不再并行分发**：改为顺序调用（基准依据见上）；错误顺序由 handler 声明序决定（此前 goroutine fanout 顺序不定）。

## [0.1.0-16] - 2026-11-22

### Changed — 测试文件名收紧（规则入 STYLE.md 第 15 条）

- 审计轮次编号出文件名：`security_audit5_test.go` → `hardening_test.go`（database 与 telemetry 两处；轮次背景已在测试顶部注释）
- 来源项目名出文件名：`telemetry/wasat_gaps_test.go` **拆分**为 `tls_test.go`（TLS 凭据面）与 `bridge_test.go`（错误桥 + 批处理节流）——主题归位
- `telemetry/database_backend_test.go` → `backend_test.go`；`database/handler_lifecycle_test.go` → `lifecycle_test.go`
- 拼写统一 `regress`：`mbta/close_regression_test.go` → `close_regress_test.go`；`syslog/handler_audit4_test.go` → `handler_audit_test.go`（编号出文件名）
- 同主题合并：根包 `handler_regress2_test.go` 并入 `handler_regress_test.go`
- `database/numeric_normalization_test.go` → `normalization_test.go`
- **同题分裂合并（第二轮全量核对，59 → 54 个测试文件）**：`precision_test.go` 并入 `integrity_test.go`；根包 `level_audit_test.go` 并入 `level_test.go`、`level_walk_test.go` 并入 `facade_test.go`（三文件同题收敛为二）；`closeall_test.go` 并入 `handler_multi_test.go`；`mbta/handler_audit_test.go` 与 `syslog/handler_audit_test.go` 各自并入 `handler_test.go`
- **漏网冗余**：`syslog/integration_syslog_test.go` → `integration_test.go`（包名前缀，上轮截断核对之漏）；`metrics_regress_test.go` → `handler_metrics_test.go`（名不对题——它就是 handler_metrics 的测试文件）
- **第三轮：database 拆分过细收拢（12 → 7 个测试文件）**——`error_test.go`（839 行，名不副实的 handler 行为主测）+ `lifecycle_test.go` + `gorm_logger_test.go` 并入 `handler_test.go`（43 个测试，handler 行为/生命周期/错误/装配一面）；`normalization_test.go` 并入 `integrity_test.go`（Canonical 数字归一同题）；`integration_{helpers,jsonb,postgres,opengauss}_test.go` 四合一为 `integration_test.go`（同 build-tag 族）。终态 7 文件与生产面 1:1：`config / consistency / exporters / handler / hardening / integrity / integration`
- **第四轮：其余包同种问题收拢（47 → 40 个测试文件，全包 1:1 配对达成）**——telemetry：`hardening_test.go`（审计杂集）拆解（渲染脱敏 → `config_test`，并发/覆盖告警 → `bootstrap_test`）、`bridge_test.go` 并入 `bootstrap_test`（错误桥与批处理的生产面都在 bootstrap），终态 4 文件配对 6 个生产文件的主题面；mbta：`close_regress` + `record_regress` 并入 `handler_test`（终态 1 文件）；syslog：`sd_injection` 并入 `handler_test`；filerotate：`security_regress` 并入 `writer_test`；根包：`handler_regress_test.go` 杂集**分发归位**（json×1 → `handler_json_test`、async×5 → `handler_async_test`、WithErrorHandler → `option_test`、context×2 → `handler_context_test`）
- 粒度校准原则（STYLE.md 第 15 条精神）：**测试文件与生产文件 1:1**（每 handler/exporter 一个），跨切面小主题（装配、生命周期、错误路径）并入主测，build-tag 族合一，不再为单一测试立文件

纯重命名/拆分/合并，零生产代码改动；全仓测试零失败。

## [0.1.0-15] - 2026-11-22

### Changed — 文件名整理（去包名前缀，14 个文件）

子包文件名不再重复包名（目录已承载）——规则入 STYLE.md 第 15 条：

- `database/database_handler*.go` → `handler*.go`；`database_error_test.go` → `error_test.go`；`database_consistency_test.go` → `consistency_test.go`
- `telemetry/telemetry.go` → `bootstrap.go`（Start/Shutdown 核心 + 包 doc）
- `internal/attrutil/attrutil.go` → `flatten.go`；`internal/textutil/textutil.go` → `truncate.go`（单文件包按主题命名）
- `metrics/metrics.go` → `collector.go`；`audit/audit.go` → `api.go`

根包 `mebsuta.go`/`mebsuta_test.go` 为模块主文件惯例保留。纯重命名，
无任何代码改动；全仓测试零失败。

## [0.1.0-14] - 2026-11-22

### Added — 全局单例裁决落地 + 热重载第一批（S1-S3 + L0-L1）

- **L1 `mebsuta.SetLevel(logger, level)`**——walk-based 级别热调（与 SetFileMaxAge 同款 handler 图遍历：unwrap + safeMulti + 去重）：仅构造期传 `*slog.LevelVar` 的 handler 生效，固定值进入 `skipped` 类型名清单（诚实面，不静默假装成功）；配套 `mebsuta.NewLevelVar(level)` 便捷构造与导出接口 `LevelVarSetter`（ErrorHandlerSetter 同款跨包模式）。五个 handler 落地 SetLevel：stdout（级别在 cfg.Level）、file、syslog、database、mbta。
- **S1 `mebsutatest.ResetOTelGlobals()`**——消费方测试的 otel 全局复位舞步收编（noop provider ×3 + propagator；不依赖 telemetry 以免测试环）。
- **S2 telemetry 覆盖告警**——`SetGlobal` 安装时若上一个本包引导的 TracerProvider 未复位，经 ErrorHandler 链上报 `global-overwrite`（成因提示 + 新 endpoint）；`telemetry.ResetGlobalTracking()`（TEST-ONLY）配套。局限：仅跟踪本包安装（GLOBALS.md 记录）。
- **S3 `docs/GLOBALS.md`**——单例面地图：两处生态标准（slog default + otel 全局）为唯二单例、设施 var 清单、"不新增自有单例"原则与反面清单；STYLE.md 挂链。
- **L0 文档化**——README 新增「热重载」章节：级别/保留窗/ErrorHandler 可调面 + 不可调边界（采样率、批量参数）+ telemetry 代次轮换模式。
- 本仓测试的 resetGlobals 舞步换用公共工具（telemetry 内部测试 + facade 测试）。

### 破坏性变更

- 无公开 API 移除。

## [0.1.0-13] - 2026-11-22

### Changed — SamplingRate 扩展 NeverSample 语义（alhena 接入联动）

- **`Config.SamplingRate` 合法域扩为 `{-1} ∪ [0, 1]`**：`-1` 直通 `NeverSample`（接入方三态采样器的 never 档，alhena 迁移联动需求）；`(-1, 0)` 开区间无语义拒绝；`0` 仍为默认全采样。sampler 分派三态化。
- **修复 no-op 模式 signals 时序缺陷**（castor 迁移暴露）：`signals.Store` 移至 no-op 早退之后——禁用后端但显式设置 Signals 时 `Enabled()` 曾误报 true；附回归测试。

## [0.1.0-12] - 2026-11-22

### Changed — 风格统一批（十六维度全仓扫描后执行，不留中间态）

- **A1 `telemetry.Config.Validate` 对齐全仓值形态（破坏性）**——签名改为 `func (c Config) Validate() (Config, error)`，返回规范化副本且不修改调用方（与其余 7 处 Config 一致）；Start 与测试调用点同步。
- **A2 database 错误前缀统一**——子包名前缀规则落地：database 包生产代码 25 处 `"mebsuta:"` → `"database:"`（telemetry:/prombridge: 已合规）。
- **A3 telemetry 校验错误类型化（破坏性）**——required/范围/TLS 交叉规则错误统一 `*mebsuta.ConfigError{Field, Msg}`，消费方可 `errors.As` 字段级判断；错误信息中文化。
- **A4 并发安全声明**——`telemetry.Telemetry` 与 `prombridge.Bridge` doc 补并发安全面说明。
- **A5 测试断言全面 testify 化（不留中间态）**——全仓测试的 `t.Errorf/t.Fatalf/t.Fatal` 统一改 `require.XXX`（快败语义），表格结构保持。
- **A6 注释全面中文化（不留中间态）**——全仓生产与测试代码的英文注释/doc comment 统一翻译为中文（专有名词与标识符保留：no-op/fanout/ULID/OTLP/jsonb/fail-fast 等）；错误字符串与断言匹配文本不动。
- **B 档规则成文**——新增 `docs/STYLE.md`（十六维度规则手册），`docs/CONTRIBUTING.md` 挂链置顶。

### 破坏性变更清单

- `telemetry.Config.Validate` 签名（指针 error → 值形态返回副本）。
- telemetry 校验错误类型（fmt.Errorf → *mebsuta.ConfigError，文本中文化）。
- database 包错误文本前缀（`mebsuta:` → `database:`）。

## [0.1.0-11] - 2026-11-22

### Added — wasat 缺口④转正实施

- **telemetry 日志批处理两钮**——`Config.BatchLogQueueSize`（0 → SDK 缺省 2048）与 `Config.BatchLogInterval`（0 → SDK 缺省刷新间隔），经 `sdklog.WithMaxQueueSize`/`WithExportInterval` 透传；负值 `Validate` 拒绝（fail-fast，合法域在错误信息中）。测试：50ms 短节流下记录不经 Shutdown 即抵达 + 越界拒绝。（原 0.1.0-10 的"登记不做"条目就此转正。）

## [0.1.0-10] - 2026-11-22

### Added — wasat 接入缺口批（1 硬缺口 + 2 软缺口 + 1 登记）

- **① telemetry TLS 凭据面（硬缺口修复）**——`Config` 增 `TLSCAFile`/`TLSCertFile`/`TLSKeyFile`/`TLSServerName` 四件套（镜像 mbta 凭据面形态），三个 OTLP/HTTP exporter 统一经 `WithTLSClientConfig` 透传。私有 CA 的 https collector（wasat 单文件自签形态）可达；裸 `host:port` + TLS 字段升级为 TLS；显式 `http://` + TLS 字段 `Validate` 拒绝；cert/key 必须成对；MinVersion TLS 1.2。测试：自签 CA 链端到端（span 过私有 CA 通道）、mTLS 双向（服务端强制客户端证书：有证书通过 / 无证书被拒）、校验规则。
- **③ OTel SDK 导出错误接 ErrorHandler**——`Config.OTelErrorHandler`（nil → `mebsuta.DefaultErrorHandler`）；`SetGlobal`（默认开）时挂 `otel.SetErrorHandler` 桥，exporter 失败进 mebsuta 错误链而非 stderr；`SetGlobal=false` 不触碰 otel 全局（部署方自理，文档明示）。测试：不可达端点的导出失败经桥送达。
- **② `mebsuta/prombridge` 子包**——Prometheus Registry → OTel 指标桥：counter 按轮询差分、gauge last-write-wins，histogram/summary 跳过（API 无法忠实表达预聚合 bucket 计数，文档化），`Skipped()` 诚实健康面。存量 prometheus-only 服务（mbta-go、wasat-dns 等）零改造接入。grpc-free。测试：两轮差分累计、属性透传、跳过计数。
- **mebsutatest.OTLPReceiver.Handler()**——暴露捕获端点 handler，测试可挂自建 TLS/mTLS 服务端。

### 登记（不做，按裁定）

- **④ 日志批处理参数**：SDK `BatchLogRecordProcessor` 缺省（队列 2048/5s 刷新）对当前量级够用；query 通道极高峰场景再暴露 `BatchLogQueueSize`/`BatchLogInterval` 两钮。

## [0.1.0-9] - 2026-11-22

### Fixed — 第五轮安全专项审计修复批（1 P2 / 3 P3 / 3 P4）

- **P2-1 资源 DoS：relay 扫描器字节预算**——`scanOnce` 原一次载入 `RelayBatch`（500）行含 Fields jsonb，单行上限 `MaxRecordBytesCap` 8MiB → 理论单轮 4GB。改为**小分片（50 行）水合 + 累计 32MiB 字节预算**，预算触顶即止、剩余行保持 pending 由下一轮经 ULID 游标续传（截断可恢复、不丢不跳）。回归测试以缩小预算验证"两轮续传全覆盖"。
- **P3-1 并发：`telemetry.Telemetry.signals` 数据竞争**——`Shutdown` 写 / `Enabled` 读的普通字段改为 `atomic.Uint32`；新增并发 Hammer 测试（4 goroutine × Enabled × 100 次 + 双并发 Shutdown，`-race` ×3 全绿）。
- **P3-2 注入纵深：`AutoMigrateTables` 补表名校验**——与 `EnsureTables`/`NewSpanExporter` 对齐 `tableNameRe` 防线（gorm 标识符引用为外墙，此为内墙），消除兄弟函数校验不一致。
- **P3-3 泄漏：`telemetry.Config` 脱敏渲染**——补 `String`/`GoString`：Headers 保留键名、值一律 `***`（确定性排序保证日志稳定）；`Database.DSN` 整体遮蔽（部分脱敏会漏掉新型 DSN 拼写，整体遮蔽是诚实选择）。回归测试断言 token/密码不出现。
- **P4-1（G115）：直方图 Count uint64→int64 钳制**到 MaxInt64（物理不可达，防静默回绕）；受控转换加 `#nosec` 理由标注（连同 signals 位掩码收窄共 2 处，本仓 nosec 基线 0→2，均有守卫注释）。
- **P4-2（TEST-ONLY）：OTLPReceiver 体积上限**——原始与解压后读取均 `LimitReader` 64MiB 上限，超限 413（gzip 炸弹纵深）。
- **P4-3（advisory）：metric 门面文档纪律**——instrument 按名缓存无淘汰，明示"名字不得派生自请求数据"。

### 审计记录

- 基线：`govulncheck` 零漏洞；`gosec` 修复后清零（2 处受控 nosec）。
- 无 P1；retention.go（未提交工作）复核无发现；SQL 全参数化与 DSN 脱敏覆盖面复核通过。

## [0.1.0-8] - 2026-11-22

### Changed — 引入 internal/（实现缝收编）

- **`mebsuta/attrutil` → `mebsuta/internal/attrutil`（破坏性）**——Attribute 展平工具的使用面实测全部在本模块内（root/database/syslog），外部仓零使用；收编为 internal 后退出公开契约面（SPEC 契约面随之收缩），编译器级阻止消费者依赖 JSON 输出内部展平语义。
- **新增 `mebsuta/internal/textutil`**——UTF-8 截断辅助唯一归宿：`TruncateUTF8`（含 "..." 标记，database/syslog 原有两份逐字节相同的副本删除，改为薄委托）、`CutToRuneBoundary`（硬切无标记，attrutil 原内联版收编）、`RuneBoundary`（syslog JSON 截断器直用）。规范测试集中于 textutil（含全预算扫描的 UTF-8 有效性验证），syslog 内两份被取代的本地测试移除。

### 评估结论（记录）

- **`AttrsSub`/`GroupSub` 保留公开**（原计划收编，实施时撤销）：impact 分析揭示其为跨 3 子包（database/syslog/mbta）构造的组合件，且与根包未导出的 `handlerUnwrapper` unwrap 架构及 `RecordWithGroupAttrs`/`MergeAttrs`（async/multi 核心装饰器共用）共生——迁移需连带重构 unwrap 机制与助手归属，成本超出"隐藏实现缝"的收益。定位修订为**公开组合件（消费面）**：第三方 mebsuta 风格 handler 作者可复用其 WithAttrs/WithGroup 语义。

## [0.1.0-7] - 2026-11-22

### Changed

- **依赖修复：iuboy 世系防倒退守卫**——`go mod tidy` 曾把 `mbta-go`/`pollux-go` 误升回旧世系（v0.7.0/v0.5.2，模块代理缓存的已删除标签，见 0.1.0-1 条目）。已显式压回正确钉版（`mbta-go v0.1.0-0`、`pollux-go v0.1.2-3`）并新增 go.mod `replace` 守卫：tidy/-u 不再回退；replace 仅本仓生效，对消费方不可见。
- **syslog 降级为第二支持（维护模式）**——包文档、SPEC.md、README 三处一致声明：维持可用、维持测试、不再投入新特性。第一支持网络输出为 OTLP/数据库落库/MBTA；本地输出（stdout/file）层级不变。存量部署不受影响。

### 评估结论（记录）

- **mbta 三信号承载评估完成**：mbta-go `proto/signal.proto` 的 `SignalRecord` 已具备三信号字段面（logs：body/severity；traces：name/kind/parent/status/trace_state；metrics：metric_fields/unit/temporality/exp_histogram）。结论：协议就绪，mebsuta 侧的 mbta trace/metric exporter 为后续可选实现项（当前 traces/metrics 走 OTLP/数据库后端）。

## [0.1.0-6] - 2026-11-22

### Added

- **database：span/metric exporter（方式 B 三信号补全）**——`database.NewSpanExporter(db, table)` 实现 `sdktrace.SpanExporter`、`database.NewMetricExporter(db, table)` 实现 `sdkmetric.Exporter`；行结构 `SpanRow`/`MetricRow` OTel 对齐（身份三元组/时序/状态/jsonb 属性与事件；指标 gauge/sum/histogram，指标 Temporality 恒 Cumulative——SQL 游标消费需要每行自含）。参考 DDL：`SpansTableDDL`/`MetricsTableDDL`；建表辅助 `EnsureTables`（PG DDL）与 `AutoMigrateTables`（驱动无关）。测试依赖新增 `sdk/trace/tracetest`。
- **database.OpenGorm**——统一拨号路径（驱动选择/silent gorm 日志/错误脱敏/连接池），log handler 与 exporter 共用；NewHandler 改为经此拨号（行为不变）。
- **telemetry 数据库后端（方式 B 一键引导）**——`telemetry.Config.Database *DatabaseConfig`：Driver/DSN/表名（默认 mebsuta_traces/mebsuta_metrics）/EnsureSchema（默认 true，幂等建表）/连接池。与 Endpoint 并存即 traces/metrics 双写（OTLP + DB，fanout exporter），logs 仍走 OTLP；仅 Database 时 LoggerProvider 保持 no-op（日志的 DB 通道是 slog database handler 的职责）。Shutdown 顺序保证：providers 刷完最后一批行后才关闭自有连接。

### 破坏性变更

- 无公开 API 移除；`telemetry.Config` 新增可选字段（零值行为不变）。

## [0.1.0-5] - 2026-11-22

### Added

- **database 日志表 OTel 对齐 schema（破坏性）**——列集扩展为 `id`（ULID 身份/游标）、`observed_time`、`severity_number`（`mebsuta.SeverityNumber` 映射，LevelAudit→21）、`trace_id`/`span_id`（发射上下文关联，自动提取）、`service_name`（`Config.ServiceName`）、`relayed_at`（事务性双写投递标记）。参考 DDL 固化为 `database.LogsTableDDL`（含 `id` 唯一索引与 pending 部分索引），SPEC.md 立"OTel 对齐 schema 契约"为单一事实源。签名面不变（time/level/msg/fields）；新增列属路由/关联元数据，明确不在签名内。
- **事务一致双写（ConsistencyConfig，默认关）**——DB 为事实源的事务性 outbox：`Config.RelayTo`（OTel logs 管线）+ `Consistency{Enabled, SyncRelay(默认 true), RelayScanInterval(默认 30s，0=外置对账), RelayBatch(默认 500)}`。flush 提交后同步中继 + 后台扫描器对账（`scanStop` 生命周期与 Close 无死锁，关停前一次有界清扫）；中继时从存储的 hex 重建 span 上下文保持追踪关联；**非 2PC 边界在文档与代码注释中明示**；投递 at-least-once，消费方按 ULID `id` 幂等去重。
- `recordToDBEntry` 签名增加 ctx 参数（破坏性，仅包内与测试调用方）。

### 依赖

- `oklog/ulid/v2` v2.1.2 转直接依赖（记录身份生成，crypto/rand 单调熵）。

### 破坏性变更

- 日志表新增 8 列：既有表需 `ALTER TABLE ... ADD COLUMN`（参考 `LogsTableDDL`）；旧列名未改（time/level/msg/fields/record_hash/signature/sign_algo 原样）。
- `Handler.recordToDBEntry(ctx, r)` 签名变更（未导出，测试调用方已同步）。

## [0.1.0-4] - 2026-11-22

### Added

- **`mebsuta/otlp` 子包**——slog → OTel 日志管线桥接 handler：`otlp.NewHandler(lp, Config{LoggerName, MinLevel})`，经 `WithHandler` 与本地输出组合。日志-追踪关联原生（logs SDK 自发射上下文填充 TraceID/SpanID）；preset/group 语义按 slog 展平（dotted key）；uint64 超界降级十进制串、时间戳 RFC3339Nano、时长 int64 纳秒（OTel 语义约定）；nil provider 降级 no-op。**纯 API 桥，编译图 grpc-free**。
- **根包遥测门面**——`mebsuta.StartSpan(ctx, name, attrs...)`（返回完整 `trace.Span`）、`mebsuta.Counter/Histogram/Gauge`（按名缓存 instrument；错误静默——遥测不得打断请求路径）；经 otel 全局工作，未注册自动 no-op。
- **`mebsuta.TraceContextExtractor()`**——为本地输出（stdout/file/database/syslog）注入 `trace_id`/`span_id` 属性的现成 `ContextExtractor`；OTLP 路径无需提取器。

### 破坏性变更

- 无。

## [0.1.0-3] - 2026-11-22

### Added

- **`mebsuta/telemetry` 子包**——OTel 三信号（traces/metrics/logs）OTLP/HTTP 一键引导：`telemetry.Start(ctx, Config)` 装配资源标识（service.name/version、deployment.environment.name）、头采样（`SamplingRate`，0→1 全采样）、批处理、W3C tracecontext+baggage 传播与统一 `Shutdown`（默认 5s 超时刷盘）；`Endpoint` 留空为全 no-op 模式（不触碰 otel 全局）；`SetGlobal`（默认 true）注册 otel 全局以兼容 otelgin/otelhttp 类中间件。OTel 依赖钉版 v1.47.0（logs SDK 首个稳定版；CVE-2026-24051 修复线之上）。
- **`mebsuta.SeverityNumber(level)`**——slog 级别到 OTel SeverityNumber（1..24）的规范映射，从 `mbta` 内部 `severityNumber` 提取为唯一事实源（mbta handler 改为调用根包函数；行为不变，回归测试守护）。
- **`mebsutatest.OTLPReceiver`**——测试专用 OTLP/HTTP 捕获接收器：绑定 spec 默认 `/v1/{traces,metrics,logs}` 路径，解码并留存 protobuf 请求（`Spans()`/`MetricFamilies()`/`LogRecords()` 扁平化访问、`WaitFor*` 轮询等待、gzip 透明解压、`AttrValue` 属性断言辅助）；解码走 slim proto 模块保持 grpc-free。

### 依赖

- 新增 OTel 栈：`otel`/`otel/sdk`/`otel/sdk/trace`/`otel/sdk/metric`/`otel/sdk/log` v1.47.0、`otlp{trace,metric}http` v1.47.0、`otlploghttp` v0.23.0（logs exporter 尚未随 SDK 转 v1.x 世系）、`proto/slim/otlp` v1.11.1。
- **依赖边界（知情记录）**：官方 OTel SDK exporter 经完整版 `proto/otlp` collector 包传递链入 grpc（66+ 包，仅编译产物、运行时不激活）。 containment：根包与 `mebsutatest` 编译图保持 0 grpc（`go list -deps` 门禁）；仅显式 import `mebsuta/telemetry` 的二进制承担该体积。

### 破坏性变更

- 无公开 API 移除。`mbta.severityNumber`（未导出）删除，行为由 `mebsuta.SeverityNumber` 承接；mbta wire 格式与 SeverityNumber 取值不变。

## [0.1.0-2] - 2026-11-19

### Added

- **filerotate：`Writer.SetMaxAgeDays` / `Writer.MaxAgeDays`**——按龄清理窗运行时调整与读取（仅 MaxAgeDays 一项；Path / MaxSizeMB / MaxBackups / 压缩位仍为构造期参数——重建 Writer 涉及文件句柄迁移属重启域）。
- **`mebsuta.SetFileMaxAge(logger, days)`**——Logger 级保留窗热调：遍历 handler 图（unwrap 链 + safeMulti fanout，与 CloseAll 同一访问与去重口径）对每个 FileHandler 应用；stdout-only / nil logger 无害；负值拒绝。消费面：wasat 查询日志保留键热更（log.query_retention_days）。

## [0.1.0-1] - 2026-11-08

### 依赖

- 驱动/观测栈升级：`jackc/pgx/v5 v5.12.0`、`jackc/puddle v2.2.3`、`prometheus/common v0.73.1`、`prometheus/procfs v0.23.0`、`mattn/go-sqlite3 v1.14.53`（测试依赖）
- iuboy 世系显式钉版：`mbta-go v0.1.0-0`、`pollux-go v0.1.2-3`——模块代理仍缓存旧世系 `v0.7.0`/`v0.5.2` 的"更新"标签（已从仓库删除，代理永不过期），`go get -u` 会误升，须显式压回
- go 指令 1.26.10（GO-2026-6809 stdlib 基线，修复批已同步）

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
