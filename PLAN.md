<!-- /autoplan restore point: /Users/ycq/.gstack/projects/mebsuta/dev-autoplan-restore-20260520-200031.md -->
# Plan: Go 采用就绪打磨 — 第二轮

> 上一轮（commit 82d81c0）已完成：SPEC P0 覆盖 100%、benchmark 基线、审计保护、安全修复。
> 本轮聚焦：**采用就绪** — examples、godoc、集成测试、SPEC 对齐。覆盖率作为副产品报告，不作为阶段门控。

## Goals

- 新用户可从克隆到运行示例 < 5 分钟
- 所有导出标识符有英文 godoc
- 4+ 条核心 handler 链有集成测试
- SPEC.md 含 handler 链组合规范
- Go/Rust SPEC P0/P1 行为完全对齐（差异 = 修代码）
- TESTING.md 含当前覆盖率数值

## Non-Goals

- 不改变公共 API 签名（向后兼容）
- 不添加新功能特性
- 不涉及 Rust 代码修改
- 覆盖率不作为阶段门控（完成后报告数值即可）

## NOT in scope（有意排除）

| 排除项 | 原因 |
| --- | --- |
| Syslog TLS 传输测试 | 需要 TLS 证书基础设施，超出打磨范围 |
| Database 独立 Go module 拆分 | 上轮评估为 follow-up，仍不在执行范围 |
| grapheme 级 UTF-8 截断 | Go 版本字节级截断，不改 |
| SafeMulti goroutine-per-record 重构 | 高风险架构变更，需独立设计 |
| Prometheus metrics 测试修复 | 已有问题是全局注册器状态泄漏，需要上游重构 |
| AsyncHandler sendMu 保护 | Eng 评估为 LOW/MED，记录为 follow-up |
| NewStdoutHandler 签名统一 | 破坏性 API 变更，超出本轮范围 |

## Phase 0: Go 示例程序 + README 修复

### 背景
Rust 有 5 个可运行示例（`rust/mebsuta/examples/`），Go 零个。这是采用就绪的最大障碍。同时 `go/README.md:31` 的 `NewFileHandler(cfg)` 签名错误，新用户复制粘贴会编译失败。

### Tasks
1. 创建 `go/examples/` 目录结构
2. `basic/main.go` — 最简 stdout JSON 输出
3. `file/main.go` — 文件输出 + 轮转配置
4. `sampling/main.go` — 采样装饰器用法
5. `async/main.go` — 异步写入用法
6. `chain/main.go` — 完整生产配置链（Sampling → Async → Multi([File, Stdout])）
7. 修复 `go/README.md` 所有代码签名（`NewFileHandler(cfg)` → `NewFileHandler(cfg, slog.LevelInfo)` 等）
8. README 添加 examples 链接

### Exit Criteria
- 5 个示例 `go run ./examples/<name>` 全部通过
- README 代码可复制粘贴编译
- `go vet ./examples/...` 无警告

### 前置条件：无

## Phase 1: 英文 Godoc 全覆盖

### 背景
Eng+DX 审查确认 40+ 导出符号缺 godoc 或仅有中文注释。pkg.go.dev 需要 English godoc。PLAN.md 原仅列 6 个函数，实际范围远大。

### Tasks
1. 所有导出函数补充英文 godoc（一句话，以函数名开头）
2. 构造函数优先：`New`, `NewFileHandler`, `NewSyslogHandler`, `NewStdoutHandler`, `NewDatabaseHandler`
3. 装饰器次优先：`WithAsync`, `WithSampling`, `WithMetrics`, `WithContextExtractor`
4. 便捷函数：`Debug`, `Info`, `Warn`, `Error`, `Audit`, `*Context` 变体
5. 类型：`LevelHandler`, `HandlerOption`, `AsyncConfig`, `ErrorHandler`, `LogEntry`, `ContextExtractor`
6. 辅助函数：`RecordToLogEntry`, `AsyncDropped`, `CloseAll`, `MergeAttrs`, `ReportError`
7. 验证 `go doc` 输出可读性

### Exit Criteria
- `go vet ./...` 无警告
- 所有导出标识符有英文 godoc
- `go doc mebsuta.NewFileHandler` 等关键函数输出有意义

### 前置条件：无（可与 Phase 0 并行）

## Phase 2: SPEC Handler 链组合规范

### 背景
SPEC.md 描述了每个独立 handler 的行为，但没有定义装饰器链的组合语义。DX 审查确认这是 WARN 级缺失。

### Tasks
1. 在 SPEC.md 添加 "Handler Chain Composition" 章节
2. 定义推荐链顺序：`safeMulti → Metrics → Sampling → Async → 实际 Handler`
3. 记录禁止组合：`Async → Syslog`、`Async → Database`（已有注释警告）
4. 定义链中 Audit 级别语义（不丢弃、不采样）
5. 记录 `Close()` 传播规则（装饰器从外向内 Close）

### Exit Criteria
- SPEC.md 含完整链组合规范
- 推荐/禁止组合有明确列表
- Audit 级别行为有 pass/fail criteria

### 前置条件：无（可与 Phase 0/1 并行）

## Phase 3: Handler 链集成测试

### 背景
上一轮 PLAN 标记了此任务但未执行。Eng 审查建议扩展：覆盖不同顺序、加入 DatabaseHandler、使用 fake HandlerMetrics。

### Tasks
1. Sampling → Async → Stdout 链：验证采样 + 异步写入
2. Sampling → Async → File 链：验证文件写入 + 采样旁路
3. Metrics → Sampling → Async 链：验证 metrics 正确记录（使用 fake HandlerMetrics）
4. Multi([Stdout, File]) 链：验证 fanout
5. Async → Sampling 链（反向顺序）：验证行为差异
6. Database 加入链测试：Metrics → Async → Database
7. Error/Audit 级别穿透所有链的验证
8. CloseAll 在完整链上的正确传播

### Exit Criteria
- 6+ 条 handler 链有集成测试
- Audit 级别在所有链中不被丢弃
- `go test -race ./...` 通过

### 前置条件：Phase 0 完成

## Phase 4: Syslog Mock Server + 网络路径测试

### 背景
Syslog handler 的 `Handle`、`Close`、`write`、`reconnect`、`processQueue`、`safeSend` 全部 0% 覆盖。

### Tasks
1. 创建 `syslog_mock_test.go`，TCP mock server（`net.Listen("tcp", ...)`）
2. 测试 `Handle()` → 完整写入路径
3. 测试 `Close()` → 优雅关闭（验证排空逻辑）
4. 测试 `formatJSONMessage()` 和 `formatStructuredMessage()`
5. 测试 `reconnect()` → 断连后重连
6. 测试 `backoffDelay()` → 注入 rand 源避免 jitter 陷阱

### Exit Criteria
- Handle/Close 覆盖率 ≥ 70%
- `go test -race ./...` 通过

### 前置条件：Phase 3 完成

## Phase 5: Database 错误路径测试

### 背景
DatabaseHandler.Handle 仅 31%，NewDatabaseHandler 仅 7.7%。

### Tasks
1. batch retry 耗尽场景（3 次重试后 error handler 上报）
2. error handler 回调被正确调用
3. `WithAttrs`/`WithGroup` 返回正确类型
4. `recordToDBEntry` 字段映射完整性

### Exit Criteria
- Database 包覆盖率 ≥ 60%
- `go test -race ./database/` 通过

### 前置条件：无（可与 Phase 4 并行）

## Phase 6: Go/Rust SPEC 对齐验证

### 背景
Eng 审查确认：P0/P1 差异应默认修复代码，而非仅记录。

### Tasks
1. 逐条对比 SPEC.md 每个 P0/P1 要求
2. 优先级计算（facility * 8 + severity）一致性验证
3. 截断行为差异确认已在 SPEC 记录
4. LevelAudit 行为一致性验证
5. **发现的 P0/P1 差异直接修代码**，P2 差异记录到 SPEC.md

### Exit Criteria
- SPEC.md 所有 P0/P1 项 Go+Rust 双通过
- P0/P1 差异已修复（不是仅记录）
- `go test -race ./...` 通过

### 前置条件：Phase 3-5 完成

## Phase 7: TESTING.md 更新 + 最终覆盖率报告

### 背景
TESTING.md 缺少覆盖率数值。所有测试完成后更新。

### Tasks
1. 运行 `go test -coverprofile=coverage.out ./...`
2. 在 TESTING.md 添加覆盖率数值表格（package / coverage / date）
3. 验证 TESTING.md 与实际测试一致

### Exit Criteria
- TESTING.md 含覆盖率数值
- 数据与 `go test -cover` 一致

### 前置条件：Phase 0-6 全部完成

## Dream State Delta

```
CURRENT STATE                  THIS PLAN                   12-MONTH IDEAL
─────────────────────────────────────────────────────────────────────────
0 个 Go 示例           ──→     5 个可运行示例           ──→  pkg.go.dev 就绪
README 签名错误        ──→     代码可复制粘贴编译       ──→  新用户 5 分钟上手
40+ 符号缺 godoc       ──→     英文 godoc 全覆盖       ──→  pkg.go.dev 就绪
无链组合规范           ──→     SPEC 链组合章节          ──→  双语言互操作性
无链集成测试           ──→     6+ 条链集成测试          ──→  生产配置验证
```

## Risk Register

| Risk | Impact | Mitigation |
| --- | --- | --- |
| SPEC P0/P1 差异需大量修复 | Phase 6 延迟 | 先验证再评估，大改动可拆 follow-up |
| Examples 数量不足 | DX 改善有限 | 与 Rust 5 个对齐，覆盖核心场景 |
| backoffDelay jitter 测试不稳定 | Syslog 测试 flaky | 注入固定 rand 源 |

## Eng Review Consensus

| # | Finding | Claude | Codex | Consensus | Action |
|---|---------|--------|-------|-----------|--------|
| E1 | Go 无可运行示例程序（Rust 有 5 个） | HIGH | HIGH | **必须添加** | Phase 0 |
| E2 | 计划仍读起来像覆盖率项目 | HIGH | HIGH | **重写计划** | 已重写 |
| E3 | Godoc 范围低估（40+ 符号，非 6 个） | MED | MED | **扩大范围** | Phase 1 |
| E4 | SPEC 对齐应默认修复代码 | MED | HIGH | **修复优先** | Phase 6 |
| E5 | SyslogHandler.Close() 排空竞争 | MED | MED | **验证** | Phase 4 |
| E6 | AsyncHandler 缺 sendMu | LOW | MED | **follow-up** | 不在本轮 |
| E7 | Metrics 链测试需 fake HandlerMetrics | MED | MED | **使用 fake** | Phase 3 |
| E8 | backoffDelay() jitter 测试陷阱 | LOW | LOW | **注入 rand** | Phase 4 |
| E9 | 链测试应覆盖不同顺序 | MED | MED | **采纳** | Phase 3 |
| E10 | DatabaseHandler 应加入链测试 | MED | MED | **采纳** | Phase 3 |

## DX Review Consensus

| # | Finding | Claude | Codex | Consensus | Action |
|---|---------|--------|-------|-----------|--------|
| D1 | Go 无示例程序 | FAIL | — | **FAIL** | Phase 0 |
| D2 | README NewFileHandler 签名错误 | FAIL | FAIL | **FAIL** | Phase 0 |
| D3 | 7 构造函数+8 便捷函数缺 godoc | WARN | PASS* | **WARN** | Phase 1 |
| D4 | TESTING.md 缺覆盖率数值 | WARN | — | **WARN** | Phase 7 |
| D5 | SPEC 缺链组合规范 | WARN | — | **WARN** | Phase 2 |

*Codex scope limited to README/types.go; did not review full godoc surface.

## Decision Audit Trail

| # | Phase | Decision | Classification | Principle | Rationale | Rejected |
|---|-------|----------|-----------|-----------|----------|----------|
| 1 | CEO | 前提确认：调整为采用就绪方向 | User Decision | P1+P6 | 覆盖率不是正确北极星，godoc/examples/集成测试优先 | 保持覆盖率优先 |
| 2 | Eng | 重写计划为采用就绪优先 | Consensus | P1+P6 | E1-E2: 两个模型一致认为 examples/godoc 优先于覆盖率 | 保持覆盖率阶段门控 |
| 3 | DX | README 签名错误为 BLOCKER | Consensus | P5 | 两个模型一致确认 NewFileHandler(cfg) 无法编译 | 仅更新文档 |
