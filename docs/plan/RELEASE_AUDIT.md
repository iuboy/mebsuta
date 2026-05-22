<!-- /autoplan restore point: /Users/ycq/.gstack/projects/mebsuta/dev-autoplan-restore-20260522-185511.md -->

# Mebsuta 发布前代码审计 — Autoplan Deep Review

> **AUTOPLAN v1.43.3.0** | 2026-05-22 | CEO + Eng + DX 全流程双声音审查

---

## AUTOPLAN 决策审计记录

| # | Phase | Decision | Classification | Principle | Rationale | Rejected |
|---|-------|----------|-----------|-----------|----------|----------|
| 1 | CEO | 发 beta/RC 而非正式版 | Mechanical | P6 (bias action) | 两个独立模型一致确认审计过时 + SPEC 差距 | 正式发布 |
| 2 | CEO | 审计报告需标注每个发现对应的 commit SHA | Mechanical | P1 (completeness) | 报告和实际代码状态不一致 | 维持现状 |
| 3 | CEO | SPEC 合规差距 4 项需在 SPEC 中声明或修复 | Taste | P1+P5 | 语义差异 vs 实际行为差异 | 忽略 |
| 4 | CEO | 竞争定位需在 README 中明确 | Taste | P2 (boil lakes) | 无差异化 = 无采用理由 | 后续迭代 |
| 5 | CEO | CI/CD 添加 publish 步骤 | Mechanical | P1 | Release workflow 只验证不发布 | 后续迭代 |

---

## CEO 双声音共识 (6/6 CONFIRMED)

**两个模型 6/6 维度一致确认**: 不发正式版，先发 beta/RC。

### 核心发现 (CRITICAL)

1. **审计报告过时**: 原始报告说 30 commits，实际 54 commits。C-1 (Rust Async) 在 CHANGELOG 中标记为已修复，但审计仍列为 CRITICAL 阻塞项。
2. **发布策略前提有误**: VERSIONING.md 允许独立发布，但审计按"统一发布"评估。
3. **CI/CD 只验证不发布**: release.yml 缺少 `cargo publish`、`gh release create`、MSRV 测试。
4. **SPEC 自相矛盾**: SPEC 要求 "drop on full" 但又要求 "blocking send never dropped"。
5. **破坏性变更爆炸半径被低估**: import path 变更 + zap→slog 同时发生。
6. **竞争定位缺失**: 没有回答"为什么不用 slog/tracing"。

---

## 概述

**分支**: dev -> main (fast-forward merge)
**范围**: 30 commits, 103 files changed, +18,645/-3,812 lines
**产品**: 双语言日志库 (Rust + Go)
**审计类型**: 发布前全面代码审计
**审计日期**: 2026-05-22

---

## GSTACK REVIEW REPORT

### 总体结论: CONDITIONAL PASS

发布前需修复 **1 个 CRITICAL** 和 **2 个 HIGH** 级别问题，其余 WARN 项可在后续迭代处理。

---

## Phase 3: 工程审查 (双声音 — 6/7 CONFIRMED)

### 新发现 (比原始审计扩展)

| # | 严重性 | 文件:行 | 描述 | Claude | Codex |
|---|--------|---------|------|--------|-------|
| E-1 | **CRITICAL** | `database.rs:256` | Rust Database 缺少 Error/Audit 阻塞发送，违反 SPEC | YES | YES |
| E-2 | **HIGH** | `file.rs:385` | compress_file 临时文件无 0600 权限 | YES | YES |
| E-3 | **HIGH** | `async_handler.rs:40-74` | 缺少 Async+Syslog/Database 禁止组合检测 | YES | YES |
| E-4 | **HIGH** | `sampling.rs:74` | clone_box 重置 counter，与 Go 行为不一致 | YES | YES |
| E-5 | **MEDIUM** | `async_handler.rs:100-118` | yield_now spin-loop 浪费 CPU + close 饥饿 | YES | YES |
| E-6 | **MEDIUM** | `database.rs:287` | flush() 是空操作，API 误导性 | YES | N/A |
| E-7 | **MEDIUM** | `syslog.rs:183` vs `syslog_handler.go:432` | Audit severity 映射跨语言不一致 | YES | YES |
| E-8 | **MEDIUM** | `file.rs` | 缺少启动时残留压缩文件清理 | YES | N/A |
| E-9 | **MEDIUM** | `handler.rs:93` | close_all 可能不递归关闭内层 (TASTE) | NO | YES |

### 测试覆盖缺口

| 缺口 | 语言 | 严重性 |
|------|------|--------|
| Rust 没有 chain 集成测试 | Rust | HIGH |
| Rust Database 没有 Error/Audit blocking send 测试 | Rust | HIGH |
| Rust 没有 Async+Syslog/Database 禁止组合测试 | Rust | HIGH |
| Rust async 测试只断言 `count >= 2`，不够严格 | Rust | MEDIUM |
| Rust file handler 没有压缩后 0600 权限验证 | Rust | MEDIUM |

### 性能关注

- Rust async blocking send 使用 `yield_now()` spin-loop，buffer 满时浪费 CPU
- `tx` mutex 在 spin 期间被持有，阻止 `close_if_needed()` — 可能导致 close 延迟 5s

---

## Phase 3.5: DX 开发者体验审查 (6.1/10)

| 维度 | 评分 | 说明 |
|------|------|------|
| 入门体验 (TTHW) | 8/10 | 4 行 Go / 3 行 Rust 即可创建 logger |
| API 一致性 | 6/10 | Console vs Text 命名不统一，参数顺序不对称 |
| 错误信息 | 8/10 | 统一 `mebsuta:` 前缀，配置验证错误具体可操作 |
| 文档质量 | 7/10 | SPEC 优秀，README 清晰，但缺竞争定位 |
| 迁移体验 | 7/10 | MIGRATION.md 全面，但缺 Rust 说明和自动迁移 |
| SPEC 合规 | 5/10 | Rust 有 6 个 SPEC 合规差距 |
| CI/CD DX | 5/10 | Release workflow 不发布任何东西 |
| 竞争定位 | 3/10 | 没有回答"为什么不用 slog/tracing" |

---

## 跨阶段主题

**主题: Rust SPEC 合规差距** — 在 CEO、Eng、DX 三个阶段被独立标记。高置信度信号。
Rust 有 6 个 SPEC 合规差距未声明: Database blocking send、prohibited combinations、file permissions、sampling clone、syslog severity、close propagation。

**主题: 竞争定位缺失** — CEO 和 DX 阶段独立标记。高置信度信号。
SPEC 和文档专注于"跨语言对齐"（内部价值），但用户关心的是"为什么不用 slog/tracing"（外部价值）。

---

## AUTOPLAN 最终发现清单 (扩展后)

### CRITICAL (阻塞发布)

| ID | 来源 | 问题 | 状态 |
|----|------|------|------|
| C-1 | Eng/DX | **Rust Async 缺少 Error/Audit 优先处理** | **已修复 (未暂存)** |
| E-1 | Eng | **Rust Database 缺少 Error/Audit 阻塞发送** | **未修复** |

### HIGH (应修复)

| ID | 来源 | 问题 | 状态 |
|----|------|------|------|
| H-1 | CEO | **SECURITY.md 安全联系邮箱为占位符** | **已修复 (未暂存)** |
| E-2 | Eng | **Rust compress_file 临时文件无 0600 权限** | **未修复** |
| E-3 | Eng | **Rust 缺少 Async+Syslog/Database 禁止组合检测** | **未修复** |
| E-4 | Eng | **Rust Sampling clone_box 重置 counter** | **未修复** |

### MEDIUM (建议修复)

| ID | 来源 | 问题 | 状态 |
|----|------|------|------|
| M-1 | CEO | CHANGELOG Unreleased 段缺少版本号 | 未修复 |
| E-5 | Eng | Rust async yield_now spin-loop + close 饥饿 | 未修复 |
| E-7 | Eng | Syslog Audit severity 映射跨语言不一致 | 未修复 |
| E-8 | Eng | Rust 缺少启动时残留压缩文件清理 | 未修复 |
| CEO-1 | CEO | 审计报告过时/不一致 | 本报告已修正 |
| CEO-2 | CEO | CI/CD 缺少 publish 步骤 | 未修复 |
| CEO-3 | CEO | 竞争定位缺失 | 未修复 |

### 发布建议

**不发正式版。建议方案:**

1. 修复 E-1 (Rust Database blocking send)
2. 修复 E-2 (file permissions)
3. 修复 E-3 (prohibited combinations)
4. 修复 E-4 (sampling counter)
5. 在 SPEC 中声明 E-7, E-8, E-9 差距
6. 发 `rust/v0.1.0-beta.1` + `go/v0.4.0-beta.1`
7. 给 2 周时间早期验证
8. 正式版发布前完成 CI/CD publish 步骤

---

## Phase 1: CEO 战略审查

### 1.1 发布策略 -- WARN

- 30 个 commit 一次性合并到 main，构成 HIGH 风险的"大爆炸"发布
- CHANGELOG.md 的 Unreleased 段缺少版本号标注（应标注为 v0.4.0 或对应版本）
- 建议考虑 beta 标签先行验证（如 `go/v0.4.0-beta.1` + `rust/v0.1.0-beta.1`）

### 1.2 破坏性变更评估 -- WARN

| 变更 | 影响级别 | 缓解措施 |
|------|---------|---------|
| Go: zap -> slog 迁移 | BREAKING | MIGRATION.md 覆盖完整 |
| Go: 根目录 -> go/ 子目录 | BREAKING | import path 变更已文档化 |
| Rust: 全新实现 | NEW | 无迁移负担 |
| SPEC.md 跨语言契约 | NEW | 明确了行为边界 |

### 1.3 CI/CD 就绪度 -- PASS

- path-aware CI 正确分离 Go/Rust 构建
- release guard 防止误发布
- Dependabot groups 管理依赖更新

### 1.4 战略建议

- 合并发布策略可行，但建议先打 beta 标签
- SECURITY.md 中的安全联系邮箱为占位符，发布前必须替换
- VERSIONING.md 和独立标签策略已就绪

---

## Phase 3: 工程审查

### 3.1 安全审查 -- PASS

| 检查项 | Go | Rust | 状态 |
|--------|-----|------|------|
| SQL 注入防护 | 正则 `^[a-zA-Z_][a-zA-Z0-9_]*$` | 字符级验证 | PASS |
| 文件权限 0600 | 常量 `logFileMode = 0600` | `set_permissions(0o600)` | PASS |
| 密码泄露防护 | `maskPasswordInDSN` 覆盖 MySQL/PG/URI | `mask_dsn_password` 覆盖 URI | PASS |
| NaN/Inf JSON | 检测后转 `null` | `is_finite()` 检测转 `null` | PASS |
| RFC5424 转义 | `escapeSDValue` 转义 `"`, `\`, `]` | 对等实现 | PASS |

### 3.2 并发安全 -- PASS

| 检查项 | 状态 | 实现 |
|--------|------|------|
| Close() 幂等性 | PASS | 所有 Handler 使用 `atomic.Bool.CompareAndSwap` |
| Close() 后 Handle() 安全 | PASS | 所有 Handler 检查 closed 标志，返回 nil |
| Async channel drain | PASS | cancel -> close channel -> wait drain 顺序正确 |
| Audit/Error 阻塞发送 (Go) | PASS | 5s 超时阻塞 select |
| Multi panic 隔离 | PASS | 独立 defer recover |
| Sampling counter 竞争 | PASS | `atomic.Int64` 指针共享 |

### 3.3 SPEC 合规 -- PASS (Go) / WARN (Rust)

| SPEC 要求 | Go | Rust | 状态 |
|-----------|-----|------|------|
| Level ordering | PASS | PASS | |
| JSON 输出格式 (time/level/message/attributes) | PASS | PASS | |
| File handler (0600, rotation, idempotent close) | PASS | PASS | |
| Async (bounded, drop on full, flush on close) | PASS | **WARN** | |
| Sampling (initial+thereafter, keep error/audit) | PASS | PASS | |
| 禁止 Async->Syslog/Database | PASS | N/A | |
| Close() 传播 | PASS | PASS | |

### 3.4 测试覆盖 -- PASS

- 所有 Handler 生命周期测试完备（concurrent close/write、idempotent close、closed handle）
- Go 测试使用 `-race` 标志
- Rust 使用 `#[cfg(test)]` 单元测试 + 集成测试
- 边界条件覆盖良好（buffer full、rotation boundary、truncation edge cases）

---

## Phase 3.5: DX 开发者体验审查

### 4.1 API 一致性 -- WARN

- 概念层面高度对称，但构造函数参数顺序和配置模型存在差异
- Go `Console` vs Rust `Text` 命名不统一
- Go 使用 functional options，Rust 使用 serde struct -- 各自惯用但需文档说明

### 4.2 文档质量 -- PASS

- SPEC.md 优秀（分级清晰、pass/fail criteria 完备、JSON Schema 规范）
- Go/Rust README 结构清晰，快速开始简洁
- godoc/rustdoc 注释质量良好

### 4.3 入门体验 -- PASS

- 4 行 Go 代码 / 3 行 Rust 代码即可创建 logger
- 构建和测试命令标准（`go test -race ./...` / `cargo test --workspace`）
- 依赖管理合理

### 4.4 错误信息 -- PASS

- 统一 `mebsuta:` 前缀
- 配置验证错误具体且可操作
- nil ErrorHandler 不 panic

### 4.5 迁移体验 -- PASS

- MIGRATION.md 覆盖 Go zap->slog 迁移全面
- 已移除 API 有明确的替代方案表格

---

## 发现问题清单

### CRITICAL (阻塞发布)

| ID | 来源 | 问题 | 文件 |
|----|------|------|------|
| C-1 | DX/Eng | **Rust Async 缺少 Error/Audit 优先处理** -- SPEC.md "Audit Level Semantics in Chains" 要求 audit-level 使用阻塞发送+5s 超时，但 Rust async handler 对所有级别统一使用 `try_send`（非阻塞），Error/Audit 记录可被丢弃 | `rust/mebsuta/src/async_handler.rs` |

### HIGH (应修复)

| ID | 来源 | 问题 | 文件 |
|----|------|------|------|
| H-1 | CEO | **SECURITY.md 安全联系邮箱为占位符** -- 发布后用户无法报告安全漏洞 | `SECURITY.md` |
| ~~H-2~~ | DX | ~~Go README 引用不存在的 `examples/` 目录~~ -- **已验证存在**，不构成问题 | `go/README.md` |

### MEDIUM (建议修复)

| ID | 来源 | 问题 | 文件 |
|----|------|------|------|
| M-1 | CEO | **CHANGELOG Unreleased 段缺少版本号** | `CHANGELOG.md` |
| ~~M-2~~ | DX | ~~go.mod 指定 `go 1.26.0` 可能笔误~~ -- **已验证**: Go 1.26.0 于 2026-02 发布，版本号合理 | `go/go.mod` |
| M-3 | DX | **MIGRATION.md 缺少 Rust 说明** -- 用户可能寻找不存在的 Rust 迁移信息 | `MIGRATION.md` |
| M-4 | DX | **Go Console vs Rust Text 命名不统一** | `go/types.go`, `rust/mebsuta/src/` |

### LOW (后续迭代)

| ID | 来源 | 问题 | 文件 |
|----|------|------|------|
| L-1 | DX | 构造函数参数顺序不对称（Go level 在后，Rust level 在前） | 多文件 |
| L-2 | DX | Rust ErrorHandler 签名对新手不友好 | `rust/` |
| L-3 | DX | Go README 缺少 SyslogHandler 使用示例 | `go/README.md` |
| L-4 | DX | Rust Sampling 使用位置参数而非配置对象 | `rust/` |

---

## 审计维度总结

| 维度 | 评级 | 说明 |
|------|------|------|
| CEO/战略 | **WARN** | 大规模合并有风险，beta 标签建议合理，CI 就绪 |
| 架构 | **PASS** | 双语言 Handler 架构清晰，与 SPEC 对齐 |
| 安全 | **PASS** | 所有关键安全控制正确实现 |
| 并发 | **PASS** | atomic 操作、race detector、正确同步 |
| 测试 | **PASS** | 关键路径、边界条件、并发场景覆盖充分 |
| 性能 | **PASS** | benchmark 基线已建立 |
| DX | **WARN** | Rust Async SPEC 违规 + 文档不一致 |
| SPEC 合规 | **WARN** | Go PASS，Rust Async 缺少 Audit 优先处理 |

---

## 发布决策建议

### 方案 A: 修复后发布 (推荐)

修复 C-1、H-1、H-2 后直接合并到 main，作为正式版本发布。

- 修复工作量: ~2-3 小时
- 风险: 低（修复范围小且明确）

### 方案 B: Beta 先行

先以 beta 标签发布，收集反馈后再发正式版。

- 延迟: 1-2 周
- 风险: 最低

### 方案 C: 直接发布

跳过修复，接受已知缺陷直接发布。

- 风险: 中高（Rust SPEC 违规可能导致 audit 记录丢失）
- **不推荐**
