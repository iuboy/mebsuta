<!-- /autoplan restore point: /Users/ycq/.gstack/projects/go/dev-autoplan-restore-20260520-155018.md -->
# Plan: 继续打磨 Go 版本（调整后）

> 经 CEO 双声音审查，用户确认方向：聚焦 SPEC P0 + benchmark + 审计合规，跳过低杠杆工作。

## Goals

- SPEC P0 行为覆盖率 100%
- 建立性能基准线（benchmark）
- 强化审计合规功能（LevelAudit 是独特卖点）
- 统一代码质量（godoc、错误处理、命名）

## Non-Goals

- 不改变公共 API 的函数签名（向后兼容）
- 不添加新功能特性（仅在已有功能上打磨）
- 不涉及 Rust 实现的修改
- 不追求统一的行覆盖率数字（按 SPEC 优先级分层）

## NOT in scope（有意排除）

| 排除项 | 原因 |
| --- | --- |
| doRotate() 大规模拆分 | 两个模型都认为风险 > 收益，58 行线性逻辑可接受 |
| grapheme 级 UTF-8 截断 | Go 版本是字节级截断，改 grapheme 需引入新依赖，超出打磨范围 |
| 产品定位/差异化策略 | 超出「打磨」范围，留作独立任务 |
| database 模块拆分为独立 Go module | 评估后记录为 follow-up，不在此计划执行 |

## What already exists

| 子问题 | 已有代码 | 可复用度 |
| --- | --- | --- |
| AsyncHandler channel 发送 | `sendRecord()` 已提取（未提交） | 100% — 直接提交 |
| MetricsHandler/safeMulti 测试 | `mebsuta_test.go` 已写（未提交） | 100% — 直接提交 |
| Sanitizer 测试 | `config/sanitizer_test.go` 已写（未提交） | 100% — 直接提交 |
| Syslog 截断 + UTF-8 消毒 | `safeMessageForLog()`, `cleanHostname()` 已有 | 高 — 只需补 `escapeSDValue` 测试 |
| Benchmark 框架 | `benchmark_test.go` 已存在 | 高 — 需要扩展和记录基线 |
| 审计 Level | `LevelAudit` 已实现 | 需验证在所有 handler 链中正确传递 |

## Phase 1: 提交未提交的改动

### Tasks
1. 提交 `async_handler.go` DRY 重构（sendRecord 提取）
2. 提交 `mebsuta_test.go` 新增测试（MetricsHandler、safeMulti、RecordWithGroupAttrs）
3. 提交 `config/sanitizer_test.go`（新增 sanitizer 测试文件）
4. 验证所有测试通过

### Exit Criteria
- `go test -race -count=1 ./...` 全部通过
- 改动已提交

### 前置条件：无

## Phase 2: Database Handler SPEC P0 测试

### 背景
DatabaseHandler 覆盖率仅 3.1%，但 SPEC 对其有明确的 P0 要求。代码使用 GORM，需要先验证 mock 策略可行。

### Tasks
1. **Spike（30 分钟）**：验证 `gorm.io/driver/sqlite` 内存模式能否跑通 `NewDatabaseHandler → Handle → Close` 全路径。如果不行，尝试 `DATA-DOG/go-sqlmock` + GORM `DB()` 注入
2. 测试 SPEC P0 行为：table name 验证、并发 close/write 安全、幂等 Close、writes after close no panic
3. 测试 SPEC P1 行为：批量写入、flush on close
4. 测试错误路径：error handler 上报

### Exit Criteria
- SPEC Database Handler P0 行为覆盖率 100%
- spike 结果记录在案
- `go test -race ./database/` 通过

### 前置条件：GORM mock 策略 spike 通过

## Phase 3: Syslog Handler 补全

### 背景
`escapeSDValue()` 覆盖率 0%，`generateHostname()` 仅 41.2%。Go 版本的截断是字节级，不是 grapheme 级。在 SPEC 中记录此差异。

### Tasks
1. 为 `escapeSDValue()` 添加单元测试（RFC5424 特殊字符转义）
2. 为 `generateHostname()` 添加边界测试（空值、超长、特殊字符）
3. 补充 RFC5424 格式化集成测试（含 structured data）
4. 验证截断后输出是合法 UTF-8（不是 grapheme 级，SPEC 记录差异）

### Exit Criteria
- `escapeSDValue()` 覆盖率 100%
- `generateHostname()` 覆盖率 ≥ 80%
- SPEC.md Syslog 部分增加 Language-specific 说明：Go 使用字节级截断
- 所有 P0 syslog 测试在 TESTING.md 标记为 covered

### 前置条件：无

## Phase 4: 性能基准线建立

### 背景
日志库的核心竞争力是性能。没有 benchmark 基线，无法评估任何优化效果。`benchmark_test.go` 已存在但需要扩展。

### Tasks
1. 运行现有 `benchmark_test.go`，记录 ns/op 和 allocs/op 基线
2. 补充关键路径 benchmark：StdoutHandler JSON/Text、FileHandler 写入、AsyncHandler channel 吞吐、SamplingHandler 采样开销
3. 记录结果到 `BENCHMARKS.md`（新建，含硬件/Go 版本信息）
4. 识别明显的性能瓶颈（如有）

### Exit Criteria
- 关键 handler 路径有 benchmark 数据
- `BENCHMARKS.md` 包含可复现的基线数据
- 无明显性能问题（如 > 1μs/op alloc-free 的基本路径）

### 前置条件：Phase 1 完成

## Phase 5: 审计合规功能加固

### 背景
LevelAudit 是 Mebsuta 的独特卖点。需要确保它在所有 handler 链中正确工作：
- SamplingHandler 不应丢弃 Error/Audit 级别记录
- AsyncHandler 不应因 buffer full 而丢弃 Audit 记录
- MultiHandler 正确 fanout Audit 记录
- FileHandler/StdoutHandler 正确输出 audit 元数据

### Tasks
1. 验证 SamplingHandler 在采样时保留 Audit 级别（SPEC P0：Error and Audit records must not be dropped）
2. 为 AsyncHandler 添加 Audit 保护：`sendRecord` 中 Error/Audit 级别使用阻塞等待（带超时），非 Error/Audit 继续非阻塞丢弃
3. 审查 DatabaseHandler 同样需要 Audit 保护（同上策略）
4. 测试 MultiHandler 对 Audit 记录的 fanout 行为
5. 添加 AsyncHandler 并发 Close/Write 测试（`go test -race`）
6. 验证所有 handler 输出中 audit 元数据（event_type、actor、success）正确
7. 在 `types.go` 添加编译期断言：`LevelAudit >= slog.LevelError`

### Exit Criteria
- SPEC Sampling P0 确认：Audit 级别不被采样丢弃
- AsyncHandler/DatabaseHandler Error/Audit 级别不会被 buffer full 丢弃（阻塞等待或超时）
- `go test -race ./...` 无竞态
- TESTING.md 更新 audit 相关测试覆盖

### 前置条件：Phase 1 完成

## Phase 6: 代码质量统一

### 背景
各 handler 的错误处理模式和命名风格不统一。部分导出函数缺少 godoc。

### Tasks
1. 统一错误前缀格式：所有 `ReportError` 调用使用一致的 handler name 标识
2. 为所有导出函数/类型补充 godoc（英文，以函数名开头的一句话描述）
3. 清理 `stdout_handler.go` 中 `newStdoutHandlerWithWriter` 的可见性
4. 审查 `handler.go` 中 `prefixAttrs` 是否应为内部函数
5. 提取 `listBackups()` 辅助函数（doRotate 的小范围改进，不做大拆分）
6. **安全修复**：`maskPasswordInDSN` 对未知 DSN 格式改为返回 `"(redacted)"` 而非前缀
7. **安全修复**：`compressFile` 临时文件权限改为 0600（`os.OpenFile` 替代 `os.Create`）
8. **安全修复**：`SyslogConfig.Validate()` 添加 Tag 长度限制（≤48 字符）+ 非打印字符过滤
9. **文档化**：AsyncHandler godoc 说明不保留原始 context（使用 `context.Background()`）

### Exit Criteria
- `go vet ./...` 无警告
- 所有导出标识符有英文 godoc
- 错误消息格式统一
- `maskPasswordInDSN` 对未知格式不泄露任何原始内容
- 压缩文件权限 0600
- SyslogTag 验证生效

### 前置条件：Phase 2-5 完成

## Phase 7: 覆盖率扫尾 + TESTING.md 更新

### Tasks
1. 运行完整覆盖率报告，识别 SPEC P0 行为的覆盖缺口
2. 为 handler 链（Sampling → Async → File）添加集成测试
3. 更新 TESTING.md 所有 Go Coverage 列
4. Follow-up issue：评估是否将 `database/` 子包拆分为独立 Go module

### Exit Criteria
- SPEC P0 行为覆盖率 100%（Go 所有 handler）
- TESTING.md 更新完整
- 所有包测试通过 `go test -race -count=1 ./...`

### 前置条件：Phase 6 完成

## Dream State Delta

```
CURRENT STATE                  THIS PLAN                   12-MONTH IDEAL
─────────────────────────────────────────────────────────────────────────
覆盖率 62.9%          ──→     SPEC P0 覆盖 100%      ──→  Go/Rust 行为完全对齐
Database 3.1%          ──→     SPEC P0 测试完成       ──→  可选的独立 module
无 benchmark           ──→     关键路径基线数据        ──→  vs slog/zap/zerolog 对比
Audit 未加固           ──→     全链路审计保护          ──→  合规认证就绪
godoc 不完整           ──→     英文 godoc 全覆盖       ──→  pkg.go.dev 就绪
```

## Risk Register

| Risk | Impact | Mitigation |
| --- | --- | --- |
| GORM mock 策略不可行 | Phase 2 阻塞 | Phase 2 开头做 spike，不可行则降级为 sqlmock |
| AsyncHandler Audit 保护需要改逻辑 | drop-on-full 语义变化 | 如果需要改，保持向后兼容（新配置项） |
| 覆盖率扫尾发现深层问题 | 延迟 | SPEC P0 优先，P2 问题记录为 follow-up |

## Decision Audit Trail

| # | Phase | Decision | Classification | Principle | Rationale | Rejected |
|---|-------|----------|-----------|-----------|----------|----------|
| 1 | CEO | 前提确认：调整优先级 | User Decision | P1+P3 | 用户选择 SPEC P0 + benchmark + 审计合规方向 | 按原计划执行、重新定义方向 |
| 2 | CEO | 删除 doRotate 大拆分 | Auto-decided | P3+P5 | 两个模型都认为风险>收益，58行线性逻辑可接受 | 5 子方法拆分 |
| 3 | CEO | 修正 grapheme 测试为 UTF-8 合法性验证 | Auto-decided | P5+P1 | Go 版本字节级截断，测试 grapheme 会失败 | grapheme 级截断测试 |
| 4 | CEO | 新增 Benchmark Phase | Auto-decided | P1+P2 | 日志库核心竞争力是性能，无基线无法优化 | 无 benchmark |
| 5 | CEO | 新增审计合规加固 Phase | Auto-decided | P1+P2 | LevelAudit 是独特卖点，需确保全链路正确 | 仅做覆盖率 |
| 6 | CEO | Godoc 改为英文 | Auto-decided | P1+P6 | pkg.go.dev 国际用户，SPEC.md 已是英文 | 保持中文 |
| 7 | CEO | 保留 Database 测试但降级为 SPEC P0 聚焦 | Auto-decided | P3+P1 | 两个模型质疑 ROI，但 SPEC P0 仍需覆盖 | 跳过或全覆盖 |
| 8 | CEO | FileHandler 仅提取 listBackups | Auto-decided | P5+P3 | 小范围改进，不做大拆分 | 完整 doRotate 重构 |
| 9 | Eng | AsyncHandler/DB 缺 Audit 保护 | Auto-decided | P1+P2 | 两个模型一致标记为高，Phase 5 已覆盖 | 保持 drop-on-full |
| 10 | Eng | maskPasswordInDSN 可能泄露密码 | Auto-decided | P1+P5 | 未知 DSN 格式返回前缀可能暴露密码，改为返回 "(redacted)" | 保持当前行为 |
| 11 | Eng | compressFile 临时文件权限 | Auto-decided | P1+P5 | 日志文件要求 0600，压缩文件也应一致 | 使用 os.OpenFile 0600 |
| 12 | Eng | SyslogTag 无长度/内容验证 | Auto-decided | P1+P5 | 防止 syslog 协议注入，限制 Tag 长度 + 过滤非打印字符 | 不验证 |
| 13 | Eng | AsyncHandler 缺并发 Close 测试 | Auto-decided | P1+P2 | SPEC P0 要求 concurrent close/write 无 panic | 不测试 |
| 14 | Eng | Benchmark 补充 RunParallel | Auto-decided | P1+P2 | safeMulti goroutine-per-record 需要在真正并行下量化开销 | 仅单线程 |
| 15 | Eng | LevelAudit 添加编译期断言 | Auto-decided | P5+P1 | 防止 LevelAudit 值意外低于 Error | 不加断言 |

## Eng Review Findings

### Architecture (Section 1)
Handler 装饰器链设计合理：safeMulti → Sampling → Async → Metrics → 实际 handler。
泛型子处理程序 `AttrsSub[H]`/`GroupSub[H]` 消除了各 handler 的重复 WithAttrs/WithGroup 定义。
SamplingHandler 共享状态（count/ticker/wg）通过指针跨 WithAttrs/WithGroup 实例正确共享。
safeMulti 多 handler 路径使用 goroutine-per-record，高并发下需 benchmark 量化。

### Error & Rescue Registry (Section 2)
| 方法/路径 | 可能的失败 | 异常类 | 救援? | 用户看到 |
|---|---|---|---|---|
| AsyncHandler.sendRecord | buffer full | dropped count | Y | error handler 报告 |
| AsyncHandler.sendRecord | channel closed (panic) | panic | Y (recover) | error handler 报告 |
| DatabaseHandler.Handle | buffer full | dropped count | Y | error handler 报告 |
| DatabaseHandler.flush | batch insert fail | GORM error | Y (3x retry) | error handler 报告 |
| SamplingHandler.Handle | count overflow | incorrect sampling | N | 短暂不一致（SPEC 允许） |
| SyslogHandler.writeWithRetry | network fail | reconnect loop | Y (backoff) | 自动重连 |

**关键 GAP**：AsyncHandler 和 DatabaseHandler 对 Audit 级别无保护 — buffer full 时 Audit 记录会被丢弃。

### Security (Section 3)
| 威胁 | 可能性 | 影响 | 计划是否缓解 |
|---|---|---|---|
| maskPasswordInDSN 未知格式泄露 | 中 | 中 | Phase 6 修复 |
| SyslogTag 注入 | 低 | 中 | Phase 6 添加验证 |
| compressFile 权限过宽 | 低 | 低 | Phase 6 修复 |
| DatabaseHandler table name SQL 注入 | 低 | 高 | 已有正则验证 |

### Failure Modes Registry (Section 4)
| 失败模式 | 严重性 | 处理 | 测试覆盖 |
|---|---|---|---|
| AsyncHandler buffer full 丢弃 Audit | 高 | Phase 5 添加 Audit 保护 | 待补 |
| DatabaseHandler batch retry 耗尽 | 中 | 3 次重试 + error handler | 待补 |
| SamplingHandler 窗口边界不一致 | 低 | atomic 操作，SPEC 允许 | 已覆盖 |
| SyslogHandler 网络断连 | 中 | 自动重连 + backoff | 待补 |

### Test Diagram (Section 5)
```
Handler 链测试覆盖:
  Sampling → inner          ✅ TestWithSampling_*
  Async → inner              ✅ TestAsyncHandler_*
  Multi → [h1, h2]          ✅ TestSafeMultiHandler_*
  Sampling → Async → File   ❌ 无集成测试（Phase 7）
  Async 并发 Close/Write    ❌ 无测试（Phase 2/5）
  Database full lifecycle   ❌ 3.1% 覆盖（Phase 2）
  Syslog reconnect          ❌ 无测试（Phase 3 补充）
```
