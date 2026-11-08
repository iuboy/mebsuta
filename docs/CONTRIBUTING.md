# 贡献指南

感谢您对 Mebsuta 项目的关注！我们欢迎任何形式的贡献。

## 版本与破坏性策略

自 2026-11-08 世系重置起，库版本自 `v0.1.0-0` 重新起算（旧世系 v0.1.0–v0.8.0
及 latest 标签已移除，CHANGELOG 保留历史条目）。详见
[VERSIONING.md](./VERSIONING.md)：

- 版本号恒为 `v0.1.<patch>-<rev>`，只有 patch 与 rev 递增。
- **默认进行破坏性变更，无兼容要求**：除非维护者明确要求保持兼容，API
  破坏性调整不做兼容别名、不做迁移期、不升 minor——调用方随版本更新
  同步修正。
- 发版流程：CHANGELOG 定版（patch 递增、rev 复位 0；同 patch 热修递增
  rev）→ 打 `v0.1.x-<rev>` 标签推送 → release.yml 出 Release。
- 目标版本号已被占用即视为重复：rev 向后延续至下一个未占用值，已发布版本
  号永不重用或覆盖。

## 开发环境设置

### 前置要求

- Go 版本以 `go.mod` 为准
- Docker (用于运行集成测试)
- Git

### 设置步骤

1. Fork 并克隆仓库
   ```bash
   git clone https://github.com/your-username/mebsuta.git
   cd mebsuta
   ```

2. 创建功能分支
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. 安装依赖
   ```bash
   go mod download
   ```

## 代码规范

- 遵循 [Effective Go](https://go.dev/doc/effective_go) 指南
- 遵循 [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- 使用 `gofmt` 格式化代码
   ```bash
   gofmt -s -w .
   ```

## 提交前检查

```bash
go test -race -count=1 ./...
go vet ./...
gofmt -s -l .
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

或使用脚本：

```bash
./scripts/test.sh unit    # 单元测试
./scripts/test.sh vet     # go vet
./scripts/test.sh fmt     # 格式检查
```

`govulncheck` 需要联网更新漏洞数据。

## 提交规范

使用 Conventional Commits 格式：

```
<type>(<scope>): <subject>
```

类型：`feat`、`fix`、`docs`、`style`、`refactor`、`perf`、`test`、`build`、`ci`、`chore`、`revert`

## Pull Request 流程

1. 确保代码通过所有测试
2. 更新相关文档（如需要）
3. 提交 Pull Request
4. 根据审查反馈修改

## 测试指南

### 单元测试

```bash
go test -v ./...
go test -cover ./...
```

### 集成测试

```bash
./scripts/test.sh integration
```

### 基准测试

```bash
./scripts/test.sh bench
```

## 代码审查要点

1. **正确性**: 逻辑正确，边界条件处理
2. **安全性**: SQL 注入、并发安全
3. **性能**: 避免不必要的内存分配
4. **可维护性**: 代码清晰、注释完整
5. **测试**: 充分的测试覆盖

## 发布流程

发布规则详见 [VERSIONING.md](VERSIONING.md)。

- 发布使用 `vX.Y.Z` 标签
- 发布前必须更新 `CHANGELOG.md`，并确认测试和漏洞扫描通过
