# 贡献指南

感谢您对 Mebsuta 项目的关注！我们欢迎任何形式的贡献。

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
