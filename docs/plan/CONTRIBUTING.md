# 贡献指南

感谢您对 Mebsuta 项目的关注！我们欢迎任何形式的贡献。

## 开发环境设置

### 前置要求

- Go 版本以 `go/go.mod` 为准
- Rust stable toolchain
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
   cd go && go mod download
   cd ../rust && cargo fetch
   ```

## 开发流程

### 仓库结构

本仓库是双语言 monorepo：

- `go/`: Go module
- `rust/`: Rust workspace
- 根目录: 共享规范、版本策略、贡献指南、安全策略和 CI

跨语言行为以 `SPEC.md` 为准。新增或修改 Go/Rust 共享行为时，必须同步更新 `SPEC.md` 和 `TESTING.md`。

### 代码规范

- 遵循 [Effective Go](https://go.dev/doc/effective_go) 指南
- 遵循 [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- 使用 `gofmt` 格式化代码
   ```bash
   cd go
   gofmt -s -w .
   ```
- Rust 代码使用 `rustfmt` 和 `clippy`
   ```bash
   cd rust
   cargo fmt --all
   cargo clippy --workspace -- -D warnings
   ```

### 提交前检查

运行测试确保代码质量：
```bash
# Go
cd go
go test -race -count=1 ./...
go vet ./...
gofmt -s -l .

# Rust
cd ../rust
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
```

依赖漏洞扫描：

```bash
cd go
go run golang.org/x/vuln/cmd/govulncheck@latest ./...

cd ../rust
cargo audit
```

`cargo audit` 和 `govulncheck` 需要联网更新漏洞数据。

### 提交规范

使用清晰的提交信息格式：

```
<type>(<scope>): <subject>

<body>
```

类型：
- `feat`: 新功能
- `fix`: Bug修复
- `docs`: 文档更新
- `refactor`: 代码重构
- `test`: 测试相关
- `chore`: 构建/工具链相关

示例：
```
feat(logger): 添加动态采样支持

实现了基于时间窗口的日志采样功能，避免日志爆炸。
- 初始100条全部记录
- 之后每10条记录1条
- 时间窗口60秒
```

### Pull Request 流程

1. 确保您的代码通过所有测试
2. 更新相关文档（如需要）
3. 提交 Pull Request
4. 等待代码审查
5. 根据反馈进行修改
6. 合并后可删除功能分支

如果 PR 改变 Go/Rust 共享行为：

1. 更新 `SPEC.md`
2. 更新 `TESTING.md`
3. 为受影响语言补测试
4. 在 `CHANGELOG.md` 的 Go、Rust 或 Repository 区域记录变更

## 测试指南

### 单元测试

```bash
cd go
go test -v ./...

go test -v ./config/...

go test -cover ./...

cd ../rust
cargo test --workspace
```

### 集成测试

```bash
# 运行集成测试（需要Docker）
cd go
./test.sh integration

# 或直接使用go test
go test -tags=integration ./...
```

### 基准测试

```bash
# 运行基准测试
cd go
./test.sh benchmark

# 或直接使用go test
go test -bench=. -benchmem ./...

cd ../rust
cargo bench --workspace
```

## 代码审查要点

我们在审查代码时会关注：

1. **正确性**: 逻辑正确，边界条件处理
2. **安全性**: SQL注入、命令注入、并发安全
3. **性能**: 避免不必要的内存分配、阻塞操作
4. **可维护性**: 代码清晰、注释完整
5. **测试**: 有足够的测试覆盖

## 文档贡献

我们欢迎以下类型的文档改进：

- 修正错误和拼写
- 添加使用示例
- 补充架构设计说明
- 更新API文档

## 发布流程

发布规则详见 `VERSIONING.md`。

- Go 发布使用 `go/vX.Y.Z` 标签
- Rust 发布使用 `rust/vX.Y.Z` 标签
- 整仓发布保留 `vX.Y.Z` 标签

发布前必须更新 `CHANGELOG.md`，并确认对应语言的测试和漏洞扫描通过。

## 获取帮助

如有任何问题，请：

- 提交 [Issue](https://github.com/iuboy/mebsuta/issues)
- 查看根目录 `README.md`、`SPEC.md`、`TESTING.md` 和语言目录 README
- 加入 [讨论](https://github.com/iuboy/mebsuta/discussions)

---

再次感谢您的贡献！
