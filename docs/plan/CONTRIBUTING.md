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

## 开发流程

### 仓库结构

```
mebsuta/
├── mebsuta.go              # New(), Init(), Option
├── handler.go              # CloseAll, handlerUnwrapper
├── config.go               # FileConfig, StdoutConfig, SyslogConfig, etc.
├── types.go                # EventType, LevelAudit, HandlerError
├── file_handler.go         # FileHandler
├── stdout_handler.go       # StdoutHandler
├── syslog_handler.go       # SyslogHandler
├── async_handler.go        # WithAsync
├── sampling_handler.go     # WithSampling
├── metrics_handler.go      # WithMetrics
├── context_extractor.go    # WithContextExtractor
├── database/               # DatabaseHandler (gorm 隔离)
├── metrics/                # Prometheus 指标
├── examples/               # 可运行示例
└── docs/                   # 文档
```

### 代码规范

- 遵循 [Effective Go](https://go.dev/doc/effective_go) 指南
- 遵循 [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- 使用 `gofmt` 格式化代码
   ```bash
   gofmt -s -w .
   ```

### 提交前检查

运行测试确保代码质量：
```bash
go test -race -count=1 ./...
go vet ./...
gofmt -s -l .
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

`govulncheck` 需要联网更新漏洞数据。

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

## 测试指南

### 单元测试

```bash
go test -v ./...
go test -cover ./...
```

### 集成测试

```bash
# 运行集成测试（需要Docker）
./test.sh integration

# 或直接使用go test
go test -tags=integration ./...
```

### 基准测试

```bash
# 运行基准测试
./test.sh benchmark

# 或直接使用go test
go test -bench=. -benchmem ./...
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

- 发布使用 `vX.Y.Z` 标签
- 发布前必须更新 `CHANGELOG.md`，并确认测试和漏洞扫描通过

## 获取帮助

如有任何问题，请：

- 提交 [Issue](https://github.com/iuboy/mebsuta/issues)
- 查看根目录 `README.md` 和 `SPEC.md`
- 加入 [讨论](https://github.com/iuboy/mebsuta/discussions)

---

再次感谢您的贡献！
