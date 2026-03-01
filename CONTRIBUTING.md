# 贡献指南

感谢您对 Mebsuta 项目的关注！我们欢迎任何形式的贡献。

## 开发环境设置

### 前置要求

- Go 1.22 或更高版本
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
# 运行所有测试
./test.sh unit

# 运行格式检查
./test.sh fmt

# 运行 go vet
./test.sh vet

# 运行基准测试
./test.sh benchmark
```

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
# 运行所有单元测试
go test -v ./...

# 运行特定包的测试
go test -v ./config/...

# 运行带覆盖率的测试
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

1. 更新 CHANGELOG.md
2. 更新版本号（如有必要）
3. 创建 Git 标签
4. 创建 GitHub Release

## 获取帮助

如有任何问题，请：

- 提交 [Issue](https://github.com/iuboy/mebsuta/issues)
- 查看 [文档](https://github.com/iuboy/mebsuta/blob/main/docs/)
- 加入 [讨论](https://github.com/iuboy/mebsuta/discussions)

---

再次感谢您的贡献！
