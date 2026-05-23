# Versioning

Mebsuta 遵循 Semantic Versioning 2.0.0。

## Module

Go module path: `github.com/iuboy/mebsuta`

## Version Tags

```text
v0.1.0
v0.1.1
v1.0.0
```

### Legacy Tags

Tags `v0.1.0` through `v0.3.4` 是 monorepo 拆分前的旧版本，使用 `go/` 子目录的 import path `github.com/iuboy/mebsuta/go`。

当前版本使用根级 `vX.Y.Z` 标签，import path 为 `github.com/iuboy/mebsuta`。

### Pre-release

```text
v1.0.0-rc.1
v1.0.0-beta.1
```

## Semantic Versioning

Version format:

```text
vMAJOR.MINOR.PATCH
```

- `MAJOR`: 不兼容的 API 变更
- `MINOR`: 向后兼容的新功能
- `PATCH`: 向后兼容的修复

## Breaking Changes

以下变更需要 major version bump：

1. 删除或重命名导出的 public API
2. 修改 public 函数、方法或类型的签名
3. 删除支持的配置字段
4. 以向后不兼容的方式修改 `SPEC.md` 定义的行为
5. 以消费者无法容忍的方式修改序列化输出

以下不是 breaking changes：

1. 添加新的导出 API
2. 添加可选的配置字段
3. 添加新的 handler 或装饰器
4. 在不改变行为的前提下提升性能
5. 修复 bug 以匹配文档行为
6. 当旧行为是安全 bug 时收紧不安全的默认值

## Release Checklist

- [ ] 更新 `CHANGELOG.md`
- [ ] 确认 `go.mod` module path 正确
- [ ] 运行 Go 测试、vet、格式化和 `govulncheck`
- [ ] 创建 tag `vX.Y.Z`
- [ ] 推送 tag 并确认 release validation 通过

## Deprecation Policy

当 API 需要废弃时：

1. 在 godoc 中标记为 deprecated
2. 说明替代方案
3. 至少保留一个 minor release
4. 在下一个 major release 中移除

示例：

```go
// Deprecated: use NewFileHandler(FileConfig{...}) instead. This will be removed in v2.0.0.
func NewSimpleConfig(name string) *LoggerConfig {
    // ...
}
```

## Dependency Management

依赖应定期更新安全修复。

- Go 依赖管理在 `go.mod` 和 `go.sum`
- GitHub Actions 依赖管理在仓库根目录

安全扫描：

- Go: `govulncheck`
- GitHub Actions: Dependabot
