# 性能基准

**环境**: Apple M5, macOS, Go 1.27 darwin/arm64（不同轮次硬件/编译器版本不同，只做相对比较）

## Handler 开销

| Handler | ns/op | B/op | allocs/op |
|---------|-------|------|-----------|
| StdoutHandler (JSON) | 912 | 801 | 13 |
| StdoutHandler (Console) | 446 | 209 | 2 |
| StdoutHandler (WithAttrs) | 1026 | 958 | 16 |
| SamplingHandler (pass) | 764 | 691 | 9 |
| SamplingHandler (drop) | 153 | 0 | 0 |
| MetricsHandler | 1047 | 800 | 13 |
| ContextExtractor | 930 | 847 | 14 |
| AsyncHandler | 295 | 328 | 4 |

## SafeMultiHandler

顺序分发（0.1.0-17 起 ≥4 handler 不再 goroutine-per-record fanout——
旧路径 10.8–28.6µs/op 且 3 倍波动，见 CHANGELOG）：

| 配置 | ns/op | B/op | allocs/op |
|------|-------|------|-----------|
| 2 handlers | 1746 | 1542 | 26 |
| 4 handlers | 3285 | 3028 | 52 |
| 2 handlers (parallel) | 558 | 1666 | 26 |

## 并行吞吐

| Handler | ns/op | B/op | allocs/op |
|---------|-------|------|-----------|
| StdoutHandler JSON (parallel) | 386 | 916 | 13 |

## 运行基准

```bash
go test -bench=. -benchmem -run=^$ ./...
```

Benchmarks vary by hardware. Use relative comparisons, not absolute values.
