# 性能基准

**环境**: Apple M5, macOS, Go 1.24 darwin/arm64

## Handler 开销

| Handler | ns/op | B/op | allocs/op |
|---------|-------|------|-----------|
| StdoutHandler (JSON) | 718 | 1180 | 14 |
| StdoutHandler (Console) | 328 | 215 | 0 |
| SamplingHandler (pass) | 596 | 1068 | 12 |
| SamplingHandler (drop) | 118 | 0 | 0 |
| MetricsHandler | 733 | 1195 | 14 |
| ContextExtractor | 713 | 1282 | 16 |

## SafeMultiHandler

| 配置 | ns/op | B/op | allocs/op |
|------|-------|------|-----------|
| 2 handlers | 7279 | 3032 | 36 |
| 4 handlers | 9095 | 5182 | 68 |
| 2 handlers (parallel) | 2975 | 2924 | 36 |

## 并行吞吐

| Handler | ns/op | B/op | allocs/op |
|---------|-------|------|-----------|
| StdoutHandler JSON (parallel) | 953 | 1297 | 14 |

## 运行基准

```bash
go test -bench=. -benchmem -run=^$ ./...
```

Benchmarks vary by hardware. Use relative comparisons, not absolute values.
