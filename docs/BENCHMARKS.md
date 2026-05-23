# Performance Benchmarks

Mebsuta Go 日志库基准测试结果。

## Methodology

```bash
go test -bench=. -benchmem -run=^$ ./...
```

**Environment**: Apple M5, macOS, Go 1.24 darwin/arm64

## Handler Overhead

| Handler | ns/op | B/op | allocs/op |
|---------|-------|------|-----------|
| StdoutHandler (JSON) | 718 | 1180 | 14 |
| StdoutHandler (Console) | 328 | 215 | 0 |
| SamplingHandler (pass) | 596 | 1068 | 12 |
| SamplingHandler (drop) | 118 | 0 | 0 |
| MetricsHandler | 733 | 1195 | 14 |
| ContextExtractor | 713 | 1282 | 16 |

**Key findings**:
- SamplingHandler drop 路径几乎零开销（118 ns, 0 allocs）
- Console 格式比 JSON 快 2.2x（328 vs 718 ns/op）
- MetricsHandler 仅增加 ~15 ns 开销

## SafeMultiHandler

| Configuration | ns/op | B/op | allocs/op |
|---------------|-------|------|-----------|
| 2 handlers | 7279 | 3032 | 36 |
| 4 handlers | 9095 | 5182 | 68 |
| 2 handlers (parallel) | 2975 | 2924 | 36 |

**Key findings**:
- 并行模式下 2 handlers 吞吐提升 2.4x（2975 vs 7279 ns/op）
- allocs 线性增长：每个 handler ~18 allocs（`r.Clone()` + goroutine 开销）

## Parallel Throughput

| Handler | ns/op | B/op | allocs/op |
|---------|-------|------|-----------|
| StdoutHandler JSON (parallel) | 953 | 1297 | 14 |

并行下 JSON handler 增加约 33% 开销（953 vs 718 ns/op），仍保持零自定义分配。

## Memory Usage

| Handler | Buffer Memory |
|---------|---------------|
| AsyncHandler (256 buffer) | ~50 KB |
| SyslogHandler (1000 buffer) | ~300 KB |
| SamplingHandler | <1 KB |
| MetricsHandler | <1 KB |

## Running Benchmarks

```bash
# 全部基准
go test -bench=. -benchmem -run=^$ ./...

# 特定 handler
go test -bench=BenchmarkStdoutHandler -benchmem ./...

# CPU profiling
go test -bench=. -cpuprofile=cpu.prof ./...
go tool pprof cpu.prof

# Memory profiling
go test -bench=. -memprofile=mem.prof ./...
go tool pprof mem.prof
```

## Contributing

新增 handler 时：

1. 在 `*_test.go` 中添加 `Benchmark<HandlerName>_<Operation>`
2. 包含 pass-through 和 error 路径
3. 更新本文档

## Historical Data

| Date | Platform | Stdout JSON | Console | Sampling Drop |
|------|----------|-------------|---------|---------------|
| 2026-05-22 | M5/arm64 | 718 ns/op | 328 ns/op | 118 ns/op |

Benchmarks vary by hardware. Use relative comparisons, not absolute values.
