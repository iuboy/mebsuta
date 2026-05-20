# Go Performance Baseline

Hardware: Apple Silicon (M-series), macOS. Go 1.26.3 darwin/arm64.
Date: 2026-05-20.

## Summary

| Benchmark | ns/op | B/op | allocs/op |
|---|---|---|---|
| StdoutHandler JSON | 350 | 331 | 0 |
| StdoutHandler Console | 317 | 210 | 0 |
| StdoutHandler WithAttrs | 311 | 276 | 0 |
| SamplingHandler Pass | 309 | 205 | 0 |
| SamplingHandler Drop | 116 | 0 | 0 |
| AsyncHandler (256 buffer) | drops | — | — |
| AsyncHandler (64K buffer) | drops | — | — |
| MetricsHandler | 392 | 349 | 0 |
| ContextExtractor | 362 | 370 | 1 |
| SafeMulti 2 handlers | 5894 | 1168 | 8 |
| SafeMulti 4 handlers | 6676 | 2179 | 12 |
| StdoutHandler JSON Parallel | 451 | 203 | 0 |
| SafeMulti 2 Parallel | 2074 | 995 | 8 |
| Chain: Sampling→Async→Stdout | drops | — | — |

## Notes

- **AsyncHandler** drops records under benchmark load even with 64K buffer. This is expected: the single-consumer goroutine cannot keep up with the producer. In production, the inner handler (file/syslog) is the bottleneck. The drop count is tracked via `AsyncDropped()`.
- **SafeMultiHandler** uses goroutine-per-record with `sync.WaitGroup`. The 8 allocs/op for 2 handlers reflects `r.Clone()` + goroutine overhead. Parallel benchmark shows better throughput (2074 ns/op vs 5894 ns/op serial) because goroutines overlap.
- **SamplingHandler Drop** is essentially free (116 ns, 0 allocs) — atomic check + early return.
- All handlers achieve **zero allocs** on the basic write path (Stdout, Sampling, Metrics). The single alloc in ContextExtractor comes from the attribute slice returned by the extractor closure.

## How to reproduce

```bash
cd go/
go test -bench=. -benchmem -count=3 -timeout=5m ./...
```
