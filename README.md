# Mebsuta

Mebsuta 现在按语言拆分为两个独立项目：

| Project | Path | Runtime | Description |
| --- | --- | --- | --- |
| Rust implementation | `rust/` | Cargo workspace | `mebsuta` core crate plus `mebsuta-tracing` and `mebsuta-metrics` companion crates |
| Go implementation | `go/` | Go module | `log/slog` based implementation with file, syslog, database, sampling, async, and metrics handlers |

## Rust

```bash
cd rust
cargo test --workspace
cargo run -p mebsuta --example basic
```

See `rust/README.md` for Rust usage and crate layout.

## Go

```bash
cd go
go test -race -count=1 ./...
```

See `go/README.md` for Go usage and package layout.

## Repository Docs

Repository-level process and policy documents remain at the root:

- `SPEC.md`
- `TESTING.md`
- `IMPLEMENTATION_PLAN.md`
- `CHANGELOG.md`
- `CONTRIBUTING.md`
- `SECURITY.md`
- `VERSIONING.md`
- `MIGRATION.md`

`SPEC.md` is the shared behavior contract for both language implementations.
`TESTING.md` maps those shared behaviors to Go and Rust test coverage.

## License

MIT License
