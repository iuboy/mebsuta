# Versioning

Mebsuta follows Semantic Versioning 2.0.0, with language-specific release streams inside one repository.

## Repository Model

This repository is a dual-language monorepo:

- Go module: `go/`
- Rust workspace: `rust/`
- Shared governance: repository root

The Go and Rust implementations share the behavior contract in `SPEC.md`, but they may release on different schedules.

## Version Streams

### Legacy Tags

Tags `v0.1.0` through `v0.3.4` are Go-only releases created before the monorepo split. They use root-level `v*` tags and the import path `github.com/iuboy/mebsuta` (without the `/go` suffix).

Starting from the monorepo split, Go releases use `go/vX.Y.Z` tags and the import path `github.com/iuboy/mebsuta/go`.

### Go

Go releases use tags under the `go/` namespace:

```text
go/v0.1.0
go/v0.1.1
go/v1.0.0
```

This matches the Go module living in the `go/` subdirectory. The module path is `github.com/iuboy/mebsuta/go`.

### Rust

Rust releases use tags under the `rust/` namespace:

```text
rust/v0.1.0
rust/v0.1.1
rust/v1.0.0
```

The Cargo package versions in `rust/Cargo.toml` and member crates must match the release being validated.

### Umbrella Releases

Root tags such as `v0.1.0` are reserved for optional whole-repository releases. They should only be used when Go and Rust are intentionally released together.

## Semantic Versioning

Version format:

```text
vMAJOR.MINOR.PATCH
```

- `MAJOR`: incompatible API or behavior changes
- `MINOR`: backward-compatible features
- `PATCH`: backward-compatible fixes

Pre-release examples:

```text
go/v1.0.0-rc.1
rust/v1.0.0-beta.1
```

## Breaking Changes

The following require a major version bump for the affected language stream:

1. Removing or renaming exported public APIs
2. Changing public function, method, trait, interface, or type signatures
3. Removing supported configuration fields
4. Changing `SPEC.md` behavior in a backward-incompatible way
5. Changing serialized output in a way consumers cannot tolerate

The following are not breaking changes:

1. Adding new exported APIs
2. Adding optional configuration fields
3. Adding new handlers or decorators
4. Improving performance without changing behavior
5. Fixing bugs to match documented behavior
6. Tightening unsafe defaults when the old behavior was a security bug

## Release Checklist

For a Go release:

- [ ] Update `CHANGELOG.md` under the Go section
- [ ] Confirm `go/go.mod` module path is correct
- [ ] Run Go tests, vet, formatting, and `govulncheck`
- [ ] Create tag `go/vX.Y.Z`
- [ ] Push the tag and confirm release validation passes

For a Rust release:

- [ ] Update `CHANGELOG.md` under the Rust section
- [ ] Update Cargo package versions
- [ ] Run Rust tests, fmt, clippy, and `cargo audit`
- [ ] Confirm Cargo package validation passes
- [ ] Create tag `rust/vX.Y.Z`
- [ ] Push the tag and confirm release validation passes

For an umbrella release:

- [ ] Confirm both language implementations are intended to ship together
- [ ] Run full repository validation
- [ ] Create tag `vX.Y.Z`
- [ ] Publish GitHub release notes that clearly identify Go and Rust versions

## Deprecation Policy

When an API needs to be deprecated:

1. Mark it as deprecated in language-native documentation.
2. Explain the replacement.
3. Keep it for at least one minor release after deprecation when practical.
4. Remove it in the next major release.

Go example:

```go
// Deprecated: use NewLoggerConfigBuilder instead. This will be removed in v2.0.0.
func NewSimpleConfig(name string) *LoggerConfig {
    // ...
}
```

Rust example:

```rust
#[deprecated(note = "use LoggerConfigBuilder instead; this will be removed in v2.0.0")]
pub fn new_simple_config(name: &str) -> LoggerConfig {
    // ...
}
```

## Dependency Management

Dependencies should be updated regularly for security fixes.

- Go dependencies are managed in `go/go.mod`.
- Rust dependencies are managed in `rust/Cargo.toml` and `rust/Cargo.lock`.
- GitHub Actions dependencies are managed at the repository root.

Security scanning:

- Go: `govulncheck`
- Rust: `cargo audit`
- GitHub Actions: Dependabot
