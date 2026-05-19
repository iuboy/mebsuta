#!/bin/bash

set -e

case "${1:-test}" in
    test)
        cargo test --workspace
        ;;
    check)
        cargo check --workspace --all-targets
        ;;
    fmt)
        cargo fmt --all -- --check
        ;;
    clippy)
        cargo clippy --workspace -- -D warnings
        ;;
    all)
        cargo fmt --all -- --check
        cargo clippy --workspace -- -D warnings
        cargo test --workspace
        ;;
    help|--help|-h)
        echo "Usage: $0 [test|check|fmt|clippy|all]"
        ;;
    *)
        echo "unknown option: $1" >&2
        exit 1
        ;;
esac
