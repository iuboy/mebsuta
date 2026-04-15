#!/bin/bash

# Mebsuta 测试脚本

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

check_go() {
    if ! command -v go &> /dev/null; then
        print_error "Go 未安装"
        exit 1
    fi
    print_info "Go: $(go version)"
}

run_unit_tests() {
    print_info "运行单元测试..."
    go test -v -race -count=1 ./...
}

run_integration_tests() {
    print_info "运行集成测试（需要 Docker）..."
    go test -v -race -count=1 -tags=integration ./integration/...
}

run_benchmarks() {
    print_info "运行基准测试..."
    go test -bench=. -benchmem -count=1 ./...
}

run_coverage() {
    print_info "运行测试并生成覆盖率报告..."
    go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
    go tool cover -html=coverage.out -o coverage.html
    print_success "覆盖率报告: coverage.html"
    go tool cover -func=coverage.out | tail -1
}

run_vet() {
    print_info "运行 go vet..."
    go vet ./...
}

run_fmt_check() {
    print_info "检查代码格式..."
    if [ "$(gofmt -s -l . | wc -l)" -gt 0 ]; then
        print_error "以下文件需要格式化:"
        gofmt -s -l .
        exit 1
    fi
    print_success "代码格式正确"
}

cleanup() {
    print_info "清理测试文件..."
    rm -f coverage.out coverage.html
    print_success "清理完成"
}

show_help() {
    cat <<EOF
Mebsuta 测试脚本

用法: $0 [选项]

选项:
  all          运行单元测试 + 集成测试 + 覆盖率报告（默认）
  unit         仅运行单元测试
  integration  运行集成测试（需要 Docker）
  bench        运行基准测试
  cover        运行测试并生成覆盖率报告
  vet          运行 go vet 检查
  fmt          检查代码格式
  clean        清理测试产物
  help         显示帮助信息
EOF
}

main() {
    check_go

    case "${1:-all}" in
        all)
            run_unit_tests
            run_integration_tests
            run_coverage
            ;;
        unit)
            run_unit_tests
            ;;
        integration)
            run_integration_tests
            ;;
        bench)
            run_benchmarks
            ;;
        cover)
            run_coverage
            ;;
        vet)
            run_vet
            ;;
        fmt)
            run_fmt_check
            ;;
        clean)
            cleanup
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            print_error "未知选项: $1"
            show_help
            exit 1
            ;;
    esac

    print_success "完成"
}

main "$@"
