#!/bin/bash

# Mebsuta Go 测试脚本

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
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
    (cd "$ROOT_DIR" && go test -race -count=1 ./...)
}

run_benchmarks() {
    print_info "运行基准测试..."
    (cd "$ROOT_DIR" && go test -bench=. -benchmem -count=1 ./...)
}

run_coverage() {
    print_info "运行测试并生成覆盖率报告..."
    (cd "$ROOT_DIR" && go test -race -coverprofile=coverage.out -covermode=atomic ./...)
    (cd "$ROOT_DIR" && go tool cover -html=coverage.out -o coverage.html)
    print_success "覆盖率报告: $ROOT_DIR/coverage.html"
    (cd "$ROOT_DIR" && go tool cover -func=coverage.out | tail -1)
}

run_vet() {
    print_info "运行 go vet..."
    (cd "$ROOT_DIR" && go vet ./...)
}

run_staticcheck() {
    print_info "运行 staticcheck..."
    if ! command -v staticcheck &> /dev/null; then
        print_info "staticcheck 未安装，正在安装..."
        (cd "$ROOT_DIR" && go install honnef.co/go/tools/cmd/staticcheck@latest)
    fi
    (cd "$ROOT_DIR" && staticcheck ./...)
}

run_fmt_check() {
    print_info "检查代码格式..."
    unformatted=$(cd "$ROOT_DIR" && gofmt -s -l .)
    if [ -n "$unformatted" ]; then
        print_error "以下文件需要格式化:"
        echo "$unformatted"
        exit 1
    fi
    print_success "代码格式正确"
}

run_integration() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker 未安装"
        exit 1
    fi

    print_info "启动 Docker 服务..."
    (cd "$ROOT_DIR" && docker compose -f scripts/docker-compose.yml up -d --wait)

    print_info "运行集成测试..."
    (cd "$ROOT_DIR" && go test -race -count=1 -tags=integration ./database/...)
    local db_result=$?

    (cd "$ROOT_DIR" && go test -race -count=1 -tags=integration ./syslog/...)
    local syslog_result=$?

    print_info "停止 Docker 服务..."
    (cd "$ROOT_DIR" && docker compose -f scripts/docker-compose.yml down)

    if [ $db_result -ne 0 ]; then
        print_error "数据库集成测试失败"
        exit $db_result
    fi
    if [ $syslog_result -ne 0 ]; then
        print_error "Syslog 集成测试失败"
        exit $syslog_result
    fi
    print_success "集成测试通过"
}

cleanup() {
    print_info "清理测试产物..."
    rm -f "$ROOT_DIR/coverage.out" "$ROOT_DIR/coverage.html"
    print_success "清理完成"
}

show_help() {
    cat <<EOF
Mebsuta 测试脚本

用法: $0 [选项]

选项:
  all           运行单元测试 + go vet + staticcheck + 覆盖率报告（默认）
  unit          仅运行单元测试
  integration   运行 Docker 集成测试（需要 Docker）
  bench         运行基准测试
  cover         运行测试并生成覆盖率报告
  vet           运行 go vet 检查
  lint          运行 staticcheck
  fmt           检查代码格式
  clean         清理测试产物
  help          显示帮助信息
EOF
}

main() {
    check_go

    case "${1:-all}" in
        all)
            run_unit_tests
            run_vet
            run_staticcheck
            run_fmt_check
            run_coverage
            ;;
        unit)
            run_unit_tests
            ;;
        integration)
            run_integration
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
        lint)
            run_staticcheck
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
