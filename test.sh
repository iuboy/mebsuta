#!/bin/bash

# Mebsuta 测试脚本
# 用于运行所有测试项

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 打印带颜色的消息
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 打印分隔线
print_separator() {
    echo "=================================================="
}

# 检查 Go 是否安装
check_go() {
    print_info "检查 Go 环境..."
    if ! command -v go &> /dev/null; then
        print_error "Go 未安装，请先安装 Go"
        exit 1
    fi
    local go_version=$(go version)
    print_success "Go 环境检查通过: $go_version"
}

# 运行所有测试
run_all_tests() {
    print_info "开始运行所有测试..."
    print_separator
    
    # 运行测试并生成覆盖率报告
    print_info "执行测试并生成覆盖率报告..."
    
    # 使用 go test 运行所有测试
    # -v: 显示详细输出
    # -race: 检测竞态条件
    # -cover: 生成覆盖率信息
    # -coverprofile=coverage.out: 输出覆盖率文件
    # -covermode=atomic: 使用原子模式（适用于并发测试）
    if go test -v -race -cover -coverprofile=coverage.out -covermode=atomic ./...; then
        print_success "所有测试通过！"
    else
        print_error "测试失败！"
        exit 1
    fi
}

# 生成覆盖率报告
generate_coverage_report() {
    print_separator
    print_info "生成覆盖率报告..."
    
    # 生成 HTML 格式的覆盖率报告
    if go tool cover -html=coverage.out -o coverage.html; then
        print_success "覆盖率报告已生成: coverage.html"
        print_info "可以在浏览器中打开 coverage.html 查看详细覆盖率"
    else
        print_warning "生成 HTML 覆盖率报告失败"
    fi
    
    # 打印覆盖率摘要
    print_info "覆盖率摘要:"
    go tool cover -func=coverage.out | tail -1
}

# 运行特定包的测试
run_package_tests() {
    local package=$1
    print_info "运行包 $package 的测试..."

    if go test -v -race -cover ./$package; then
        print_success "包 $package 测试通过"
    else
        print_error "包 $package 测试失败"
        exit 1
    fi
}

# 运行集成测试
run_integration_tests() {
    print_info "运行集成测试..."
    print_warning "集成测试需要Docker环境"

    if go test -v -tags=integration ./...; then
        print_success "集成测试通过"
    else
        print_error "集成测试失败"
        exit 1
    fi
}

# 运行基准测试
run_benchmarks() {
    print_separator
    print_info "运行基准测试..."
    
    if go test -bench=. -benchmem ./...; then
        print_success "基准测试完成"
    else
        print_error "基准测试失败"
        exit 1
    fi
}

# 代码格式检查
run_fmt_check() {
    print_separator
    print_info "检查代码格式..."
    
    # 检查是否有未格式化的文件
    if [ $(gofmt -s -l . | wc -l) -gt 0 ]; then
        print_warning "以下文件需要格式化:"
        gofmt -s -l .
        print_info "运行 'gofmt -s -w .' 来格式化代码"
    else
        print_success "所有代码格式正确"
    fi
}

# 运行 go vet 检查
run_vet() {
    print_separator
    print_info "运行 go vet 检查..."
    
    if go vet ./...; then
        print_success "go vet 检查通过"
    else
        print_error "go vet 检查失败"
        exit 1
    fi
}

# 清理测试文件
cleanup() {
    print_separator
    print_info "清理测试文件..."
    
    # 删除覆盖率文件
    rm -f coverage.out coverage.html
    
    print_success "清理完成"
}

# 显示帮助信息
show_help() {
    echo "Mebsuta 测试脚本"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  all         运行所有测试（默认）"
    echo "  unit        仅运行单元测试"
    echo "  integration 运行集成测试（需要Docker）"
    echo "  race        运行竞态检测测试"
    echo "  cover       运行测试并生成覆盖率报告"
    echo "  benchmark   运行基准测试"
    echo "  fmt         检查代码格式"
    echo "  vet         运行 go vet 检查"
    echo "  clean       清理测试文件"
    echo "  help        显示此帮助信息"
    echo ""
    echo "示例:"
    echo "  $0              # 运行所有测试"
    echo "  $0 unit         # 仅运行单元测试"
    echo "  $0 integration # 运行集成测试（需要Docker）"
    echo "  $0 cover        # 运行测试并生成覆盖率报告"
    echo "  $0 benchmark    # 运行基准测试"
}

# 主函数
main() {
    print_separator
    echo "Mebsuta 测试脚本"
    print_separator
    
    # 检查 Go 环境
    check_go
    echo ""
    
    # 如果没有参数，默认运行所有测试
    if [ $# -eq 0 ]; then
        run_all_tests
        generate_coverage_report
        print_separator
        print_success "测试完成！"
        exit 0
    fi
    
    # 根据参数执行不同操作
    case "$1" in
        all)
            run_all_tests
            generate_coverage_report
            ;;
        unit)
            print_info "运行单元测试..."
            go test -v -short ./...
            ;;
        integration)
            run_integration_tests
            ;;
        race)
            print_info "运行竞态检测测试..."
            go test -race -v ./...
            ;;
        cover)
            run_all_tests
            generate_coverage_report
            ;;
        benchmark)
            run_benchmarks
            ;;
        fmt)
            run_fmt_check
            ;;
        vet)
            run_vet
            ;;
        clean)
            cleanup
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            print_error "未知选项: $1"
            echo ""
            show_help
            exit 1
            ;;
    esac
    
    print_separator
    print_success "操作完成！"
}

# 执行主函数
main "$@"
