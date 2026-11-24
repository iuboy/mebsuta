# 代码风格规范

本规范来自 2026-11-22 的十六维度全仓扫描（七维基础 + 九维补扫），是
PR 审查与重构的判定依据。约定优先级：正确性 > 一致性 > 简洁。

## 配置（Config）

1. **Validate 形态**：`func (c Config) Validate() (Config, error)`——值
   接收者、返回填好默认值的规范化副本、**不修改调用方**；fail-fast，
   错误信息含合法域。
2. **校验错误类型**：统一 `*mebsuta.ConfigError{Field, Msg}`，消费方以
   `errors.As` 做字段级判断。运行期（非配置）错误用 `fmt.Errorf` 带
   包名前缀。
3. **三态布尔**：需区分"未设置/开/关"的字段用 `*bool` + `mebsuta.Ptr`；
   两态用 `bool`。
4. **默认值常量**：导出为 `DefaultXxx`（如 `DefaultShutdownTimeout`）。

## 命名与构造

5. **构造器**：handler 家族 `NewXxxHandler`；纯对象 `New`；**拥有后台
   goroutine 的用 `Start`**（必配 `Shutdown`/`Close`）；exporter 用
   `NewXxxExporter`。
6. **关闭语义**：资源释放、幂等——`Close() error`（io.Closer）；含
   刷盘/超时语义或 OTel 接口面——`Shutdown(ctx context.Context) error`。
7. **接收者**：类型名首字母小写，1–3 字符（h/m/r/e/w/t/b/c）。
8. **缩写词**：全大写（ID、URL、API、HTTP、TLS），不出现 Id/Url 拼法。

## 错误与日志

9. **错误前缀**：**子包名**作前缀（`telemetry:`/`database:`/`prombridge:`/
   `syslog:`…）。模块名在 import 路径已出现，不重复。
10. **库零打印**：生产代码禁止 `fmt.Print*`/`log.Print*`；一切内部失败
    经 `mebsuta.ErrorHandler` 链上报（现状已达标，守成）。

## 注释与断言（不留中间态）

11. **注释语言：统一中文**——包级与导出符号 doc comment、行内注释、
    测试注释一律中文。专有名词与标识符保留原文（no-op、fanout、ULID、
    OTLP、jsonb、fail-fast、at-least-once、mTLS、SAN、handler、
    exporter、batcher 等 API/协议名）。doc comment 结构（段落、#
    标记、缩进代码块）保持。README/CHANGELOG/SPEC 本为中文。
12. **测试断言：统一 testify `require`**——`require.XXX` 快败语义，
    不混用 assert 与标准库 t.Errorf/Fatalf。表格测试保持结构。
13. **导出符号必带 doc comment**（现状已达标，守成）；被并发使用的
    导出类型在 doc 中声明并发安全面。

## 并发与结构

14. **goroutine 归属**：每个 `go` 语句在其上方注释归属（owner 与
    shutdown 路径）。
15. **文件组织**：根包按 `handler_*.go` 功能分文件；子包
    `handler.go`/`config.go` 布局；一文件一主题。**子包文件名不带包名
    前缀**（目录已承载包名——`database/handler.go` 而非
    `database/database_handler.go`；单文件包按主题命名如
    `attrutil/flatten.go`）。根包主文件 `mebsuta.go` 为模块惯例保留。
    **测试文件主题 ≤ 2 词**；审计轮次编号与来源项目名不入文件名
    （写入测试顶部注释——如 `hardening_test.go` 而非
    `security_audit5_test.go`）；`regress` 拼写统一（不混用
    `regression`）；同主题回归测试合并一个文件（不设 `*_2`）。
16. **测试包形态**：默认内部包测试（可用未导出面）；仅当需要导入本
    模块其他子包时用外部包 `mebsuta_test`（先例：facade_test.go）。

## 附：examples 覆盖

新能力随附 example（现有 20 个，含 plane/prombridge/telemetry-database 等）；
缺口随新能力补齐。

## 附：全局状态

单例面地图与"不新增自有单例"原则见 [GLOBALS.md](./GLOBALS.md)。
