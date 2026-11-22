package telemetry

import (
	"fmt"
	"strings"
)

// String 实现 fmt.Stringer 并脱敏：Header 的值（OTLP 认证令牌）折叠为
// ***，已配置的 Database DSN 整体渲染为 ***。database.Config 的先例是
// 通过改写凭据子串脱敏；这里选择整体掩码更为诚实，因为 telemetry 从
// 不需要从渲染字符串重新连接，而部分脱敏器可能漏掉新式 DSN 拼法
// （第五轮审计 P3 发现——缺失的 String/GoString 曾让 %v 原样打印
// Headers）。
func (c Config) String() string {
	var b strings.Builder
	c.writeBody(&b)
	return b.String()
}

// GoString 实现 fmt.GoStringer，做同样的脱敏，使 %#v 输出（调试器、
// 错误模板）也无法泄漏。
func (c Config) GoString() string {
	var b strings.Builder
	b.WriteString("telemetry.Config{")
	c.writeBody(&b)
	b.WriteString("}")
	return b.String()
}

func (c Config) writeBody(b *strings.Builder) {
	fmt.Fprintf(b, "ServiceName:%q ServiceVersion:%q Environment:%q Endpoint:%q Signals:%v SamplingRate:%v Headers:%s ShutdownTimeout:%s MetricExportInterval:%s Database:",
		c.ServiceName, c.ServiceVersion, c.Environment, c.Endpoint, c.Signals, c.SamplingRate,
		renderHeaders(c.Headers), c.ShutdownTimeout, c.MetricExportInterval)
	if c.Database == nil {
		b.WriteString("<nil>")
		return
	}
	fmt.Fprintf(b, "{Driver:%s DSN:%s TracesTable:%s MetricsTable:%s}",
		c.Database.Driver, dsnMask(c.Database.DSN), c.Database.TracesTable, c.Database.MetricsTable)
}

// renderHeaders 保留键名（运维需要看到设置了"哪些" header），
// 并掩码所有值。
func renderHeaders(h map[string]string) string {
	if len(h) == 0 {
		return "map[]"
	}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	// 确定性顺序：无泄漏的输出对日志而言也必须稳定。
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+":***")
	}
	return "map[" + strings.Join(parts, " ") + "]"
}

// dsnMask 对任何非空 DSN 返回 ***。
func dsnMask(dsn string) string {
	if dsn == "" {
		return `""`
	}
	return `"***"`
}
