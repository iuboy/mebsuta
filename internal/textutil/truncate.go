// Package textutil 持有各日志 handler 共享的 UTF-8 安全截断工具。它
// 之所以存在，是因为三个包各自长出了逐字节相同的副本（database、
// syslog）外加一个内联变体（attrutil）——单一归属加单一测试点，可以
// 防止 rune 边界规则在不同输出之间漂移。
//
// 不适用"仅限测试"的说明：这是生产共享管线，但它是 internal 的——
// 不属于对外消费面。
package textutil

// TruncateUTF8 把 s 截到至多 maxBytes 字节且不切开 UTF-8 rune，发生
// 截断时追加 "..."，让下游读者能看出值被缩短了。本来就短的字符串
// 原样通过；maxBytes 非正时返回空串；maxBytes 小于 len("...") 时在
// rune 边界硬切（没有空间放标记）。
func TruncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	if maxBytes <= 0 {
		return ""
	}
	if maxBytes < 4 {
		return s[:runeBoundary(s, maxBytes)]
	}
	limit := maxBytes - 3
	return s[:runeBoundary(s, limit)] + "..."
}

// CutToRuneBoundary 把 s 截到至多 maxLen 字节，结束在合法的 rune 边界，
// 不追加任何标记——用于属性值截断的风格，那里预算的每个字节都属于
// 内容本身。
func CutToRuneBoundary(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:runeBoundary(s, maxLen)]
}

// RuneBoundary 返回不超过 len(s) 的最大下标 n，使 s[:n] 结束在 UTF-8
// rune 边界上。导出给需要自行在边界处切片的调用方（例如 syslog 的
// JSON 截断器）。
func RuneBoundary(s string, n int) int {
	if n <= 0 {
		return 0
	}
	if n >= len(s) {
		return len(s)
	}
	for n > 0 && (s[n]&0xC0) == 0x80 {
		n--
	}
	return n
}

// runeBoundary 是上述工具使用的内部拼写。
func runeBoundary(s string, n int) int { return RuneBoundary(s, n) }
