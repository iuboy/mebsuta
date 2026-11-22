// Package attrutil 提供共享的 slog 属性转换工具。
// 供子包（syslog、database）跨模块使用而导出。
package attrutil

import (
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/iuboy/mebsuta/internal/textutil"
)

// NaNBehavior 控制 NaN 与 Inf 浮点值的表示方式。
type NaNBehavior int

// NaN 处理行为。
const (
	NaNSafe NaNBehavior = iota
	NaNString
	NaNRaw
)

// SlogValueAny 把 slog.Value 转换为 Go 的 any 值。
//
// NaN/Inf 处理：当 nan 为 NaNSafe 且值是 NaN 或 ±Inf 时，本函数返回
// nil。调用方必须处理 nil 值（例如在类型断言为 float64 之前先检查）。
//
// group 嵌套超过 maxFlattenDepth 时返回 nil 而不是继续递归：这个导出
// 函数没有其他深度防护，若不如此，自引用的 LogValuer→group 链会
// 溢出栈（不可恢复的 fatal）。
func SlogValueAny(v slog.Value, nan NaNBehavior) any {
	return slogValueAny(v, nan, 0)
}

// depthLimitValue 标记被递归上限丢弃的值。它必须能与 NaNSafe 为非有限
// 浮点产生的 null 区分开——否则审计者看到 null 无法分辨"值是 NaN /
// 缺失"与"嵌套超过上限"。
const depthLimitValue = "<max-depth>"

func slogValueAny(v slog.Value, nan NaNBehavior, depth int) any {
	if depth >= maxFlattenDepth {
		return depthLimitValue
	}
	switch v.Kind() {
	case slog.KindGroup:
		groupAttrs := v.Group()
		m := make(map[string]any, len(groupAttrs))
		for _, a := range groupAttrs {
			m[a.Key] = slogValueAny(a.Value, nan, depth+1)
		}
		return m
	case slog.KindLogValuer:
		v = v.Resolve()
	}
	switch v.Kind() {
	case slog.KindString:
		return v.String()
	case slog.KindInt64:
		return v.Int64()
	case slog.KindUint64:
		return v.Uint64()
	case slog.KindFloat64:
		f := v.Float64()
		if math.IsNaN(f) || math.IsInf(f, 0) {
			switch nan {
			case NaNSafe:
				return nil
			case NaNString:
				return fmt.Sprintf("%g", f)
			default:
				return f
			}
		}
		return f
	case slog.KindBool:
		return v.Bool()
	case slog.KindDuration:
		return v.Duration().String()
	case slog.KindTime:
		return v.Time()
	default:
		// error 类型的值必须呈现其消息，而非其（私有的）底层结构——
		// 否则 json.Marshal 会把它们渲染成 "{}"。
		if anyVal := v.Any(); anyVal != nil {
			if err, ok := anyVal.(error); ok {
				return err.Error()
			}
		}
		return v.Any()
	}
}

const (
	maxFlattenDepth = 16
	maxKeyLen       = 256
	maxAttrCount    = 1024
)

// FlattenAttr 把 slog.Attr 扁平化进 out 映射，可带键前缀。
//
// 重要：本函数在无任何同步的情况下写入调用方提供的映射。若多个
// goroutine 共享同一映射，调用方必须串行化访问（例如用互斥锁）。
func FlattenAttr(out map[string]any, prefix string, attr slog.Attr, nan NaNBehavior) {
	flattenAttr(out, prefix, attr, nan, 0)
}

func flattenAttr(out map[string]any, prefix string, attr slog.Attr, nan NaNBehavior, depth int) {
	flattenAttrTracked(out, prefix, attr, nan, depth, nil)
}

// FlattenAttrMarked 把 slog.Attr 扁平化进 out，可带键前缀，并报告是否
// 触碰了任何上限：超长键被截断到 maxKeyLen、属性数量上限丢弃了该属性、
// 或嵌套上限跳过了某个子树。调用方跨属性累积该标志以呈现截断标记
// （JSON 契约路径发出 attributes["_truncated"]，对应 syslog handler 的
// _truncated PARAM-NAME）。
//
// 重要：本函数在无任何同步的情况下写入调用方提供的映射。若多个
// goroutine 共享同一映射，调用方必须串行化访问（例如用互斥锁）。
func FlattenAttrMarked(out map[string]any, prefix string, attr slog.Attr, nan NaNBehavior) bool {
	truncated := false
	flattenAttrTracked(out, prefix, attr, nan, 0, &truncated)
	return truncated
}

func markTruncated(truncated *bool) {
	if truncated != nil {
		*truncated = true
	}
}

func flattenAttrTracked(out map[string]any, prefix string, attr slog.Attr, nan NaNBehavior, depth int, truncated *bool) {
	if depth >= maxFlattenDepth {
		markTruncated(truncated)
		return
	}
	if len(out) >= maxAttrCount {
		markTruncated(truncated)
		return
	}
	attr.Value = attr.Value.Resolve()
	key := attr.Key
	// 尽早拒绝空键——在拼接前缀之前——使非空前缀与空键的组合不会产生
	// "prefix." 这类带尾点的键。这是输入清洁，不是截断事件：不通过
	// truncated 标志报告。
	if key == "" {
		return
	}
	if prefix != "" {
		key = prefix + "." + key
	}
	if len(key) > maxKeyLen {
		// 在合法的 UTF-8 rune 边界处截断，避免切开多字节字符——那会
		// 产生非法 UTF-8 并可能破坏下游渲染。
		key = truncateToValidUTF8(key, maxKeyLen)
		markTruncated(truncated)
	}
	if attr.Value.Kind() == slog.KindGroup {
		for _, child := range attr.Value.Group() {
			flattenAttrTracked(out, key, child, nan, depth+1, truncated)
		}
		return
	}
	out[key] = SlogValueAny(attr.Value, nan)
}

// FlattenAttrsToMap 把 slog.Attr 切片转换为扁平的 map[string]any。
//
// 返回的映射是新分配的、由调用方独占；后续访问无需同步。初始容量按
// 2 倍缩放，以减少属性含 Group 值（会展开为多个条目）时的重分配。
func FlattenAttrsToMap(attrs []slog.Attr, nan NaNBehavior) map[string]any {
	// 按 2 倍超配：Group 属性会在同一扁平映射中展开为多个条目，
	// 因此 len(attrs) 只是下界，不是实际数量。
	out := make(map[string]any, len(attrs)*2)
	for _, attr := range attrs {
		FlattenAttr(out, "", attr, nan)
	}
	return out
}

// FormatTime 返回 UTC 时区、RFC3339Nano 格式的时间。
func FormatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

// truncateToValidUTF8 委托给 internal/textutil（硬切风格、无标记）——
// 这是 rune 边界回退逻辑曾经的第三份副本。
func truncateToValidUTF8(s string, maxLen int) string {
	return textutil.CutToRuneBoundary(s, maxLen)
}
