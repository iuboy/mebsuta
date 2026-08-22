// Package attrutil provides shared slog attribute conversion utilities.
// It is exported for cross-module use by sub-packages (syslog, database).
package attrutil

import (
	"fmt"
	"log/slog"
	"math"
	"time"
	"unicode/utf8"
)

// NaNBehavior controls how NaN and Inf float values are represented.
type NaNBehavior int

// NaN handling behaviors.
const (
	NaNSafe NaNBehavior = iota
	NaNString
	NaNRaw
)

// SlogValueAny converts a slog.Value to a Go any value.
//
// NaN/Inf handling: When nan is NaNSafe and the value is NaN or ±Inf, this
// function returns nil. Callers MUST handle nil values (e.g. by checking
// before type-asserting to float64).
//
// Group nesting deeper than maxFlattenDepth returns nil instead of recursing
// further: this exported function has no other depth guard, and a
// self-referential LogValuer→group chain would otherwise overflow the stack
// (an unrecoverable fatal).
func SlogValueAny(v slog.Value, nan NaNBehavior) any {
	return slogValueAny(v, nan, 0)
}

func slogValueAny(v slog.Value, nan NaNBehavior, depth int) any {
	if depth >= maxFlattenDepth {
		return nil
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
		// error-typed values must surface their message, not their (private)
		// backing struct — otherwise json.Marshal renders them as "{}".
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

// FlattenAttr flattens a slog.Attr into out map with optional key prefix.
//
// IMPORTANT: This function writes to the caller-provided map without any
// synchronization. If multiple goroutines share the same map, the caller
// must serialize access (e.g. with a mutex).
func FlattenAttr(out map[string]any, prefix string, attr slog.Attr, nan NaNBehavior) {
	flattenAttr(out, prefix, attr, nan, 0)
}

func flattenAttr(out map[string]any, prefix string, attr slog.Attr, nan NaNBehavior, depth int) {
	if depth >= maxFlattenDepth {
		return
	}
	if len(out) >= maxAttrCount {
		return
	}
	attr.Value = attr.Value.Resolve()
	key := attr.Key
	// Reject empty key early — before prefix concatenation — so that a
	// non-empty prefix combined with an empty key does not produce a
	// trailing-dot key like "prefix.".
	if key == "" {
		return
	}
	if prefix != "" {
		key = prefix + "." + key
	}
	if len(key) > maxKeyLen {
		// Truncate at a valid UTF-8 rune boundary to avoid splitting
		// multi-byte characters, which would produce invalid UTF-8 and
		// potentially corrupt downstream rendering.
		key = truncateToValidUTF8(key, maxKeyLen)
	}
	if attr.Value.Kind() == slog.KindGroup {
		for _, child := range attr.Value.Group() {
			flattenAttr(out, key, child, nan, depth+1)
		}
		return
	}
	out[key] = SlogValueAny(attr.Value, nan)
}

// FlattenAttrsToMap converts a slice of slog.Attr into a flat map[string]any.
//
// The returned map is newly allocated and owned exclusively by the caller;
// no synchronization is needed for subsequent access. The initial capacity
// is scaled by a factor of 2 to reduce reallocations when attrs contain
// Group values that expand into multiple entries.
func FlattenAttrsToMap(attrs []slog.Attr, nan NaNBehavior) map[string]any {
	// Over-allocate by 2x: Group attrs expand into multiple entries in the
	// same flat map, so len(attrs) is a lower bound, not the actual count.
	out := make(map[string]any, len(attrs)*2)
	for _, attr := range attrs {
		FlattenAttr(out, "", attr, nan)
	}
	return out
}

// FormatTime returns the time formatted as RFC3339Nano in UTC.
func FormatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

// truncateToValidUTF8 truncates s to at most maxLen bytes, ensuring the
// result ends on a valid UTF-8 rune boundary. This prevents multi-byte
// character splitting that would produce invalid UTF-8 in log output.
func truncateToValidUTF8(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	// Walk backward from the truncation point to find a valid rune boundary.
	for maxLen > 0 && !utf8.RuneStart(s[maxLen]) {
		maxLen--
	}
	return s[:maxLen]
}
