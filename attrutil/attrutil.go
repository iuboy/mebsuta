// Package attrutil provides shared slog attribute conversion utilities.
// It is exported for cross-module use by sub-packages (syslog, database).
package attrutil

import (
	"fmt"
	"log/slog"
	"math"
	"time"
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
func SlogValueAny(v slog.Value, nan NaNBehavior) any {
	switch v.Kind() {
	case slog.KindGroup:
		groupAttrs := v.Group()
		m := make(map[string]any, len(groupAttrs))
		for _, a := range groupAttrs {
			m[a.Key] = SlogValueAny(a.Value, nan)
		}
		return m
	case slog.KindLogValuer:
		return SlogValueAny(v.Resolve(), nan)
	}
	v = v.Resolve()
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
		return v.Any()
	}
}

const (
	maxFlattenDepth = 16
	maxKeyLen       = 256
	maxAttrCount    = 1024
)

// FlattenAttr flattens a slog.Attr into out map with optional key prefix.
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
	if prefix != "" {
		key = prefix + "." + key
	}
	if key == "" {
		return
	}
	if len(key) > maxKeyLen {
		key = key[:maxKeyLen]
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
func FlattenAttrsToMap(attrs []slog.Attr, nan NaNBehavior) map[string]any {
	out := make(map[string]any, len(attrs))
	for _, attr := range attrs {
		FlattenAttr(out, "", attr, nan)
	}
	return out
}

// FormatTime returns the time formatted as RFC3339Nano in UTC.
func FormatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}
