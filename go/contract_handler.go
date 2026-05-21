package mebsuta

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"time"
)

type contractJSONHandler struct {
	w     io.Writer
	attrs []slog.Attr
	group string
}

func newContractJSONHandler(w io.Writer) slog.Handler {
	return &contractJSONHandler{w: w}
}

func (h *contractJSONHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (h *contractJSONHandler) Handle(_ context.Context, r slog.Record) error {
	attributes := make(map[string]any)
	eventType, actor, success := "", "", (*bool)(nil)

	addAttr := func(prefix string, attr slog.Attr) {
		if attr.Equal(slog.Attr{}) {
			return
		}
		flattenAttr(attributes, prefix, attr)
	}

	for _, attr := range h.attrs {
		addAttr("", attr)
	}
	r.Attrs(func(attr slog.Attr) bool {
		addAttr(h.group, attr)
		return true
	})

	if v, ok := attributes["event_type"].(string); ok {
		eventType = v
		delete(attributes, "event_type")
	}
	if v, ok := attributes["actor"].(string); ok {
		actor = v
		delete(attributes, "actor")
	}
	if v, ok := attributes["success"].(bool); ok {
		success = &v
		delete(attributes, "success")
	}

	level := r.Level.String()
	if r.Level == LevelAudit {
		level = "AUDIT"
	}

	entry := struct {
		Time       string         `json:"time"`
		Level      string         `json:"level"`
		EventType  string         `json:"event_type,omitempty"`
		Message    string         `json:"message"`
		Actor      string         `json:"actor,omitempty"`
		Success    *bool          `json:"success,omitempty"`
		Attributes map[string]any `json:"attributes"`
	}{
		Time:       r.Time.UTC().Format(time.RFC3339Nano),
		Level:      level,
		EventType:  eventType,
		Message:    r.Message,
		Actor:      actor,
		Success:    success,
		Attributes: attributes,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(h.w, string(data))
	return err
}

func (h *contractJSONHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := &contractJSONHandler{
		w:     h.w,
		attrs: make([]slog.Attr, 0, len(h.attrs)+len(attrs)),
		group: h.group,
	}
	next.attrs = append(next.attrs, h.attrs...)
	if h.group == "" {
		next.attrs = append(next.attrs, attrs...)
		return next
	}
	for _, attr := range attrs {
		next.attrs = append(next.attrs, prefixAttr(h.group, attr))
	}
	return next
}

func (h *contractJSONHandler) WithGroup(name string) slog.Handler {
	group := name
	if h.group != "" && name != "" {
		group = h.group + "." + name
	}
	return &contractJSONHandler{
		w:     h.w,
		attrs: append([]slog.Attr(nil), h.attrs...),
		group: group,
	}
}

func prefixAttr(group string, attr slog.Attr) slog.Attr {
	if group == "" || attr.Key == "" {
		return attr
	}
	attr.Key = group + "." + attr.Key
	return attr
}

func flattenAttr(out map[string]any, prefix string, attr slog.Attr) {
	attr.Value = attr.Value.Resolve()
	key := attr.Key
	if prefix != "" {
		key = prefix + "." + key
	}
	if key == "" {
		return
	}
	if attr.Value.Kind() == slog.KindGroup {
		for _, child := range attr.Value.Group() {
			flattenAttr(out, key, child)
		}
		return
	}
	out[key] = slogValueAny(attr.Value)
}

func slogValueAny(v slog.Value) any {
	v = v.Resolve()
	switch v.Kind() {
	case slog.KindString:
		return v.String()
	case slog.KindBool:
		return v.Bool()
	case slog.KindInt64:
		return v.Int64()
	case slog.KindUint64:
		return v.Uint64()
	case slog.KindFloat64:
		f := v.Float64()
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return nil
		}
		return f
	case slog.KindDuration:
		return v.Duration().String()
	case slog.KindTime:
		return v.Time().UTC().Format(time.RFC3339Nano)
	default:
		return v.Any()
	}
}
