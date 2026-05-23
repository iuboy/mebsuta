package mebsuta

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"sync"
	"time"

	"github.com/iuboy/mebsuta/attrutil"
)

type contractJSONHandler struct {
	mu    sync.Mutex
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

	for _, attr := range h.attrs {
		attrutil.FlattenAttr(attributes, "", attr, attrutil.NaNSafe)
	}
	r.Attrs(func(attr slog.Attr) bool {
		attrutil.FlattenAttr(attributes, h.group, attr, attrutil.NaNSafe)
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

	var source string
	if r.PC != 0 {
		frames := runtime.CallersFrames([]uintptr{r.PC})
		if f, ok := frames.Next(); ok {
			source = fmt.Sprintf("%s:%d %s", f.File, f.Line, f.Function)
		}
	}

	entry := struct {
		Time       string         `json:"time"`
		Level      string         `json:"level"`
		Source     string         `json:"source,omitempty"`
		EventType  string         `json:"event_type,omitempty"`
		Message    string         `json:"message"`
		Actor      string         `json:"actor,omitempty"`
		Success    *bool          `json:"success,omitempty"`
		Attributes map[string]any `json:"attributes"`
	}{
		Time:       r.Time.UTC().Format(time.RFC3339Nano),
		Level:      level,
		Source:     source,
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

	h.mu.Lock()
	defer h.mu.Unlock()
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
