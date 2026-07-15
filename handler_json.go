package mebsuta

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/iuboy/mebsuta/attrutil"
)

// attrMapPool recycles map[string]any across Handle calls to reduce GC pressure.
var attrMapPool = sync.Pool{
	New: func() any { return make(map[string]any, 16) },
}

func getAttrMap() map[string]any {
	return attrMapPool.Get().(map[string]any)
}

func putAttrMap(m map[string]any) {
	for k := range m {
		delete(m, k)
	}
	attrMapPool.Put(m)
}

// contractJSONHandler produces stable-contract JSON output: {"time","level","message","attributes"}.
// It is used instead of slog.JSONHandler to enforce the output schema and handle NaN/Inf floats.
type contractJSONHandler struct {
	mu    *sync.Mutex
	w     io.Writer
	attrs []slog.Attr
	group string
	loc   *time.Location // 日志时间展示时区，nil 时用 UTC
}

// jsonEntry is the JSON output structure for log records.
type jsonEntry struct {
	Time       string         `json:"time"`
	Level      string         `json:"level"`
	Source     string         `json:"source,omitempty"`
	EventType  string         `json:"event_type,omitempty"`
	Message    string         `json:"message"`
	Actor      string         `json:"actor,omitempty"`
	Success    *bool          `json:"success,omitempty"`
	Attributes map[string]any `json:"attributes"`
}

// newContractJSONHandler returns a slog.Handler that writes stable-contract JSON to w.
// loc controls the timezone of the "time" field; nil defaults to UTC.
func newContractJSONHandler(w io.Writer, loc *time.Location) slog.Handler {
	return &contractJSONHandler{w: w, mu: &sync.Mutex{}, loc: loc}
}

func (h *contractJSONHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

// timezone 返回配置的时区，nil 时用 UTC。
func (h *contractJSONHandler) timezone() *time.Location {
	if h.loc == nil {
		return time.UTC
	}
	return h.loc
}

func (h *contractJSONHandler) Handle(_ context.Context, r slog.Record) error {
	attributes := getAttrMap()
	defer putAttrMap(attributes)

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
			source = fmt.Sprintf("%s:%d %s", filepath.Base(f.File), f.Line, f.Function)
		}
	}

	entry := &jsonEntry{
		Time:       r.Time.In(h.timezone()).Format(time.RFC3339Nano),
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
	_, err = h.w.Write(append(data, '\n'))
	return err
}

func (h *contractJSONHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := &contractJSONHandler{
		w:     h.w,
		mu:    h.mu,
		attrs: make([]slog.Attr, 0, len(h.attrs)+len(attrs)),
		group: h.group,
		loc:   h.loc,
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
		mu:    h.mu,
		attrs: append([]slog.Attr(nil), h.attrs...),
		group: group,
		loc:   h.loc,
	}
}

// prefixAttr prepends group to the attr's key if both are non-empty.
func prefixAttr(group string, attr slog.Attr) slog.Attr {
	if group == "" || attr.Key == "" {
		return attr
	}
	attr.Key = group + "." + attr.Key
	return attr
}

var _ slog.Handler = (*contractJSONHandler)(nil)
