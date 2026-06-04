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

// entryPool recycles jsonEntry across Handle calls to reduce heap allocations.
var entryPool = sync.Pool{
	New: func() any { return new(jsonEntry) },
}

// newContractJSONHandler returns a slog.Handler that writes stable-contract JSON to w.
func newContractJSONHandler(w io.Writer) slog.Handler {
	return &contractJSONHandler{w: w, mu: &sync.Mutex{}}
}

func (h *contractJSONHandler) Enabled(context.Context, slog.Level) bool {
	return true
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

	entry := entryPool.Get().(*jsonEntry)
	entry.Time = r.Time.UTC().Format(time.RFC3339Nano)
	entry.Level = level
	entry.Source = source
	entry.EventType = eventType
	entry.Message = r.Message
	entry.Actor = actor
	entry.Success = success
	entry.Attributes = attributes

	data, err := json.Marshal(entry)

	// Reset and return entry to pool before proceeding.
	entry.Time = ""
	entry.Level = ""
	entry.Source = ""
	entry.EventType = ""
	entry.Message = ""
	entry.Actor = ""
	entry.Success = nil
	entry.Attributes = nil
	entryPool.Put(entry)

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
