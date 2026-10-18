package mebsuta

import (
	"bytes"
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

// jsonEncoder bundles a buffer with the encoder bound to it. Pooling the pair
// keeps encode+newline outside the handler mutex (parallel marshal, serialized
// write only) while still avoiding the per-record Marshal allocation and the
// append(data, '\n') reallocation — json.Encoder appends the newline natively.
type jsonEncoder struct {
	buf *bytes.Buffer
	enc *json.Encoder
}

var jsonEncoderPool = sync.Pool{
	New: func() any {
		buf := new(bytes.Buffer)
		return &jsonEncoder{buf: buf, enc: json.NewEncoder(buf)}
	},
}

func getJSONEncoder() *jsonEncoder { return jsonEncoderPool.Get().(*jsonEncoder) }

func putJSONEncoder(je *jsonEncoder) {
	je.buf.Reset()
	jsonEncoderPool.Put(je)
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

	// Promote the audit contract fields from PRESET attrs only (set via
	// WithAttrs at logger construction). Record attrs with the same keys stay
	// inside "attributes": letting per-call attrs promote would let any log
	// site override the trusted actor/event_type/success — audit forgery by
	// key collision.
	for _, attr := range h.attrs {
		attrutil.FlattenAttr(attributes, "", attr, attrutil.NaNSafe)
	}
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

	// Record attrs land in attributes only; keys colliding with preset values
	// overwrite the attribute map entry but can no longer reach the promoted
	// top-level fields.
	r.Attrs(func(attr slog.Attr) bool {
		attrutil.FlattenAttr(attributes, h.group, attr, attrutil.NaNSafe)
		return true
	})

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

	je := getJSONEncoder()
	defer putJSONEncoder(je)

	if err := je.enc.Encode(entry); err != nil {
		// NaNSafe only sanitizes TOP-LEVEL floats; a NaN/chan/func hidden
		// inside a nested map or struct still fails encoding here. Returning
		// the error would silently discard the whole record (slog.Logger
		// ignores Handle errors) — instead, degrade to a fallback record so
		// the audit trail keeps a trace of what was lost and why.
		je.buf.Reset()
		if encErr := je.enc.Encode(h.fallbackEntry(r, level, err)); encErr != nil {
			return err // genuinely unreachable: all fallback values are strings
		}
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.w.Write(je.buf.Bytes())
	return err
}

// fallbackEntry builds the minimal ERROR record describing a marshal failure.
// It must never use the pooled attributes map (already returned to the pool
// by the caller's defer) and must never fail to encode: every value below is
// a plain string.
func (h *contractJSONHandler) fallbackEntry(r slog.Record, level string, cause error) *jsonEntry {
	msg := r.Message
	if len(msg) > 1024 {
		msg = msg[:1024] + "..."
	}
	return &jsonEntry{
		Time:    r.Time.In(h.timezone()).Format(time.RFC3339Nano),
		Level:   "ERROR",
		Message: "mebsuta: log record marshal failed; original message truncated below",
		Attributes: map[string]any{
			"original_level":   level,
			"original_message": msg,
			"marshal_error":    cause.Error(),
		},
	}
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
	// slog: WithGroup("") is a no-op — the previous code reset an existing
	// group to empty, releasing already-grouped attrs to the root namespace.
	if name == "" {
		return h
	}
	group := name
	if h.group != "" {
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
