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

	"github.com/iuboy/mebsuta/internal/attrutil"
	"github.com/iuboy/mebsuta/internal/textutil"
)

// attrMapPool 在多次 Handle 调用间回收 map[string]any，降低 GC 压力。
var attrMapPool = sync.Pool{
	New: func() any { return make(map[string]any, 16) },
}

// jsonEncoder 把缓冲区与绑定其上的编码器捆绑在一起。对这一对做池化，
// 既让编码+换行发生在 handler 互斥锁之外（并行序列化、仅串行写入），
// 又避免了每条记录一次 Marshal 分配和 append(data, '\n') 的扩容
// ——json.Encoder 原生追加换行。
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

// contractJSONHandler 产出稳定契约的 JSON 输出：{"time","level","message","attributes"}。
// 用它替代 slog.JSONHandler，以强制输出 schema 并处理 NaN/Inf 浮点。
type contractJSONHandler struct {
	mu    *sync.Mutex
	w     io.Writer
	attrs []slog.Attr
	group string
	loc   *time.Location // 日志时间展示时区，nil 时用 UTC
}

// jsonEntry 是日志记录的 JSON 输出结构。
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

// newContractJSONHandler 返回向 w 写稳定契约 JSON 的 slog.Handler。
// loc 控制 "time" 字段的时区；nil 默认 UTC。
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

// promoteField 在 key 尚未被认领且 attributes[key] 恰为类型 T 时取出
// 该值并从 map 移除；此后对已认领字段的调用都是 no-op，预设值正是
// 这样在与 AUDIT 记录属性冲突时保持权威。类型不匹配则原位保留
// （留作证据）。返回 ok=false 表示本次没有可提升的值。string 与
// *bool 两个目标形态由同一泛型实现（后者经 &v 装箱）。
func promoteField[T any](attributes map[string]any, key string, claimed *bool) (T, bool) {
	var zero T
	if *claimed {
		return zero, false
	}
	v, ok := attributes[key].(T)
	if ok {
		*claimed = true
		delete(attributes, key)
	}
	return v, ok
}

func (h *contractJSONHandler) Handle(_ context.Context, r slog.Record) error {
	attributes := getAttrMap()
	defer putAttrMap(attributes)

	eventType, actor, success := "", "", (*bool)(nil)

	// 对每条记录都从预设属性（logger 构造时经 WithAttrs 设置）提升审计
	// 契约字段；AUDIT 级别记录额外从记录属性提升。级别是信任锚：记录
	// 只会经审计调用点（audit.AuditEvent 等）达到 AUDIT 严重级，因此其
	// 记录属性可信地携带 event_type/actor/success。非 AUDIT 记录的记录
	// 级键保留在 "attributes" 内：若允许普通日志点上的逐调用属性提升，
	// 任何一行 INFO 都能覆盖可信的 actor/event_type/success——借键冲
	// 突伪造审计。冲突时预设值胜出；冲突的记录值留在 attributes 内作
	// 为证据。
	truncated := false
	for _, attr := range h.attrs {
		if attrutil.FlattenAttrMarked(attributes, "", attr, attrutil.NaNSafe) {
			truncated = true
		}
	}
	var etClaimed, acClaimed, scClaimed bool
	if v, ok := promoteField[string](attributes, "event_type", &etClaimed); ok {
		eventType = v
	}
	if v, ok := promoteField[string](attributes, "actor", &acClaimed); ok {
		actor = v
	}
	if v, ok := promoteField[bool](attributes, "success", &scClaimed); ok {
		success = &v
	}

	// 记录属性落入 attributes；AUDIT 级别记录可随后从中提升。非 AUDIT
	// 记录上冲突的键会覆盖属性 map 条目，但永远到不了被提升的顶层
	// 字段。
	r.Attrs(func(attr slog.Attr) bool {
		if attrutil.FlattenAttrMarked(attributes, h.group, attr, attrutil.NaNSafe) {
			truncated = true
		}
		return true
	})
	if r.Level == LevelAudit {
		// 已认领的字段被跳过：预设值保持权威，冲突的记录值留在
		// attributes 内。
		if v, ok := promoteField[string](attributes, "event_type", &etClaimed); ok {
			eventType = v
		}
		if v, ok := promoteField[string](attributes, "actor", &acClaimed); ok {
			actor = v
		}
		if v, ok := promoteField[bool](attributes, "success", &scClaimed); ok {
			success = &v
		}
	}

	// 规范文本名称唯一映射(B7):AUDIT 此前在内联判断里渲染,现统一走
	// LevelName,与 console/syslog/mbta/otlp 同源。
	level := LevelName(r.Level)

	// 保留的省略标记（与 syslog handler 的 _truncated PARAM-NAME 对应）：
	// 某属性被数量/深度上限丢弃或某键被长度上限截断，attributes 因此不
	// 完整。发生截断时，用户恰好命名为 _truncated 的属性会被覆盖
	// ——标记胜出，消费方才能信任它作为完整性信号。
	if truncated {
		attributes["_truncated"] = true
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
		// NaNSafe 只净化顶层浮点；藏在嵌套 map 或结构体中的
		// NaN/chan/func 仍会在此让编码失败。返回错误会静默丢弃整条
		// 记录（slog.Logger 忽略 Handle 错误）——改为降级为回退记录，
		// 让审计痕迹保留丢失内容及其原因的痕迹。
		je.buf.Reset()
		// 回退记录携带原级别与已提升的审计契约字段(B6):AUDIT 记录
		// 序列化失败时此前被降级为普通 ERROR 且丢掉 event_type/actor/
		// success——合规消费方会漏掉这次审计事件。
		if encErr := je.enc.Encode(h.fallbackEntry(r, level, eventType, actor, success, err)); encErr != nil {
			return err // 真正不可达：所有回退值都是字符串
		}
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.w.Write(je.buf.Bytes())
	return err
}

// fallbackEntry 构建描述序列化失败的最小记录。它保留原级别与已提升
// 的审计契约字段(B6)——AUDIT 记录不得因序列化失败被降级为普通
// ERROR。它绝不能使用池化的 attributes map（已被调用方的 defer 归还
// 池中），也绝不能编码失败：下面每个值都是纯字符串。
func (h *contractJSONHandler) fallbackEntry(r slog.Record, level, eventType, actor string, success *bool, cause error) *jsonEntry {
	// UTF-8 安全截断:裸 msg[:1024] 会切开多字节 rune,残缺字节经
	// encoding/json 变成 U+FFFD。textutil 与 database/syslog 共用同一
	// 截断口径(含 "..." 标记,总长不超预算)。
	msg := textutil.TruncateUTF8(r.Message, 1024)
	return &jsonEntry{
		Time:      r.Time.In(h.timezone()).Format(time.RFC3339Nano),
		Level:     level,
		EventType: eventType,
		Message:   "mebsuta: log record marshal failed; original message truncated below",
		Actor:     actor,
		Success:   success,
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
	// slog：WithGroup("") 是 no-op——旧代码会把已有 group 重置为空，
	// 把已分组的属性放回根命名空间。
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

// prefixAttr 在 group 与属性键都非空时，向键前加上 group 前缀。
func prefixAttr(group string, attr slog.Attr) slog.Attr {
	if group == "" || attr.Key == "" {
		return attr
	}
	attr.Key = group + "." + attr.Key
	return attr
}

var _ slog.Handler = (*contractJSONHandler)(nil)
