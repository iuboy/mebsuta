package handlerkit

import (
	"context"
	"log/slog"
)

// AttrsSub 是 WithAttrs/WithGroup 链的子 handler，消除各 handler 间重复的子类型。
// 此前从根包导出(仅因 database/syslog/mbta 需要它);现归属 internal 实现缝。
type AttrsSub struct {
	Parent slog.Handler
	Attrs  []slog.Attr
	Group  string
}

func (h *AttrsSub) Enabled(ctx context.Context, level slog.Level) bool {
	return h.Parent.Enabled(ctx, level)
}

func (h *AttrsSub) Handle(ctx context.Context, r slog.Record) error {
	if h.Group != "" {
		return h.Parent.Handle(ctx, RecordWithGroupAttrs(r, h.Group, h.Attrs))
	}
	// M1：AddAttrs 前先克隆，避免修改调用方的记录。
	// 单 handler 的 fanout 路径未克隆地传递原始记录，而 slog 契约
	// 禁止 handler 修改记录。
	newR := r.Clone()
	newR.AddAttrs(h.Attrs...)
	return h.Parent.Handle(ctx, newR)
}

func (h *AttrsSub) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &AttrsSub{
		Parent: h.Parent,
		Attrs:  MergeAttrs(h.Attrs, attrs, h.Group),
		Group:  h.Group,
	}
}

func (h *AttrsSub) WithGroup(name string) slog.Handler {
	// name 为空时，按 slog 规范 WithGroup 是 no-op：原样返回当前
	// handler。
	if name == "" {
		return h
	}
	// 将已有 group 与新 group 名拼接，与 GroupSub.WithGroup 一致。
	group := name
	if h.Group != "" {
		group = h.Group + "." + name
	}
	return &GroupSub{
		Parent: h.Parent,
		Group:  group,
		Attrs:  h.Attrs,
	}
}

func (h *AttrsSub) UnwrapHandler() slog.Handler {
	return h.Parent
}

// GroupSub 是 WithGroup 链的子 handler，转发给父级前为所有记录属性加 group 名前缀。
type GroupSub struct {
	Parent slog.Handler
	Group  string
	Attrs  []slog.Attr
}

func (h *GroupSub) Enabled(ctx context.Context, level slog.Level) bool {
	return h.Parent.Enabled(ctx, level)
}

func (h *GroupSub) Handle(ctx context.Context, r slog.Record) error {
	return h.Parent.Handle(ctx, RecordWithGroupAttrs(r, h.Group, h.Attrs))
}

func (h *GroupSub) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &AttrsSub{
		Parent: h.Parent,
		Attrs:  MergeAttrs(h.Attrs, attrs, h.Group),
		Group:  h.Group,
	}
}

func (h *GroupSub) WithGroup(name string) slog.Handler {
	// M2：slog 中 WithGroup("") 是 no-op——不要追加尾点。
	group := h.Group
	if name != "" {
		if group != "" {
			group += "."
		}
		group += name
	}
	return &GroupSub{
		Parent: h.Parent,
		Group:  group,
		Attrs:  h.Attrs,
	}
}

func (h *GroupSub) UnwrapHandler() slog.Handler {
	return h.Parent
}

// prefixAttrs 为每个属性的键加上 "group." 前缀。group 为空时原样返回 attrs。
func prefixAttrs(group string, attrs []slog.Attr) []slog.Attr {
	if group == "" {
		return attrs
	}
	out := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		out[i] = slog.Attr{Key: group + "." + a.Key, Value: a.Value}
	}
	return out
}

// MergeAttrs 合并 existing 与 newAttrs，并为 newAttrs 的键加给定 group 前缀。
func MergeAttrs(existing, newAttrs []slog.Attr, group string) []slog.Attr {
	merged := make([]slog.Attr, len(existing), len(existing)+len(newAttrs))
	copy(merged, existing)
	merged = append(merged, prefixAttrs(group, newAttrs)...)
	return merged
}

// RecordWithGroupAttrs 用原记录的属性加 group 前缀，再叠加 extraAttrs，
// 创建新的 slog.Record。extraAttrs 假定已带 group 前缀（构造时由
// MergeAttrs 生成）。记录属性的前缀语义与 prefixAttrs 一致：group 为空
// 时属性原样透传；否则为每个记录属性键前加 "group."。
func RecordWithGroupAttrs(r slog.Record, group string, extraAttrs []slog.Attr) slog.Record {
	newR := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	if group == "" {
		r.Attrs(func(attr slog.Attr) bool {
			newR.AddAttrs(attr)
			return true
		})
	} else {
		r.Attrs(func(attr slog.Attr) bool {
			newR.AddAttrs(slog.Attr{Key: group + "." + attr.Key, Value: attr.Value})
			return true
		})
	}
	newR.AddAttrs(extraAttrs...)
	return newR
}
