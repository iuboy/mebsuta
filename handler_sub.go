package mebsuta

import (
	"context"
	"log/slog"
)

// AttrsSub is a sub-handler for WithAttrs/WithGroup chains, eliminating duplicate sub-types across handlers.
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
	r.AddAttrs(h.Attrs...)
	return h.Parent.Handle(ctx, r)
}

func (h *AttrsSub) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &AttrsSub{
		Parent: h.Parent,
		Attrs:  MergeAttrs(h.Attrs, attrs, h.Group),
		Group:  h.Group,
	}
}

func (h *AttrsSub) WithGroup(name string) slog.Handler {
	return &GroupSub{
		Parent: h.Parent,
		Group:  name,
		Attrs:  h.Attrs,
	}
}

func (h *AttrsSub) unwrapHandler() slog.Handler {
	return h.Parent
}

var _ handlerUnwrapper = (*AttrsSub)(nil)

// GroupSub is a sub-handler for WithGroup chains, prefixing all record attrs with the group name before forwarding to the parent.
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
	return &GroupSub{
		Parent: h.Parent,
		Group:  h.Group + "." + name,
		Attrs:  h.Attrs,
	}
}

func (h *GroupSub) unwrapHandler() slog.Handler {
	return h.Parent
}

var _ handlerUnwrapper = (*GroupSub)(nil)
