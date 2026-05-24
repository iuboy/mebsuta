package mebsuta

import (
	"context"
	"log/slog"
)

// AttrsSub is a generic sub-handler for WithAttrs/WithGroup chains, eliminating duplicate sub-types across handlers.
type AttrsSub[H slog.Handler] struct {
	Parent H
	Attrs  []slog.Attr
	Group  string
}

func (h *AttrsSub[H]) Enabled(ctx context.Context, level slog.Level) bool {
	return h.Parent.Enabled(ctx, level)
}

func (h *AttrsSub[H]) Handle(ctx context.Context, r slog.Record) error {
	if h.Group != "" {
		return h.Parent.Handle(ctx, RecordWithGroupAttrs(r, h.Group, h.Attrs))
	}
	r.AddAttrs(h.Attrs...)
	return h.Parent.Handle(ctx, r)
}

func (h *AttrsSub[H]) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &AttrsSub[H]{
		Parent: h.Parent,
		Attrs:  MergeAttrs(h.Attrs, attrs, h.Group),
		Group:  h.Group,
	}
}

func (h *AttrsSub[H]) WithGroup(name string) slog.Handler {
	return &GroupSub[H]{
		Parent: h.Parent,
		Group:  name,
		Attrs:  h.Attrs,
	}
}

func (h *AttrsSub[H]) unwrapHandler() slog.Handler {
	return h.Parent
}

var _ handlerUnwrapper = (*AttrsSub[*FileHandler])(nil)

// GroupSub is a generic sub-handler for WithGroup chains, prefixing all record attrs with the group name before forwarding to the parent.
type GroupSub[H slog.Handler] struct {
	Parent H
	Group  string
	Attrs  []slog.Attr
}

func (h *GroupSub[H]) Enabled(ctx context.Context, level slog.Level) bool {
	return h.Parent.Enabled(ctx, level)
}

func (h *GroupSub[H]) Handle(ctx context.Context, r slog.Record) error {
	return h.Parent.Handle(ctx, RecordWithGroupAttrs(r, h.Group, h.Attrs))
}

func (h *GroupSub[H]) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &AttrsSub[H]{
		Parent: h.Parent,
		Attrs:  MergeAttrs(h.Attrs, attrs, h.Group),
		Group:  h.Group,
	}
}

func (h *GroupSub[H]) WithGroup(name string) slog.Handler {
	return &GroupSub[H]{
		Parent: h.Parent,
		Group:  h.Group + "." + name,
		Attrs:  h.Attrs,
	}
}

func (h *GroupSub[H]) unwrapHandler() slog.Handler {
	return h.Parent
}

var _ handlerUnwrapper = (*GroupSub[*FileHandler])(nil)
