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
	// M1: clone before AddAttrs to avoid mutating the caller's record.
	// The single-handler fan-out path passes the original record un-cloned,
	// and slog's contract forbids handlers from modifying the record.
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
	// H4: mirror GroupSub.WithGroup's concatenation. Without this,
	// WithGroup("a").WithAttrs(...).WithGroup("b") yields group "b"
	// instead of "a.b", breaking the slog group nesting contract.
	group := name
	if h.Group != "" && name != "" {
		group = h.Group + "." + name
	}
	return &GroupSub{
		Parent: h.Parent,
		Group:  group,
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
	// M2: WithGroup("") is a no-op in slog — don't append a trailing dot.
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

func (h *GroupSub) unwrapHandler() slog.Handler {
	return h.Parent
}

var _ handlerUnwrapper = (*GroupSub)(nil)
