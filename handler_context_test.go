package mebsuta

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestWithContextExtractor_WithGroup verifies extracted attrs are prefixed with group.
func TestWithContextExtractor_WithGroup(t *testing.T) {
	var buf bytes.Buffer
	inner, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelDebug})
	require.NoError(t, err)

	h := WithContextExtractor(inner, func(ctx context.Context) []slog.Attr {
		return []slog.Attr{slog.String("trace_id", "abc123")}
	})
	grouped := h.WithGroup("request")

	logger := slog.New(grouped)
	logger.Info("test")

	output := buf.String()
	require.Contains(t, output, "request.trace_id")
	require.Contains(t, output, "abc123")
}

// TestWithContextExtractor_NestedGroups verifies nested WithGroup chains prefix correctly.
func TestWithContextExtractor_NestedGroups(t *testing.T) {
	var buf bytes.Buffer
	inner, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelDebug})
	require.NoError(t, err)

	h := WithContextExtractor(inner, func(ctx context.Context) []slog.Attr {
		return []slog.Attr{slog.String("trace_id", "xyz")}
	})
	nested := h.WithGroup("http").WithGroup("request")

	logger := slog.New(nested)
	logger.Info("test")

	output := buf.String()
	require.Contains(t, output, "http.request.trace_id")
}

// TestWithContextExtractor_WithGroupThenAttrs verifies WithGroup + WithAttrs chain.
func TestWithContextExtractor_WithGroupThenAttrs(t *testing.T) {
	var buf bytes.Buffer
	inner, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelDebug})
	require.NoError(t, err)

	h := WithContextExtractor(inner, func(ctx context.Context) []slog.Attr {
		return []slog.Attr{slog.String("trace_id", "t1")}
	})
	child := h.WithGroup("req").WithAttrs([]slog.Attr{slog.String("method", "GET")})

	logger := slog.New(child)
	logger.Info("test")

	output := buf.String()
	require.Contains(t, output, "req.trace_id")
	require.Contains(t, output, "req.method")
}

// TestWithContextExtractor_EmptyGroupPassesThrough verifies no group = no prefix.
func TestWithContextExtractor_EmptyGroupPassesThrough(t *testing.T) {
	var buf bytes.Buffer
	inner, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelDebug})
	require.NoError(t, err)

	h := WithContextExtractor(inner, func(ctx context.Context) []slog.Attr {
		return []slog.Attr{slog.String("plain", "val")}
	})

	logger := slog.New(h)
	logger.Info("test")

	output := buf.String()
	require.Contains(t, output, `"plain"`)
	require.Contains(t, output, `"val"`)
}

// TestWithContextExtractor_ContextPropagation verifies context is passed to extractor.
func TestWithContextExtractor_ContextPropagation(t *testing.T) {
	var buf bytes.Buffer
	inner, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelDebug})
	require.NoError(t, err)

	h := WithContextExtractor(inner, func(ctx context.Context) []slog.Attr {
		if v, ok := ctx.Value(ctxKey("tenant")).(string); ok {
			return []slog.Attr{slog.String("tenant", v)}
		}
		return nil
	})

	logger := slog.New(h)
	ctx := context.WithValue(context.Background(), ctxKey("tenant"), "acme")
	logger.InfoContext(ctx, "routed")

	require.Contains(t, buf.String(), "acme")
}

// TestUseContextExtractor_Option verifies the Option integrates with New().
func TestUseContextExtractor_Option(t *testing.T) {
	extract := func(ctx context.Context) []slog.Attr {
		return []slog.Attr{slog.String("request_id", "req-001")}
	}

	logger, err := New(UseContextExtractor(extract))
	require.NoError(t, err)
	require.NotNil(t, logger)
}

// TestUseContextExtractor_OptionWithGroup verifies UseContextExtractor + WithGroup in pipeline.
func TestUseContextExtractor_OptionWithGroup(t *testing.T) {
	var buf bytes.Buffer

	extract := func(ctx context.Context) []slog.Attr {
		return []slog.Attr{slog.String("trace_id", "from-ctx")}
	}

	inner, err := newStdoutHandlerWithWriter(&buf, StdoutConfig{Level: slog.LevelDebug})
	require.NoError(t, err)

	logger, err := New(
		UseContextExtractor(extract),
		WithHandler(inner),
	)
	require.NoError(t, err)

	grouped := logger.WithGroup("http")
	grouped.Info("grouped request")

	output := buf.String()
	require.Contains(t, output, "http.trace_id")
}

// TestJoinGroup verifies joinGroup concatenation.
func TestJoinGroup(t *testing.T) {
	require.Equal(t, "", joinGroup("", ""))
	require.Equal(t, "a", joinGroup("", "a"))
	require.Equal(t, "a", joinGroup("a", ""))
	require.Equal(t, "a.b", joinGroup("a", "b"))
	require.Equal(t, "a.b.c", joinGroup("a.b", "c"))
}

// TestWithContextExtractor_UnwrapHandler verifies handlerUnwrapper is implemented.
func TestWithContextExtractor_UnwrapHandler(t *testing.T) {
	inner, err := NewStdoutHandler(StdoutConfig{})
	require.NoError(t, err)
	h := WithContextExtractor(inner, func(ctx context.Context) []slog.Attr { return nil })
	uw, ok := h.(handlerUnwrapper)
	require.True(t, ok, "should implement handlerUnwrapper")
	require.Equal(t, inner, uw.unwrapHandler())
}

// TestWithContextExtractor_EmptyGroupNoMutation verifies that when group is "",
// the original Record is not mutated in a way that leaks attrs to the next call.
func TestWithContextExtractor_EmptyGroupNoMutation(t *testing.T) {
	var called int
	var capturedAttrs []slog.Attr
	inner := &captureAttrsHandler{fn: func(attrs []slog.Attr) {
		called++
		capturedAttrs = attrs
	}}

	h := WithContextExtractor(inner, func(ctx context.Context) []slog.Attr {
		return []slog.Attr{slog.String("ctx_key", "ctx_val")}
	})

	logger := slog.New(h)
	logger.Info("first")
	logger.Info("second")

	if called != 2 {
		t.Fatalf("expected 2 calls, got %d", called)
	}
	// Each call should have exactly 1 extracted attr
	count := 0
	for _, a := range capturedAttrs {
		if a.Key == "ctx_key" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 ctx_key attr in last call, got %d", count)
	}
}

type captureAttrsHandler struct {
	fn func(attrs []slog.Attr)
}

func (h *captureAttrsHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureAttrsHandler) Handle(_ context.Context, r slog.Record) error {
	r.Attrs(func(a slog.Attr) bool {
		h.fn([]slog.Attr{a})
		return true
	})
	return nil
}
func (h *captureAttrsHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureAttrsHandler) WithGroup(string) slog.Handler      { return h }
