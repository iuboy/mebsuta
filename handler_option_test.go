package mebsuta

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// =============================================================================
// HandlerError tests
// =============================================================================

func TestHandlerError_Unwrap(t *testing.T) {
	inner := errors.New("inner error")
	he := HandlerError{Err: inner}
	require.Equal(t, inner, he.Unwrap())
}

func TestHandlerError_Error(t *testing.T) {
	inner := errors.New("something failed")
	he := HandlerError{Component: "file", Operation: "write", Err: inner}
	require.Equal(t, "mebsuta/file/write: something failed", he.Error())
}

func TestHandlerError_Fields(t *testing.T) {
	now := time.Now()
	he := HandlerError{
		Err:       errors.New("write failed"),
		Dropped:   42,
		Retryable: true,
		Records:   7,
		Time:      now,
	}
	require.Equal(t, int64(42), he.Dropped)
	require.True(t, he.Retryable)
	require.Equal(t, 7, he.Records)
	require.True(t, he.Time.Equal(now))
}

func TestHandlerError_ErrorsIs(t *testing.T) {
	inner := errors.New("base")
	he := HandlerError{Err: inner}
	require.True(t, errors.Is(&he, inner))
}

func TestHandlerError_ErrorsAs(t *testing.T) {
	inner := errors.New("base")
	he := &HandlerError{
		Component: "file",
		Operation: "rotate",
		Err:       inner,
	}
	var target *HandlerError
	require.True(t, errors.As(he, &target))
	require.Equal(t, "file", target.Component)
	require.Equal(t, "rotate", target.Operation)
}

// =============================================================================
// ErrorHandler factory tests
// =============================================================================

func TestLogErrorHandler(t *testing.T) {
	var buf bytes.Buffer
	eh := LogErrorHandler(&buf)
	eh(HandlerError{
		Component: "file",
		Operation: "write",
		Err:       errors.New("disk full"),
	})
	got := buf.String()
	require.Contains(t, got, "mebsuta/file/write: disk full")
}

func TestSilentErrorHandler(t *testing.T) {
	eh := SilentErrorHandler()
	// Should not panic and should not write anywhere
	eh(HandlerError{
		Component: "file",
		Operation: "write",
		Err:       errors.New("should be discarded"),
	})
}

// =============================================================================
// New() pipeline tests
// =============================================================================

func TestNew_ZeroOptions(t *testing.T) {
	logger, err := New()
	require.NoError(t, err)
	require.NotNil(t, logger)

	// Default is stdout JSON handler; verify the handler is a StdoutHandler
	_, ok := logger.Handler().(*StdoutHandler)
	require.True(t, ok, "expected StdoutHandler, got %T", logger.Handler())
}

func TestNew_UseFile(t *testing.T) {
	path := t.TempDir() + "/test.log"
	logger, err := New(UseFile(FileConfig{Path: path}))
	require.NoError(t, err)
	require.NotNil(t, logger)

	logger.Info("hello from file")
	require.NoError(t, CloseAll(logger.Handler()))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(data), "hello from file")
}

func TestNew_UseFileWithAsync(t *testing.T) {
	path := t.TempDir() + "/test.log"
	logger, err := New(
		UseFile(FileConfig{Path: path}),
		UseAsync(AsyncConfig{BufferSize: 64}),
	)
	require.NoError(t, err)
	require.NotNil(t, logger)

	logger.Info("async file message")
	require.NoError(t, CloseAll(logger.Handler()))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(data), "async file message")

	// Verify the handler chain: outer should be AsyncHandler wrapping FileHandler
	h := logger.Handler()
	_, ok := h.(*AsyncHandler)
	require.True(t, ok, "expected AsyncHandler as outermost, got %T", h)
}

func TestNew_UseFileWithAsyncAndSampling(t *testing.T) {
	path := t.TempDir() + "/test.log"
	logger, err := New(
		UseFile(FileConfig{Path: path}),
		UseAsync(AsyncConfig{BufferSize: 64}),
		UseSampling(SamplingConfig{
			Enabled:    true,
			Initial:    100,
			Thereafter: 10,
			Window:     time.Second,
		}),
	)
	require.NoError(t, err)
	require.NotNil(t, logger)

	// Write enough records that sampling would kick in if misconfigured
	for i := range 20 {
		logger.Info("sampled message", "i", i)
	}
	require.NoError(t, CloseAll(logger.Handler()))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	lines := strings.Count(string(data), "\n")
	require.Equal(t, 20, lines, "Initial=100 means all 20 should pass through sampling")
}

func TestNew_UseFileInvalidConfig(t *testing.T) {
	// Empty path should fail validation
	_, err := New(UseFile(FileConfig{Path: ""}))
	require.Error(t, err)
	require.Contains(t, err.Error(), "file path is required")
}

func TestNew_MultipleUseFile_CreatesFanout(t *testing.T) {
	dir := t.TempDir()
	path1 := dir + "/app1.log"
	path2 := dir + "/app2.log"

	logger, err := New(
		UseFile(FileConfig{Path: path1}),
		UseFile(FileConfig{Path: path2}),
	)
	require.NoError(t, err)
	require.NotNil(t, logger)

	logger.Info("fanout message", "key", "value")
	require.NoError(t, CloseAll(logger.Handler()))

	// Both files should contain the message
	data1, err := os.ReadFile(path1)
	require.NoError(t, err)
	require.Contains(t, string(data1), "fanout message")

	data2, err := os.ReadFile(path2)
	require.NoError(t, err)
	require.Contains(t, string(data2), "fanout message")

	// The handler should be a safeMulti (fanout)
	_, ok := logger.Handler().(*safeMulti)
	require.True(t, ok, "expected safeMulti for multiple UseFile, got %T", logger.Handler())
}
