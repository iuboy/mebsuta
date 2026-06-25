// Package mbta provides a slog.Handler that ships log records to a
// mebsuta-forwarder server via the MBTA binary transport protocol.
package mbta

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	mbtago "github.com/iuboy/mbta-go"
	"github.com/iuboy/mbta-go/core"
	v1 "github.com/iuboy/mbta-go/v1"

	"github.com/iuboy/mebsuta"
)

const (
	defaultBufferSize  = 1000
	defaultFlushPeriod = 5 * time.Second
	defaultBatchSize   = 100
	defaultMaxRetries  = 3
	defaultRetryDelay  = 1 * time.Second
	maxBufferSize      = 10000
	connectTimeout     = 10 * time.Second
)

// Handler ships log records to a mebsuta-forwarder via MBTA protocol.
// It implements slog.Handler, io.Closer, and mebsuta.SelfBufferedHandler.
type Handler struct {
	leveler      slog.Leveler
	cfg          Config
	client       *mbtago.Client
	buffer       chan *core.SignalRecord
	flushCh      chan chan struct{}
	wg           sync.WaitGroup
	ctx          context.Context
	cancel       context.CancelFunc
	closing      atomic.Bool
	errorHandler atomic.Pointer[mebsuta.ErrorHandler]
	hostname     string
}

// NewHandler creates a Handler that connects to the forwarder specified in cfg.
func NewHandler(cfg Config) (*Handler, error) {
	cfg, err := cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("mebsuta/mbta: %w", err)
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "localhost"
	}

	ctx, cancel := context.WithCancel(context.Background())

	bufferSize := min(cfg.BufferSize, maxBufferSize)

	// Dial: create client + connect in one step
	connectCtx, connectCancel := context.WithTimeout(ctx, connectTimeout)
	defer connectCancel()

	client, err := mbtago.Dial(connectCtx, cfg.Server, cfg.AgentID, cfg.Token, mbtago.Version1,
		mbtago.WithV1Credentials(v1.ClientCredentials{
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		}),
	)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("mebsuta/mbta: %w", err)
	}

	h := &Handler{
		leveler:  cfg.Level,
		cfg:      cfg,
		client:   client,
		buffer:   make(chan *core.SignalRecord, bufferSize),
		flushCh:  make(chan chan struct{}),
		ctx:      ctx,
		cancel:   cancel,
		hostname: hostname,
	}

	eh := mebsuta.DefaultErrorHandler
	h.errorHandler.Store(&eh)

	h.wg.Add(1)
	go h.processQueue()

	return h, nil
}

// Enabled implements slog.Handler.
func (h *Handler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.leveler.Level()
}

// Handle implements slog.Handler.
func (h *Handler) Handle(_ context.Context, r slog.Record) error {
	if h.closing.Load() {
		return nil
	}

	record := recordToSignal(r, h.hostname)
	return h.safeSend(record, r.Level)
}

// Close implements io.Closer.
func (h *Handler) Close() error {
	if !h.closing.CompareAndSwap(false, true) {
		return nil
	}

	close(h.buffer)
	h.wg.Wait()
	h.cancel()

	if h.client != nil {
		return h.client.Close()
	}
	return nil
}

// Flush drains all buffered records without closing the connection.
func (h *Handler) Flush(timeout time.Duration) error {
	if h.closing.Load() {
		return nil
	}
	done := make(chan struct{})
	select {
	case h.flushCh <- done:
	case <-time.After(timeout):
		return fmt.Errorf("mebsuta/mbta: flush timeout")
	}
	select {
	case <-done:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("mebsuta/mbta: flush timeout")
	}
}

// WithAttrs implements slog.Handler.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &mebsuta.AttrsSub{Parent: h, Attrs: attrs}
}

// WithGroup implements slog.Handler.
func (h *Handler) WithGroup(name string) slog.Handler {
	return &mebsuta.GroupSub{Parent: h, Group: name}
}

// SelfBuffered marks Handler as having built-in async buffering.
func (*Handler) SelfBuffered() {}

func (h *Handler) loadEH() mebsuta.ErrorHandler {
	v := h.errorHandler.Load()
	if v == nil {
		return nil
	}
	return *v
}

func (h *Handler) reportErr(op string, err error) {
	mebsuta.ReportError(h.loadEH(), &mebsuta.HandlerError{Component: "mbta", Operation: op, Err: err})
}

func (h *Handler) safeSend(record *core.SignalRecord, level slog.Level) error {
	defer func() {
		if r := recover(); r != nil {
			h.reportErr("send", fmt.Errorf("handler closed, log dropped"))
		}
	}()

	if h.closing.Load() {
		return fmt.Errorf("mebsuta/mbta: handler closed, log dropped")
	}

	if level >= slog.LevelError {
		select {
		case h.buffer <- record:
			return nil
		case <-time.After(5 * time.Second):
			h.reportErr("send", fmt.Errorf("buffer full timeout for %v record, dropped", level))
			return fmt.Errorf("mebsuta/mbta: buffer full timeout for %v record", level)
		}
	}

	select {
	case h.buffer <- record:
		return nil
	default:
		h.reportErr("send", fmt.Errorf("buffer full, log dropped"))
		return fmt.Errorf("mebsuta/mbta: buffer full")
	}
}

func (h *Handler) processQueue() {
	defer h.wg.Done()

	batch := make([]*core.SignalRecord, 0, h.cfg.BatchSize)
	ticker := time.NewTicker(h.cfg.FlushPeriod)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		h.sendBatch(batch)
		batch = batch[:0]
	}

	for {
		select {
		case record, ok := <-h.buffer:
			if !ok {
				flush()
				return
			}
			batch = append(batch, record)
			if len(batch) >= h.cfg.BatchSize {
				flush()
			}

		case <-ticker.C:
			flush()

		case done := <-h.flushCh:
			flush()
			close(done)

		case <-h.ctx.Done():
			flush()
			return
		}
	}
}

func (h *Handler) sendBatch(records []*core.SignalRecord) {
	signals := make([]*core.SignalRecord, len(records))
	copy(signals, records)

	batch := &core.SignalBatch{
		SchemaURL: "https://mebsuta.dev/schemas/v1/logs",
		Resource: core.Resource{
			Attributes: map[string]any{
				"host.name": h.hostname,
				"service":   h.cfg.Tag,
			},
		},
		Scope: core.Scope{
			Name:        "mebsuta",
			Version:     "mbta-handler",
			CollectorID: h.cfg.AgentID,
		},
		Signals: signals,
	}

	for attempt := range h.cfg.MaxRetries {
		_, err := h.client.SendBatch(h.ctx, batch, h.cfg.Tag, h.cfg.Source)
		if err == nil {
			return
		}

		if h.closing.Load() {
			return
		}

		h.reportErr("send_batch", fmt.Errorf("attempt %d/%d: %w", attempt+1, h.cfg.MaxRetries, err))

		if attempt < h.cfg.MaxRetries-1 {
			select {
			case <-time.After(h.cfg.RetryDelay):
			case <-h.ctx.Done():
				return
			}
		}
	}

	h.reportErr("send_batch", fmt.Errorf("failed after %d attempts, %d records dropped", h.cfg.MaxRetries, len(records)))
}

// recordToSignal converts a slog.Record into a core.SignalRecord.
func recordToSignal(r slog.Record, _ string) *core.SignalRecord {
	attrs := make(map[string]any)
	r.Attrs(func(attr slog.Attr) bool {
		attrs[attr.Key] = attrValue(attr)
		return true
	})

	severityText := r.Level.String()
	if r.Level == mebsuta.LevelAudit {
		severityText = "AUDIT"
	}

	return &core.SignalRecord{
		SignalType:     "log",
		EventID:        uuid.Must(uuid.NewV7()).String(),
		TimeUnixMs:     r.Time.UnixMilli(),
		ObservedTimeMs: time.Now().UnixMilli(),
		SeverityText:   severityText,
		Body:           r.Message,
		Attributes:     attrs,
	}
}

func attrValue(attr slog.Attr) any {
	v := attr.Value
	if v.Kind() == slog.KindGroup {
		group := v.Group()
		m := make(map[string]any, len(group))
		for _, a := range group {
			m[a.Key] = attrValue(a)
		}
		return m
	}
	return v.Any()
}

var (
	_ slog.Handler                = (*Handler)(nil)
	_ io.Closer                   = (*Handler)(nil)
	_ mebsuta.SelfBufferedHandler = (*Handler)(nil)
)

// UseMBTA is a convenience function that creates an MBTA handler and returns
// a mebsuta.HandlerOption for use with mebsuta.New().
//
// Usage:
//
//	logger, _ := mebsuta.New(
//	    mebsuta.UseStdout(mebsuta.StdoutConfig{}),
//	    mbta.UseMBTA(mbta.Config{Server: "localhost:7400", AgentID: "my-app"}),
//	)
func UseMBTA(cfg Config) (mebsuta.HandlerOption, error) {
	h, err := NewHandler(cfg)
	if err != nil {
		return nil, err
	}
	return mebsuta.WithHandler(h), nil
}
