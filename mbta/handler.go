// Package mbta provides a slog.Handler that ships log records to a
// mebsuta-forwarder server via the MBTA binary transport protocol.
package mbta

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
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
	defaultBufferSize   = 1000
	defaultFlushPeriod  = 5 * time.Second
	defaultBatchSize    = 100
	defaultMaxRetries   = 3
	defaultRetryDelay   = 1 * time.Second
	defaultCloseTimeout = 5 * time.Second
	maxBufferSize       = 10000
	connectTimeout      = 10 * time.Second

	// Attr budgets for recordToSignal, mirroring attrutil's JSON-path caps.
	maxAttrCount = 1024
	maxAttrDepth = 16

	// stateReady mirrors core.StateReady.String() from mbta-go, used to gate
	// reconnection attempts.
	stateReady = "READY"

	// defaultFlushTimeout is used when Flush is called with timeout <= 0.
	defaultFlushTimeout = 5 * time.Second
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

	hostname := sanitizeHostname(cfg.Hostname)
	if hostname == "" {
		hostname = "localhost"
	}

	ctx, cancel := context.WithCancel(context.Background())

	bufferSize := min(cfg.BufferSize, maxBufferSize)

	// Dial: create client + connect in one step
	connectCtx, connectCancel := context.WithTimeout(ctx, connectTimeout)
	defer connectCancel()

	// Propagate the full TLS credential set. Previously only InsecureSkipVerify
	// was forwarded, so CAFile/CertFile/KeyFile/ServerName silently never took
	// effect — leaving mTLS / custom CA / SNI configurations as no-ops.
	creds := v1.ClientCredentials{
		CAFile:             cfg.CAFile,
		CertFile:           cfg.CertFile,
		KeyFile:            cfg.KeyFile,
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}
	if cfg.InsecureSkipVerify {
		mebsuta.ReportError(mebsuta.DefaultErrorHandler, &mebsuta.HandlerError{Component: "mbta", Operation: "init", Err: fmt.Errorf("TLS certificate verification is disabled (InsecureSkipVerify=true) — connection is vulnerable to man-in-the-middle attacks")})
	}

	client, err := mbtago.Dial(connectCtx, cfg.Server, cfg.AgentID, cfg.Token, mbtago.Version1,
		mbtago.WithV1Credentials(creds),
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
	return level >= mebsuta.SafeLevel(h.leveler)
}

// Handle implements slog.Handler.
func (h *Handler) Handle(_ context.Context, r slog.Record) error {
	if h.closing.Load() {
		return nil
	}

	record := recordToSignal(r)
	return h.safeSend(record, r.Level)
}

// Close implements io.Closer.
//
// Drain BEFORE cancelling: processQueue's final flush (triggered by the
// closed channel) sends with h.ctx, and the previous cancel()-first order
// made mbta-go reject the send with context.Canceled — silently dropping
// every buffered record on shutdown.
func (h *Handler) Close() error {
	if !h.closing.CompareAndSwap(false, true) {
		return nil
	}

	close(h.buffer)
	h.wg.Wait()
	h.cancel()

	if h.client != nil {
		return h.closeClientBounded()
	}
	return nil
}

// closeClientBounded waits at most cfg.CloseTimeout for the mbta-go client's
// graceful close. The client's internal drain can block up to 30s even with
// nothing pending; an unbounded Close stalls shutdown until the orchestrator
// SIGKILLs the process (which loses the drain anyway).
func (h *Handler) closeClientBounded() error {
	done := make(chan error, 1)
	go func() { done <- h.client.Close() }()
	select {
	case err := <-done:
		return err
	case <-time.After(h.cfg.CloseTimeout):
		return fmt.Errorf("mebsuta/mbta: client close did not finish within %v (graceful drain abandoned; the underlying close continues in the background)", h.cfg.CloseTimeout)
	}
}

// Flush drains all buffered records without closing the connection.
func (h *Handler) Flush(timeout time.Duration) error {
	if h.closing.Load() {
		return nil
	}
	if timeout <= 0 {
		timeout = defaultFlushTimeout
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

// SetErrorHandler updates the error handler at runtime. It implements
// mebsuta.ErrorHandlerSetter so WithErrorHandler propagates into this
// handler; before it existed, SilentErrorHandler and custom hooks silently
// never reached mbta and its errors always went to stderr.
func (h *Handler) SetErrorHandler(fn mebsuta.ErrorHandler) {
	h.errorHandler.Store(&fn)
}

func (h *Handler) safeSend(record *core.SignalRecord, level slog.Level) (err error) {
	// Named return: the recover branch must set err — with a bare return the
	// caller saw nil and the drop vanished silently.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("mebsuta/mbta: handler closed, log dropped")
			h.reportErr("send", err)
		}
	}()

	if h.closing.Load() {
		return fmt.Errorf("mebsuta/mbta: handler closed, log dropped")
	}

	if level >= slog.LevelError {
		select {
		case h.buffer <- record:
			return nil
		case <-time.After(h.cfg.ErrorTimeout):
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
			// mbta-go v0.6.0 removed the per-call tag/source parameters:
			// the metadata now lives in the batch resource attributes.
			Attributes: map[string]any{
				"host.name": h.hostname,
				"service":   h.cfg.Tag,
				"source":    h.cfg.Source,
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
		_, err := h.client.SendBatch(h.ctx, batch)
		if err == nil {
			return
		}

		// Gate on the context, not the closing flag: during Close's final
		// flush the ctx is live and retries must proceed, while cancel()
		// (which happens strictly after the drain finished) must abort them.
		if h.ctx.Err() != nil {
			h.reportErr("send_batch", fmt.Errorf("handler stopped, %d records dropped", len(records)))
			return
		}

		h.reportErr("send_batch", fmt.Errorf("attempt %d/%d: %w", attempt+1, h.cfg.MaxRetries, err))

		if attempt < h.cfg.MaxRetries-1 {
			// Config.Reconnect: re-dial when the session dropped out of
			// READY. mbta-go never reconnects on its own — without this the
			// handler kept failing every batch until process restart.
			if h.reconnectEnabled() && h.client.State() != stateReady {
				h.tryReconnect()
			}
			select {
			case <-time.After(h.cfg.RetryDelay):
			case <-h.ctx.Done():
				return
			}
		}
	}

	h.reportErr("send_batch", fmt.Errorf("failed after %d attempts, %d records dropped", h.cfg.MaxRetries, len(records)))
}

func (h *Handler) reconnectEnabled() bool {
	return h.cfg.Reconnect != nil && *h.cfg.Reconnect
}

// tryReconnect re-dials the forwarder with a bounded context. Failures are
// reported and swallowed — the retry loop decides whether to keep going.
func (h *Handler) tryReconnect() {
	if h.ctx.Err() != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	if err := h.client.Connect(ctx); err != nil {
		h.reportErr("reconnect", fmt.Errorf("reconnect failed: %w", err))
	}
}

// recordToSignal converts a slog.Record into a core.SignalRecord.
func recordToSignal(r slog.Record) *core.SignalRecord {
	attrs := make(map[string]any)
	r.Attrs(func(attr slog.Attr) bool {
		// Budgets mirror attrutil's JSON-path caps: without them a single
		// record carrying a huge payload bloats every batch.
		if attr.Key == "" || len(attrs) >= maxAttrCount {
			return true
		}
		attrs[attr.Key] = attrValue(attr, 0)
		return true
	})

	severityText := r.Level.String()
	if r.Level == mebsuta.LevelAudit {
		severityText = "AUDIT"
	}

	// Never panic on the log hot path. uuid.NewV7 can only fail if the system
	// PRNG is unavailable; in that case fall back to a deterministic,
	// collision-resistant ID derived from the record timestamp rather than
	// crashing the caller's slog.Info call.
	eventID := newEventID(r.Time.UnixNano())

	return &core.SignalRecord{
		SignalType:     "log",
		EventID:        eventID,
		TimeUnixMs:     r.Time.UnixMilli(),
		ObservedTimeMs: time.Now().UnixMilli(),
		SeverityText:   severityText,
		SeverityNumber: severityNumber(r.Level),
		Body:           r.Message,
		Attributes:     attrs,
	}
}

// severityNumber maps slog levels onto the OTel-style numeric severity scale
// so downstream consumers filtering on SeverityNumber (not text) work; it was
// previously always 0 regardless of level.
func severityNumber(level slog.Level) int {
	switch {
	case level >= mebsuta.LevelAudit:
		return 21 // FATAL band; LevelAudit sits above Error
	case level >= slog.LevelError:
		return 17
	case level >= slog.LevelWarn:
		return 13
	case level >= slog.LevelInfo:
		return 9
	default:
		return 5 // DEBUG band
	}
}

// sanitizeHostname reduces the hostname (static or system) to the
// [a-zA-Z0-9.-] alphabet so it cannot carry control characters or other
// injection into the resource attributes.
func sanitizeHostname(static string) string {
	if static == "" {
		static, _ = os.Hostname()
	}
	var b strings.Builder
	b.Grow(len(static))
	for _, r := range static {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
		if b.Len() >= 255 {
			break
		}
	}
	return b.String()
}

// newEventID returns a UUIDv7 string, falling back to a timestamp-derived ID
// when UUID generation fails so the log path can never panic.
func newEventID(fallbackSeed int64) string {
	if id, err := uuid.NewV7(); err == nil {
		return id.String()
	}
	// Fallback: deterministic, monotonic, non-zero. Collisions are practically
	// impossible for fallback-only operation under PRNG failure.
	//
	// Layout follows UUIDv7: 8-4-4-4-12 hex. Group 3 is "7" + 12 bits (version
	// 7). Group 4 is the RFC 4122 variant field: the high nibble is 0x8|2bits
	// (so it starts with 8/9/a/b) packed with 12 bits of data into exactly 4
	// hex chars. The previous "%x%04x" form emitted a variable-width variant
	// nibble followed by 4 fixed chars, producing a 5-char group and a
	// 37-char (non-UUID) string.
	seed := uint64(fallbackSeed)
	return fmt.Sprintf("00000000-0000-7%03x-%04x-%012x",
		(seed>>40)&0xfff,           // group 3: 12 bits after the version nibble
		0x8000|((seed>>24)&0x0fff), // group 4: variant nibble (8) + 12 data bits
		seed&0xffffffffffff)        // group 5: 48 bits
}

func attrValue(attr slog.Attr, depth int) any {
	if depth > maxAttrDepth {
		return nil
	}
	// slog contract: handlers must resolve LogValuer values. Unresolved
	// values leak their backing structs into the encoder, which renders them
	// via fmt as internal Go representations (or pointer addresses).
	v := attr.Value.Resolve()
	if v.Kind() == slog.KindGroup {
		group := v.Group()
		m := make(map[string]any, len(group))
		for _, a := range group {
			m[a.Key] = attrValue(a, depth+1)
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
