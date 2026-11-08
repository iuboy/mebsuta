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
	"unicode/utf8"

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

	// maxAttrDepth caps group flattening recursion in recordToSignal, mirroring
	// attrutil's depth cap. Values beyond it render as "<max-depth>".
	maxAttrDepth = 16

	// stateReady mirrors core.StateReady.String() from mbta-go, used to gate
	// reconnection attempts.
	stateReady = "READY"

	// RESULT level strings as delivered to mbta-go's ResultHandler: the
	// corepb.ResultLevel enum names plus the client's synthetic "timeout"
	// (internal/protocol fires it when an in-flight slot expires with no
	// terminal RESULT).
	resultLevelRejected = "RESULT_LEVEL_REJECTED"
	resultLevelReleased = "RESULT_LEVEL_RELEASED"
	resultLevelTimeout  = "timeout"

	// defaultFlushTimeout is used when Flush is called with timeout <= 0.
	defaultFlushTimeout = 5 * time.Second
)

// Handler ships log records to a mebsuta-forwarder via MBTA protocol.
// It implements slog.Handler, io.Closer, and mebsuta.SelfBufferedHandler.
type Handler struct {
	leveler slog.Leveler
	cfg     Config
	client  *mbtago.Client
	// connectMu serializes Connect attempts. mbta-go's binding converges
	// concurrent Connects on the single-use client by closing the winner's
	// connection (application error 0x1 "conn closed") — a reconnect fired
	// while the initial connect was still in flight killed every live
	// session under load. TryLock makes re-entry a no-op instead.
	connectMu *sync.Mutex
	// pendingResults tracks seqs written to the wire whose terminal RESULT
	// has not arrived yet (sendBatch success → handleResult visibility).
	// Close waits on this set before sending CLOSE: control and data streams
	// have no ordering guarantee, so an early CLOSE frame lets the server
	// tear the connection down before the last data-stream BATCH is read.
	pendingResults sync.Map
	buffer         chan *core.SignalRecord
	sendMu         sync.RWMutex // RLock during buffer send; Lock during Close's close(buffer)
	flushCh        chan chan struct{}
	wg             sync.WaitGroup
	ctx            context.Context
	cancel         context.CancelFunc
	closing        atomic.Bool
	dropped        atomic.Int64
	attrsDropped   atomic.Int64 // attribute entries cut by the wire-schema pre-filter
	lastDropReport atomic.Int64 // unix nanos of the last surfaced drop report
	errorHandler   atomic.Pointer[mebsuta.ErrorHandler]
	hostname       string
	// batchSizes maps an in-flight batch's seq (returned by SendBatch) to the
	// number of records it carried, so the internal result handler can count
	// server-side rejections as dropped records. Entries are removed when the
	// terminal RESULT arrives.
	batchSizes sync.Map
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

	// Dial: create client + connect in one step. The connectMu hold pairs
	// with tryReconnect's serialization (single Connect in flight, ever).
	connectMu := &sync.Mutex{}
	connectMu.Lock()

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

	// Dial ctx MUST be the handler-lifetime ctx: quic-go derives the
	// connection's context from the dial context (conn.run watches ctx.Done),
	// so canceling (or timing out) the dial context closes the ESTABLISHED
	// connection. The connectTimeout bounds only the dial wait here; on
	// timeout we cancel the base ctx to abort the in-flight dial.
	type dialResult struct {
		client *mbtago.Client
		err    error
	}
	dialCh := make(chan dialResult, 1)
	go func() {
		c, derr := mbtago.Dial(ctx, cfg.Server, cfg.AgentID, cfg.Token, mbtago.Version1,
			mbtago.WithV1Credentials(creds),
		)
		dialCh <- dialResult{c, derr}
	}()
	var client *mbtago.Client
	var dialErr error
	select {
	case r := <-dialCh:
		client, dialErr = r.client, r.err
	case <-time.After(connectTimeout):
		cancel() // abort the in-flight dial
		dialErr = fmt.Errorf("dial timed out after %v", connectTimeout)
	}
	if dialErr != nil {
		connectMu.Unlock() // Dial 失败：释放串行锁，让调用方重试路径可再连
		cancel()
		return nil, fmt.Errorf("mebsuta/mbta: %w", dialErr)
	}
	connectMu.Unlock() // 连接成功：锁只护「同一时刻至多一个 Connect 在飞」

	h := &Handler{
		leveler:   cfg.Level,
		cfg:       cfg,
		client:    client,
		connectMu: connectMu,
		buffer:    make(chan *core.SignalRecord, bufferSize),
		flushCh:   make(chan chan struct{}),
		ctx:       ctx,
		cancel:    cancel,
		hostname:  hostname,
	}

	eh := mebsuta.DefaultErrorHandler
	h.errorHandler.Store(&eh)

	// Register the internal result handler on the client's single RESULT slot.
	// It wraps cfg.OnResult (the only supported way for users to observe
	// RESULTs — see Config.OnResult for the slot-ownership ruling) with drop
	// accounting for server-side rejections, closing the "SendBatch returned
	// nil but the server rejected the batch" blind spot.
	h.client.SetResultHandler(h.handleResult)

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
		// Count silently-dropped post-close records so the loss is at least
		// visible in metrics, not just an invisible nil (mirrors database).
		h.dropped.Add(1)
		return nil
	}

	record, stats := recordToSignal(r)
	h.reportAttrStats(stats)
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
		// A concurrent Close already owns the drain. Wait for its drain phase
		// to finish instead of returning early, so a double-Close caller still
		// gets the "buffer flushed" guarantee (wg.Wait is idempotent once
		// processQueue has exited).
		h.wg.Wait()
		return nil
	}

	// sendMu makes close(buffer) race-free against in-flight sends.
	h.sendMu.Lock()
	close(h.buffer)
	h.sendMu.Unlock()

	// Bounded drain: the final flush costs up to MaxRetries × (send deadline
	// + RetryDelay) — both config-capped — but even the capped worst case can
	// exceed CloseTimeout, so the drain itself is deadline-bounded and the
	// remainder is dropped and reported.
	drained := make(chan struct{})
	go func() {
		h.wg.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(h.cfg.CloseTimeout):
		h.cancel() // processQueue exits via ctx.Done; sendBatch aborts on ctx.Err
		<-drained
		// Accounting after the drain, not before: records processQueue pulled
		// out of the channel are counted by sendBatch's ctx-abort branch
		// (in-flight batches), so snapshotting the channel beforehand would
		// double-count them. Post-drain the channel is closed with no readers,
		// which makes len() an exact count of records never handed off.
		if remaining := len(h.buffer); remaining > 0 {
			h.dropped.Add(int64(remaining))
			h.reportErr("close", fmt.Errorf("close drain timed out after %v: %d buffered records dropped (in-flight batches counted separately)", h.cfg.CloseTimeout, remaining))
		}
	}
	// Wait for the final batches' RESULTs before sending CLOSE (see
	// waitResults): the drain's SendBatch only means "on the wire".
	h.waitResults(h.cfg.CloseTimeout)

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
// Dropped returns the total number of records dropped due to a full buffer
// (or during Close's bounded drain) — feeds mebsuta.DroppedCounter probes.
func (h *Handler) Dropped() int64 {
	return h.dropped.Load()
}

func (h *Handler) SetErrorHandler(fn mebsuta.ErrorHandler) {
	h.errorHandler.Store(&fn)
}

// shouldReportDrop reports whether a drop should be surfaced now: at most one
// report per second, so a flood that overflows the buffer cannot amplify into
// one error-handler invocation per dropped record.
func (h *Handler) shouldReportDrop() bool {
	now := time.Now().UnixNano()
	last := h.lastDropReport.Load()
	if now-last < int64(time.Second) {
		return false
	}
	return h.lastDropReport.CompareAndSwap(last, now)
}

func (h *Handler) safeSend(record *core.SignalRecord, level slog.Level) error {
	// sendMu makes Close's close(buffer) race-free against in-flight sends.
	h.sendMu.RLock()
	defer h.sendMu.RUnlock()

	if h.closing.Load() {
		// Counted here (not only in Handle's early return) because closing can
		// flip between Handle's check and this one; the two paths are mutually
		// exclusive so each dropped record is counted exactly once.
		h.dropped.Add(1)
		return fmt.Errorf("mebsuta/mbta: handler closed, log dropped")
	}

	// Error and Audit (LevelAudit > LevelError) records: blocking send bounded
	// by ErrorTimeout, mirroring the async handler — try non-blocking first so
	// the healthy path never allocates a timer, and respect ctx cancellation
	// so a Close-in-progress cannot hold the caller for the full timeout.
	if level >= slog.LevelError {
		select {
		case h.buffer <- record:
			return nil
		case <-h.ctx.Done():
			h.dropped.Add(1)
			if h.shouldReportDrop() {
				h.reportErr("send", fmt.Errorf("handler stopped, %v record dropped (total dropped: %d)", level, h.dropped.Load()))
			}
			return fmt.Errorf("mebsuta/mbta: handler stopped, %v record dropped", level)
		default:
		}

		timer := time.NewTimer(h.cfg.ErrorTimeout)
		defer timer.Stop()
		select {
		case h.buffer <- record:
			return nil
		case <-h.ctx.Done():
			h.dropped.Add(1)
			if h.shouldReportDrop() {
				h.reportErr("send", fmt.Errorf("handler stopped, %v record dropped (total dropped: %d)", level, h.dropped.Load()))
			}
			return fmt.Errorf("mebsuta/mbta: handler stopped, %v record dropped", level)
		case <-timer.C:
			h.dropped.Add(1)
			if h.shouldReportDrop() {
				h.reportErr("send", fmt.Errorf("buffer full timeout for %v record, dropped (total dropped: %d)", level, h.dropped.Load()))
			}
			return fmt.Errorf("mebsuta/mbta: buffer full timeout for %v record", level)
		}
	}

	select {
	case h.buffer <- record:
		return nil
	default:
		h.dropped.Add(1)
		if h.shouldReportDrop() {
			h.reportErr("send", fmt.Errorf("buffer full, log dropped (total dropped: %d)", h.dropped.Load()))
		}
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
	// Wire-schema gate: mbta-go's SendBatch returns as soon as the batch is on
	// the wire, so a batch the server will reject is invisible unless we
	// pre-validate. The recordToSignal pre-filter keeps the common budgets
	// satisfied; this probe drops anything that still violates the schema
	// (e.g. nil records) instead of poisoning the whole batch — the server
	// rejects atomically, so one bad record would silently lose them all.
	resource := core.Resource{
		// mbta-go v0.6.0 removed the per-call tag/source parameters:
		// the metadata now lives in the batch resource attributes.
		Attributes: map[string]any{
			"host.name": h.hostname,
			"service":   h.cfg.Tag,
			"source":    h.cfg.Source,
		},
	}

	valid := make([]*core.SignalRecord, 0, len(records))
	var firstErr error
	invalid := 0
	for _, rec := range records {
		probe := &core.SignalBatch{Resource: resource, Signals: []*core.SignalRecord{rec}}
		if err := probe.Validate(); err != nil {
			invalid++
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		valid = append(valid, rec)
	}
	if invalid > 0 {
		h.dropped.Add(int64(invalid))
		if h.shouldReportDrop() {
			h.reportErr("validate", fmt.Errorf("%d/%d records failed wire-schema validation and were dropped (total dropped: %d, first error: %v)", invalid, len(records), h.dropped.Load(), firstErr))
		}
	}
	if len(valid) == 0 {
		return
	}

	batch := &core.SignalBatch{
		SchemaURL: "https://mebsuta.dev/schemas/v1/logs",
		Resource:  resource,
		Scope: core.Scope{
			Name:        "mebsuta",
			Version:     "mbta-handler",
			CollectorID: h.cfg.AgentID,
		},
		Signals: valid,
	}

	for attempt := range h.cfg.MaxRetries {
		seq, err := h.client.SendBatch(h.ctx, batch)
		if err == nil {
			// Success here only means "written to the wire". Remember the
			// batch size so handleResult can count the records back out when
			// the server's terminal RESULT reports rejected/released, and
			// register the seq as pending so Close can wait for the terminal
			// RESULT before tearing the connection down.
			h.trackBatchSize(seq, len(valid))
			h.pendingResults.Store(seq, struct{}{})
			return
		}

		// Gate on the context, not the closing flag: during Close's final
		// flush the ctx is live and retries must proceed, while cancel()
		// (which happens strictly after the drain finished) must abort them.
		if h.ctx.Err() != nil {
			h.dropped.Add(int64(len(valid)))
			if h.shouldReportDrop() {
				h.reportErr("send_batch", fmt.Errorf("handler stopped, %d records dropped (total dropped: %d)", len(valid), h.dropped.Load()))
			}
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
				h.dropped.Add(int64(len(valid)))
				if h.shouldReportDrop() {
					h.reportErr("send_batch", fmt.Errorf("handler stopped, %d records dropped (total dropped: %d)", len(valid), h.dropped.Load()))
				}
				return
			}
		}
	}

	h.dropped.Add(int64(len(valid)))
	if h.shouldReportDrop() {
		h.reportErr("send_batch", fmt.Errorf("failed after %d attempts, %d records dropped (total dropped: %d)", h.cfg.MaxRetries, len(valid), h.dropped.Load()))
	}
}

// trackBatchSize records how many records a successfully written batch carried.
func (h *Handler) trackBatchSize(seq uint64, n int) {
	if seq == 0 || n <= 0 {
		return
	}
	h.batchSizes.Store(seq, n)
}

// pendingCount reports how many wire-written seqs still await a RESULT.
func (h *Handler) pendingCount() int {
	n := 0
	h.pendingResults.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

// waitResults blocks up to window for every wire-written seq to receive its
// RESULT before Close sends the CLOSE frame. Control and data streams carry
// no cross-stream ordering: without this wait the server can process CLOSE
// and tear the connection down before the final data-stream BATCH is read,
// silently dropping the last buffer's worth of records. Bounded by window
// (reuses CloseTimeout as the budget); a lost RESULT (connection died) times
// out and proceeds — the drop is already counted by the result-timeout path.
func (h *Handler) waitResults(window time.Duration) {
	if h.pendingCount() == 0 {
		return
	}
	deadline := time.Now().Add(window)
	for h.pendingCount() > 0 {
		if time.Now().After(deadline) {
			left := h.pendingCount()
			h.reportErr("close", fmt.Errorf("close result-wait timed out after %v: %d batch(es) without terminal RESULT", window, left))
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// takeBatchSize removes and returns the record count tracked for seq (0 when
// unknown, e.g. a notification for a batch this handler did not write).
func (h *Handler) takeBatchSize(seq uint64) int {
	v, ok := h.batchSizes.LoadAndDelete(seq)
	if !ok {
		return 0
	}
	n, _ := v.(int)
	return n
}

// handleResult is the internal RESULT callback registered on the client's
// single slot at construction. It wraps the user's Config.OnResult: before
// delegating, it folds server-side rejections/releases into Dropped with a
// rate-limited report — without this, a batch that passed SendBatch's
// fire-and-forget return would vanish silently.
//
// Runs on mbta-go's serial result worker (panic-safe there), never on the log
// hot path.
func (h *Handler) handleResult(seq uint64, level string, code uint32, correlation string) {
	// Any RESULT (terminal or intermediate) proves the server saw the batch:
	// release the seq from Close's wait set before counting drops.
	h.pendingResults.Delete(seq)
	n := h.takeBatchSize(seq)
	switch level {
	case resultLevelRejected, resultLevelReleased, resultLevelTimeout:
		// Terminal loss the retry loop cannot see (SendBatch already
		// returned nil). "timeout" is mbta-go's synthetic released: the
		// in-flight slot expired with no terminal, and we never re-send at
		// the result layer, so the batch is unrecoverable either way.
	default:
		n = 0 // accepted / durable / unknown level: not a drop
	}
	if n > 0 {
		h.dropped.Add(int64(n))
		if h.shouldReportDrop() {
			h.reportErr("result", fmt.Errorf("server terminal result %s (code %d) for seq %d: %d records dropped (total dropped: %d)", level, code, seq, n, h.dropped.Load()))
		}
	}
	if h.cfg.OnResult != nil {
		h.cfg.OnResult(seq, level, code, correlation)
	}
}

func (h *Handler) reconnectEnabled() bool {
	return h.cfg.Reconnect != nil && *h.cfg.Reconnect
}

// tryReconnect re-dials the forwarder with a bounded context. Failures are
// reported and swallowed — the retry loop decides whether to keep going.
// connectMu.TryLock skips the re-dial while another Connect is in flight:
// the in-flight attempt either reaches READY (nothing to do) or fails, and
// the next retry pass re-fires. A concurrent second Connect would trigger
// mbta-go binding's double-connect convergence and close the live session.
func (h *Handler) tryReconnect() {
	if h.ctx.Err() != nil {
		return
	}
	if !h.connectMu.TryLock() {
		return
	}
	defer h.connectMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	if err := h.client.Connect(ctx); err != nil {
		h.reportErr("reconnect", fmt.Errorf("reconnect failed: %w", err))
	}
}

// attrStats reports what recordToSignal's wire-schema pre-filter did to a
// record's attributes. The consuming side validates SignalBatch atomically
// (core.SignalBatch.Validate; enforced by the forwarder's sink — the mbta-go
// server itself only checks the batch envelope at ingress), so one
// out-of-budget record would get the whole batch rejected there — the
// pre-filter keeps every record within the server's budgets up front and
// reports what it had to cut.
type attrStats struct {
	// droppedAttrs counts leaf entries skipped because the record already
	// carried core.MaxSignalAttrs entries (mbta-go's per-record cap).
	droppedAttrs int
	// truncatedKeys counts keys shortened to core.MaxSignalAttrKeyLen
	// (truncated at a UTF-8 rune boundary, mirroring attrutil).
	truncatedKeys int
	// sanitizedKeys counts keys whose strict control characters (mirroring
	// mbta-go's hasStrictControlChars: < 0x20 or 0x7f) were replaced with '_'.
	sanitizedKeys int
}

// any reports whether the pre-filter had to intervene.
func (s attrStats) any() bool {
	return s.droppedAttrs > 0 || s.truncatedKeys > 0 || s.sanitizedKeys > 0
}

// reportAttrStats surfaces pre-filter interventions at most once per second
// (the shared shouldReportDrop gate) so an attribute flood cannot amplify
// into an error-handler invocation per record.
func (h *Handler) reportAttrStats(stats attrStats) {
	if !stats.any() {
		return
	}
	h.attrsDropped.Add(int64(stats.droppedAttrs))
	if h.shouldReportDrop() {
		h.reportErr("attrs", fmt.Errorf("record attributes outside server schema were pre-filtered: %d entries dropped, %d keys truncated, %d keys sanitized (attrs dropped total: %d)", stats.droppedAttrs, stats.truncatedKeys, stats.sanitizedKeys, h.attrsDropped.Load()))
	}
}

// recordToSignal converts a slog.Record into a core.SignalRecord.
//
// Groups are flattened into dot-joined keys ("request.method" instead of a
// nested map): mbta-go's proto codec has no map representation for attribute
// values and falls back to fmt.Sprintf("%v"), which renders nested maps as
// unstable internal representations. Leaf values keep attrValue's scalar
// conversion (LogValuer resolution, depth cap marker).
func recordToSignal(r slog.Record) (*core.SignalRecord, attrStats) {
	attrs := make(map[string]any)
	var stats attrStats
	r.Attrs(func(attr slog.Attr) bool {
		flattenAttr(attrs, "", attr, 0, &stats)
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
		TimeUnixNs:     r.Time.UnixNano(),
		ObservedTimeNs: time.Now().UnixNano(),
		SeverityText:   severityText,
		SeverityNumber: severityNumber(r.Level),
		Body:           r.Message,
		Attributes:     attrs,
	}, stats
}

// flattenAttr walks attr into out with dot-joined group keys, mirroring
// attrutil's flattening shape (empty keys skipped so no "prefix." junk is
// produced, entries capped at core.MaxSignalAttrs) while keeping attrValue's
// scalar conversion for leaf values.
//
// slog contract: handlers must resolve LogValuer values before conversion.
// Unresolved values would leak their backing structs into the encoder, which
// renders them via fmt as internal Go representations (or pointer addresses).
func flattenAttr(out map[string]any, prefix string, attr slog.Attr, depth int, stats *attrStats) {
	key := attr.Key
	if prefix != "" {
		key = prefix + "." + attr.Key
	}
	v := attr.Value.Resolve()
	if v.Kind() == slog.KindGroup {
		if depth >= maxAttrDepth {
			// Same marker the old attrValue used for over-deep values, so
			// downstream can distinguish "nesting exceeded the cap" from an
			// absent value.
			setAttrLeaf(out, key, "<max-depth>", stats)
			return
		}
		for _, a := range v.Group() {
			if a.Key == "" {
				// Skip before concatenation so an empty child key under a
				// group cannot yield a trailing-dot key like "prefix.".
				continue
			}
			flattenAttr(out, key, a, depth+1, stats)
		}
		return
	}
	setAttrLeaf(out, key, attrValue(v), stats)
}

// attrValue converts an already-resolved, non-group slog.Value to its scalar
// Go value (the leaf conversion previously inlined in attrValue).
func attrValue(v slog.Value) any {
	return v.Any()
}

// setAttrLeaf inserts a converted leaf value under key, enforcing the server's
// attribute budgets (entry count, key length, strict control characters).
func setAttrLeaf(out map[string]any, key string, val any, stats *attrStats) {
	if key == "" {
		return
	}
	if len(out) >= core.MaxSignalAttrs {
		stats.droppedAttrs++
		return
	}
	out[sanitizeAttrKey(key, stats)] = val
}

// sanitizeAttrKey brings one attribute key inside mbta-go's schema: strict
// control characters replaced with '_' (preserving the key's information
// instead of dropping it), then length-truncated to core.MaxSignalAttrKeyLen
// at a valid UTF-8 rune boundary.
func sanitizeAttrKey(key string, stats *attrStats) string {
	if strings.ContainsFunc(key, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		key = strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return '_'
			}
			return r
		}, key)
		stats.sanitizedKeys++
	}
	if len(key) > core.MaxSignalAttrKeyLen {
		key = truncateValidUTF8(key, core.MaxSignalAttrKeyLen)
		stats.truncatedKeys++
	}
	return key
}

// truncateValidUTF8 cuts s to at most maxLen bytes without splitting a
// multi-byte rune (same algorithm as attrutil's unexported helper).
func truncateValidUTF8(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	for maxLen > 0 && !utf8.RuneStart(s[maxLen]) {
		maxLen--
	}
	return s[:maxLen]
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
