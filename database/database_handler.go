package database

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/attrutil"
	"gorm.io/driver/gaussdb"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const (
	finalFlushTimeout = 10 * time.Second
	finalFlushRetries = 3

	// insertChunkRows caps the rows per INSERT statement inside a flush
	// batch. PostgreSQL's wire protocol allows at most 65535 bind parameters
	// per statement and each row contributes 7 columns, so an unsplit batch
	// of maxBatchSize (10000) rows would exceed the limit (70000 params) and
	// fail every flush. 1000 rows → 7000 params — safely under the limit for
	// PostgreSQL/openGauss and within SQLite's 32766-variable default.
	insertChunkRows = 1000

	// dropReportInterval rate-limits backlog-drop reports: at most one
	// report per interval, carrying the cumulative drop count. Without it a
	// log flood that overflows the backlog produces one locked stderr write
	// per dropped record — a 1:1 amplification of attack traffic.
	dropReportInterval = int64(time.Second)
)

// shouldReportDrop reports whether a drop should be surfaced now: at most one
// report per dropReportInterval. Callers must always increment h.dropped
// regardless — the counter tracks every loss, the limiter only the reporting.
func (h *Handler) shouldReportDrop() bool {
	now := time.Now().UnixNano()
	last := h.lastDropReport.Load()
	if now-last < dropReportInterval {
		return false
	}
	return h.lastDropReport.CompareAndSwap(last, now)
}

type dbLogEntry struct {
	Time    time.Time       `gorm:"column:time"`
	Level   string          `gorm:"column:level"`
	Message string          `gorm:"column:msg"`
	Fields  json.RawMessage `gorm:"type:json"`
	// Integrity protection — populated when Config.IntegritySigner is set.
	RecordHash string `gorm:"column:record_hash;default:''"`
	Signature  []byte `gorm:"column:signature;type:bytea"`
	SignAlgo   string `gorm:"column:sign_algo;size:32;default:''"`
}

// Handler writes log records in batches to a PostgreSQL or openGauss database via GORM.
type Handler struct {
	leveler        slog.Leveler
	cfg            Config
	db             *gorm.DB
	table          string
	entries        chan dbLogEntry
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	closed         atomic.Bool
	sendMu         sync.RWMutex // RLock during channel send; Lock during close
	errCount       atomic.Int64
	dropped        atomic.Int64
	lastDropReport atomic.Int64 // unix nanos of the last surfaced drop report
	flushMu        sync.Mutex
	flushErr       error // last batch-loss error, surfaced by Close
	errorHandler   atomic.Pointer[mebsuta.ErrorHandler]
}

// NewHandler creates a Handler that connects to the database specified in cfg.
func NewHandler(cfg Config) (*Handler, error) {
	cfg, err := cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("mebsuta: %w", err)
	}

	// openGauss uses the GaussDB GORM driver (gorm.io/driver/gaussdb); it
	// speaks the PostgreSQL-compatible protocol but needs its own driver for
	// openGauss-specific authentication (sha256) and error codes.
	var dialector gorm.Dialector
	switch cfg.Driver {
	case "opengauss":
		dialector = gaussdb.Open(cfg.DSN)
	default: // "postgres" — the only other value Validate accepts.
		dialector = postgres.Open(cfg.DSN)
	}

	gdb, err := gorm.Open(dialector, &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("mebsuta: connect %s database: %s", cfg.Driver, sanitizeDBError(err))
	}

	sqlDB, err := gdb.DB()
	if err != nil {
		// gorm.Open succeeded but DB() failed — close the underlying connection.
		closeSQLDB(gdb)
		return nil, fmt.Errorf("mebsuta: get database connection: %w", err)
	}

	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	if cfg.MaxConnLifetime > 0 {
		sqlDB.SetConnMaxLifetime(cfg.MaxConnLifetime)
	}

	ctx, cancel := context.WithCancel(context.Background())

	h := &Handler{
		leveler: cfg.Level,
		cfg:     cfg,
		db:      gdb,
		table:   cfg.Table,
		entries: make(chan dbLogEntry, cfg.BatchSize*10),
		ctx:     ctx,
		cancel:  cancel,
	}
	eh := mebsuta.DefaultErrorHandler
	h.errorHandler.Store(&eh)

	if cfg.warnNoTLS {
		mebsuta.ReportError(eh, &mebsuta.HandlerError{Component: "database", Operation: "init", Err: fmt.Errorf("database connection has no TLS/SSL configured — log data will be transmitted in plaintext")})
	}

	h.wg.Add(1)
	go h.run(cfg.BatchSize, cfg.BatchInterval, cfg.RetryDelay)

	return h, nil
}

// Enabled implements slog.Handler.
func (h *Handler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= mebsuta.SafeLevel(h.leveler)
}

// Handle implements slog.Handler.
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	if h.closed.Load() {
		// Count silently-dropped post-close records so the loss is at least
		// visible in metrics, not just invisible nil.
		h.dropped.Add(1)
		return nil
	}

	entry := h.recordToDBEntry(r)
	return h.sendEntry(entry, r.Level)
}

// sendEntry sends an entry to the background channel.
//
// Uses an RWMutex: sends take the read lock (concurrent — multiple goroutines
// can send simultaneously), Close takes the write lock (exclusive — waits for
// in-flight sends to finish before closing the channel). This eliminates the
// old closeMu approach that serialized ALL sends behind a single mutex and
// blocked Close for up to 5s per Error-level record.
func (h *Handler) sendEntry(entry dbLogEntry, level slog.Level) error {
	if h.closed.Load() {
		h.dropped.Add(1)
		return nil
	}

	h.sendMu.RLock()
	defer h.sendMu.RUnlock()

	if h.closed.Load() {
		h.dropped.Add(1)
		return nil
	}

	if level >= slog.LevelError {
		// Try non-blocking send first to avoid timer allocation in the common case.
		select {
		case h.entries <- entry:
			return nil
		default:
		}

		timer := time.NewTimer(h.cfg.ErrorTimeout)
		defer timer.Stop()
		select {
		case h.entries <- entry:
			return nil
		case <-timer.C:
			// sendMu (read lock) is held, so Close cannot close the channel
			// concurrently. The only reason to reach here is a full backlog.
			h.errCount.Add(1)
			h.dropped.Add(1)
			if h.shouldReportDrop() {
				mebsuta.ReportError(mebsuta.LoadErrorHandler(&h.errorHandler), &mebsuta.HandlerError{Component: "database", Operation: "write", Err: fmt.Errorf("backlog full: %v record dropped after %v wait (buffer: %d/%d, total dropped: %d)", level, h.cfg.ErrorTimeout, len(h.entries), cap(h.entries), h.dropped.Load()), Dropped: h.dropped.Load()})
			}
			return nil
		}
	}

	// Non-Error levels: non-blocking send, drop on full buffer.
	select {
	case h.entries <- entry:
		return nil
	default:
		h.errCount.Add(1)
		h.dropped.Add(1)
		if h.shouldReportDrop() {
			mebsuta.ReportError(mebsuta.LoadErrorHandler(&h.errorHandler), &mebsuta.HandlerError{Component: "database", Operation: "write", Err: fmt.Errorf("backlog full: log dropped (buffer: %d/%d, total dropped: %d)", len(h.entries), cap(h.entries), h.dropped.Load()), Dropped: h.dropped.Load()})
		}
		return nil
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

// Close implements io.Closer.
//
// Takes the write lock to wait for all in-flight sendEntry calls to complete,
// then closes the channel. This is race-detector-clean (unlike recover-based
// approaches) and allows concurrent sends (the read lock is shared). The
// channel close signals run() to drain and flush remaining records with a
// live context; cancel() is called last. If the final flush permanently lost
// a batch, that error is returned from Close instead of vanishing.
func (h *Handler) Close() error {
	if !h.closed.CompareAndSwap(false, true) {
		return nil
	}
	h.sendMu.Lock()
	close(h.entries) // safe: write lock ensures no concurrent sends
	h.sendMu.Unlock()
	h.wg.Wait()
	h.cancel()

	h.flushMu.Lock()
	flushErr := h.flushErr
	h.flushMu.Unlock()

	var errs []error
	if flushErr != nil {
		errs = append(errs, flushErr)
	}
	sqlDB, err := h.db.DB()
	if err != nil {
		errs = append(errs, fmt.Errorf("mebsuta: get database connection for close: %w", err))
		return errors.Join(errs...)
	}
	if err := sqlDB.Close(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (h *Handler) run(batchSize int, batchInterval, retryDelay time.Duration) {
	defer h.wg.Done()

	ticker := time.NewTicker(batchInterval)
	defer ticker.Stop()

	var batch []dbLogEntry

	// run() exits ONLY via channel close (the !ok path). It does NOT select
	// on h.ctx.Done() so that Close() can: (1) close(h.entries) which signals
	// run to exit, (2) wg.Wait() for the drain+flush to complete with a live
	// context, (3) h.cancel() to release resources. If run() exited on
	// ctx.Done(), the final flush would use a cancelled context and lose data.
	for {
		select {
		case entry, ok := <-h.entries:
			if !ok {
				h.setFlushErr(h.flush(batch, retryDelay))
				return
			}
			batch = append(batch, entry)

			if len(batch) >= batchSize {
				h.setFlushErr(h.flush(batch, retryDelay))
				batch = nil
			}

		case <-ticker.C:
			if len(batch) > 0 {
				h.setFlushErr(h.flush(batch, retryDelay))
				batch = nil
			}
		}
	}
}

func (h *Handler) setFlushErr(err error) {
	if err == nil {
		return
	}
	h.flushMu.Lock()
	h.flushErr = err
	h.flushMu.Unlock()
}

// flush inserts one batch, retrying transient failures. It returns an error
// only when the batch was permanently lost, so Close can surface data loss.
func (h *Handler) flush(batch []dbLogEntry, retryDelay time.Duration) error {
	if len(batch) == 0 {
		return nil
	}

	// Each attempt runs inside a transaction so that a partial failure does not
	// leave orphaned rows. Without the transaction, if CreateInBatches splits the
	// batch into multiple INSERT statements and one fails mid-way, retrying would
	// insert the already-persisted rows again, producing duplicates.
	//
	// Residual duplicate risk: if the transaction commits server-side but the
	// client hits the timeout first (ambiguous outcome), the retry re-inserts
	// the batch. The table has no natural idempotency key — dedup requires a
	// unique constraint or event-ID column, which is a schema decision left
	// to the operator.
	for i := range finalFlushRetries {
		ctx, cancel := context.WithTimeout(h.ctx, finalFlushTimeout)
		dbErr := h.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			return tx.Table(h.table).CreateInBatches(batch, insertChunkRows).Error
		})
		cancel()

		if dbErr == nil {
			return nil
		}
		h.errCount.Add(1)
		mebsuta.ReportError(mebsuta.LoadErrorHandler(&h.errorHandler), &mebsuta.HandlerError{Component: "database", Operation: "batch", Err: fmt.Errorf("batch insert failed (attempt %d/%d): %w", i+1, finalFlushRetries, dbErr)})
		if i < finalFlushRetries-1 {
			// Respect context cancellation during shutdown so we don't
			// block Close() with an unconditional sleep.
			select {
			case <-time.After(retryDelay):
			case <-h.ctx.Done():
				return nil
			}
		}
	}
	err := fmt.Errorf("mebsuta: batch of %d records lost after %d failed attempts", len(batch), finalFlushRetries)
	mebsuta.ReportError(mebsuta.LoadErrorHandler(&h.errorHandler), &mebsuta.HandlerError{Component: "database", Operation: "batch", Err: err})
	return err
}

// fieldsMapPool recycles the per-record attr map: one map allocation per log
// record is measurable GC pressure at high volume, and the map is dead once
// marshaled into entry.Fields.
var fieldsMapPool = sync.Pool{
	New: func() any { return make(map[string]any, 16) },
}

func (h *Handler) recordToDBEntry(r slog.Record) dbLogEntry {
	entry := dbLogEntry{
		Time:    r.Time,
		Level:   r.Level.String(),
		Message: r.Message,
	}

	fields, _ := fieldsMapPool.Get().(map[string]any)
	if fields == nil {
		fields = make(map[string]any, 16)
	}
	defer func() {
		for k := range fields {
			delete(fields, k)
		}
		fieldsMapPool.Put(fields)
	}()

	r.Attrs(func(attr slog.Attr) bool {
		attrutil.FlattenAttr(fields, "", attr, attrutil.NaNString)
		return true
	})
	if len(fields) > 0 {
		data, err := json.Marshal(fields)
		if err != nil {
			mebsuta.ReportError(mebsuta.LoadErrorHandler(&h.errorHandler), &mebsuta.HandlerError{Component: "database", Operation: "marshal", Err: fmt.Errorf("marshal fields: %w", err)})
			data = []byte("{}")
		}
		entry.Fields = json.RawMessage(data)
	}

	// Integrity protection: when a signer is configured, sign the canonical
	// representation of the record. Failure is non-fatal — we log the error
	// and persist the record without a signature rather than dropping it.
	if h.cfg.IntegritySigner != nil {
		// Cap the stored timestamp at the canonical precision so the signed
		// form survives the database round-trip: PostgreSQL and openGauss
		// timestamptz keep microseconds, so sub-microsecond digits would
		// otherwise be silently dropped by the column and every later
		// verification of an untampered record would fail.
		entry.Time = entry.Time.Truncate(canonicalPrecision)
		canonical, err := CanonicalBytes(entry.Time, entry.Level, entry.Message, entry.Fields)
		if err != nil {
			mebsuta.ReportError(mebsuta.LoadErrorHandler(&h.errorHandler), &mebsuta.HandlerError{
				Component: "database", Operation: "sign",
				Err: fmt.Errorf("integrity sign skipped, record persisted unsigned: %w", err),
			})
		} else {
			recordHash, sig, signErr := h.cfg.IntegritySigner.Sign(canonical)
			if signErr != nil {
				mebsuta.ReportError(mebsuta.LoadErrorHandler(&h.errorHandler), &mebsuta.HandlerError{
					Component: "database", Operation: "sign",
					Err: fmt.Errorf("integrity sign failed, record persisted unsigned: %w", signErr),
				})
			} else {
				entry.RecordHash = hex.EncodeToString(recordHash)
				entry.Signature = sig
				entry.SignAlgo = h.cfg.IntegritySigner.Algorithm()
			}
		}
	}

	return entry
}

func (h *Handler) setErrorHandler(fn mebsuta.ErrorHandler) {
	h.errorHandler.Store(&fn)
}

// SetErrorHandler updates the error handler at runtime. It implements
// mebsuta.ErrorHandlerSetter so WithErrorHandler propagates into this
// handler (the package-internal setErrorHandler alone is unreachable from
// another package).
func (h *Handler) SetErrorHandler(fn mebsuta.ErrorHandler) {
	h.errorHandler.Store(&fn)
}

// SelfBuffered marks Handler as having built-in async buffering.
func (*Handler) SelfBuffered() {}

// Dropped returns the total number of records dropped due to a full backlog
// (or after Close) — the database-side counterpart of mebsuta.AsyncDropped,
// previously counted but unreadable.
func (h *Handler) Dropped() int64 {
	return h.dropped.Load()
}

func closeSQLDB(gdb *gorm.DB) {
	if db, err := gdb.DB(); err == nil {
		_ = db.Close()
	}
}

// dsnCredRe matches common credential patterns embedded in DSN-derived error
// messages: the password segment of "user:pass@host" / "user:pass@tcp(host)",
// and key=value style params (password, passwd, sslpassword, pwd).
//
// The password-segment pattern is :[^@/]*@ — it allows ':' inside the password
// (a previous :[^:@/]+@ variant leaked anything after an embedded ':' ) and
// stops at the first '@' or '/'. Passwords containing '@' cannot be reliably
// separated from the host delimiter by regex alone; such DSNs should be parsed
// driver-side. This is a best-effort redactor for error messages, not a parser.
var dsnCredRe = regexp.MustCompile(`:[^@/]*@|(?:password|passwd|sslpassword|pwd)=[^&;\s]+`)

// sanitizeDBError removes credential-like substrings from database error messages.
func sanitizeDBError(err error) string {
	if err == nil {
		return "<nil>"
	}
	return dsnCredRe.ReplaceAllStringFunc(err.Error(), func(m string) string {
		// "user:pass@" style — preserve the colon separator shape.
		if strings.HasSuffix(m, "@") {
			return ":***@"
		}
		// "key=value" style — preserve the key, redact the value.
		eq := strings.IndexByte(m, '=')
		if eq < 0 {
			return "***"
		}
		return m[:eq+1] + "***"
	})
}

var (
	_ slog.Handler                = (*Handler)(nil)
	_ io.Closer                   = (*Handler)(nil)
	_ mebsuta.SelfBufferedHandler = (*Handler)(nil)
)
