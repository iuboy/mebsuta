package database

import (
	"context"
	"encoding/hex"
	"encoding/json"
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
)

type dbLogEntry struct {
	Time    time.Time       `gorm:"column:time"`
	Level   string          `gorm:"column:level"`
	Message string          `gorm:"column:msg"`
	Fields  json.RawMessage `gorm:"type:json"`
	// Integrity protection — populated when Config.IntegritySigner is set.
	RecordHash string `gorm:"column:record_hash;default:''"`
	Signature  []byte `gorm:"column:signature;type:bytes"`
	SignAlgo   string `gorm:"column:sign_algo;size:32;default:''"`
}

// Handler writes log records in batches to a PostgreSQL or openGauss database via GORM.
type Handler struct {
	leveler      slog.Leveler
	cfg          Config
	db           *gorm.DB
	table        string
	entries      chan dbLogEntry
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	closed       atomic.Bool
	sendMu       sync.RWMutex // RLock during channel send; Lock during close
	errCount     atomic.Int64
	errorHandler atomic.Pointer[mebsuta.ErrorHandler]
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
		return nil
	}

	h.sendMu.RLock()
	defer h.sendMu.RUnlock()

	if h.closed.Load() {
		return nil
	}

	if level >= slog.LevelError {
		// Try non-blocking send first to avoid timer allocation in the common case.
		select {
		case h.entries <- entry:
			return nil
		default:
		}

		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case h.entries <- entry:
			return nil
		case <-timer.C:
			// sendMu (read lock) is held, so Close cannot close the channel
			// concurrently. The only reason to reach here is a full backlog.
			h.errCount.Add(1)
			mebsuta.ReportError(mebsuta.LoadErrorHandler(&h.errorHandler), &mebsuta.HandlerError{Component: "database", Operation: "write", Err: fmt.Errorf("backlog full: %v record dropped after 5s wait (buffer: %d/%d)", level, len(h.entries), cap(h.entries)), Dropped: 1})
			return nil
		}
	}

	// Non-Error levels: non-blocking send, drop on full buffer.
	select {
	case h.entries <- entry:
		return nil
	default:
		h.errCount.Add(1)
		mebsuta.ReportError(mebsuta.LoadErrorHandler(&h.errorHandler), &mebsuta.HandlerError{Component: "database", Operation: "write", Err: fmt.Errorf("backlog full: log dropped (buffer: %d/%d)", len(h.entries), cap(h.entries)), Dropped: 1})
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
// live context; cancel() is called last.
func (h *Handler) Close() error {
	if !h.closed.CompareAndSwap(false, true) {
		return nil
	}
	h.sendMu.Lock()
	close(h.entries) // safe: write lock ensures no concurrent sends
	h.sendMu.Unlock()
	h.wg.Wait()
	h.cancel()

	sqlDB, err := h.db.DB()
	if err != nil {
		return fmt.Errorf("mebsuta: get database connection for close: %w", err)
	}
	return sqlDB.Close()
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
				h.flush(batch, retryDelay)
				return
			}
			batch = append(batch, entry)

			if len(batch) >= batchSize {
				h.flush(batch, retryDelay)
				batch = nil
			}

		case <-ticker.C:
			if len(batch) > 0 {
				h.flush(batch, retryDelay)
				batch = nil
			}
		}
	}
}

func (h *Handler) flush(batch []dbLogEntry, retryDelay time.Duration) {
	if len(batch) == 0 {
		return
	}

	// Each attempt runs inside a transaction so that a partial failure does not
	// leave orphaned rows. Without the transaction, if CreateInBatches splits the
	// batch into multiple INSERT statements and one fails mid-way, retrying would
	// insert the already-persisted rows again, producing duplicates.
	for i := range finalFlushRetries {
		ctx, cancel := context.WithTimeout(h.ctx, finalFlushTimeout)
		dbErr := h.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			return tx.Table(h.table).CreateInBatches(batch, len(batch)).Error
		})
		cancel()

		if dbErr == nil {
			return
		}
		h.errCount.Add(1)
		mebsuta.ReportError(mebsuta.LoadErrorHandler(&h.errorHandler), &mebsuta.HandlerError{Component: "database", Operation: "batch", Err: fmt.Errorf("batch insert failed (attempt %d/%d): %w", i+1, finalFlushRetries, dbErr)})
		if i < finalFlushRetries-1 {
			// Respect context cancellation during shutdown so we don't
			// block Close() with an unconditional sleep.
			select {
			case <-time.After(retryDelay):
			case <-h.ctx.Done():
				return
			}
		}
	}
	mebsuta.ReportError(mebsuta.LoadErrorHandler(&h.errorHandler), &mebsuta.HandlerError{Component: "database", Operation: "batch", Err: fmt.Errorf("batch of %d records lost after %d failed attempts", len(batch), finalFlushRetries)})
}

func (h *Handler) recordToDBEntry(r slog.Record) dbLogEntry {
	entry := dbLogEntry{
		Time:    r.Time,
		Level:   r.Level.String(),
		Message: r.Message,
	}

	fields := make(map[string]any, 16)

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

// SelfBuffered marks Handler as having built-in async buffering.
func (*Handler) SelfBuffered() {}

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
