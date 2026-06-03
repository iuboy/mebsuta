package database

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/attrutil"
	"gorm.io/driver/mysql"
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
}

// Handler writes log records in batches to a SQL database (MySQL or Postgres) via GORM.
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
	sendMu       sync.Mutex
	errCount     atomic.Int64
	errorHandler atomic.Pointer[mebsuta.ErrorHandler]
}

// NewHandler creates a Handler that connects to the database specified in cfg.
func NewHandler(cfg Config) (*Handler, error) {
	cfg, err := cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("mebsuta: %w", err)
	}

	var dialector gorm.Dialector
	switch cfg.Driver {
	case "mysql":
		dialector = mysql.Open(cfg.DSN)
	case "postgres":
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
		mebsuta.ReportError(eh, mebsuta.HandlerError{Component: "database", Operation: "init", Err: fmt.Errorf("database connection has no TLS/SSL configured — log data will be transmitted in plaintext")})
	}

	h.wg.Add(1)
	go h.run(cfg.BatchSize, cfg.BatchInterval, cfg.RetryDelay)

	return h, nil
}

// Enabled implements slog.Handler.
func (h *Handler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.leveler.Level()
}

// Handle implements slog.Handler.
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	if h.closed.Load() {
		return nil
	}

	entry := h.recordToDBEntry(r)

	if r.Level >= slog.LevelError {
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		h.sendMu.Lock()
		defer h.sendMu.Unlock()
		if h.closed.Load() {
			return nil
		}
		select {
		case h.entries <- entry:
			return nil
		case <-timer.C:
			h.errCount.Add(1)
			mebsuta.ReportError(mebsuta.LoadErrorHandler(&h.errorHandler), mebsuta.HandlerError{Component: "database", Operation: "write", Err: fmt.Errorf("buffer full timeout for %v record, dropped", r.Level), Dropped: 1})
			return nil
		}
	}

	h.sendMu.Lock()
	defer h.sendMu.Unlock()
	if h.closed.Load() {
		return nil
	}
	select {
	case h.entries <- entry:
		return nil
	default:
		h.errCount.Add(1)
		mebsuta.ReportError(mebsuta.LoadErrorHandler(&h.errorHandler), mebsuta.HandlerError{Component: "database", Operation: "write", Err: fmt.Errorf("buffer full, log dropped"), Dropped: 1})
		return nil
	}
}

// WithAttrs implements slog.Handler.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &mebsuta.AttrsSub[*Handler]{Parent: h, Attrs: attrs}
}

// WithGroup implements slog.Handler.
func (h *Handler) WithGroup(name string) slog.Handler {
	return &mebsuta.GroupSub[*Handler]{Parent: h, Group: name}
}

// Close implements io.Closer.
func (h *Handler) Close() error {
	if !h.closed.CompareAndSwap(false, true) {
		return nil
	}
	h.sendMu.Lock()
	close(h.entries)
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

		case <-h.ctx.Done():
			h.flush(batch, retryDelay)
			return
		}
	}
}

func (h *Handler) flush(batch []dbLogEntry, retryDelay time.Duration) {
	if len(batch) == 0 {
		return
	}

	for i := range finalFlushRetries {
		ctx, cancel := context.WithTimeout(context.Background(), finalFlushTimeout)
		dbErr := h.db.WithContext(ctx).Table(h.table).CreateInBatches(batch, len(batch)).Error
		cancel()

		if dbErr == nil {
			return
		}
		h.errCount.Add(1)
		mebsuta.ReportError(mebsuta.LoadErrorHandler(&h.errorHandler), mebsuta.HandlerError{Component: "database", Operation: "batch", Err: fmt.Errorf("batch insert failed (attempt %d/%d): %w", i+1, finalFlushRetries, dbErr)})
		if i < finalFlushRetries-1 {
			time.Sleep(retryDelay)
		}
	}
	mebsuta.ReportError(mebsuta.LoadErrorHandler(&h.errorHandler), mebsuta.HandlerError{Component: "database", Operation: "batch", Err: fmt.Errorf("batch of %d records lost after %d failed attempts", len(batch), finalFlushRetries)})
}

func (h *Handler) recordToDBEntry(r slog.Record) dbLogEntry {
	entry := dbLogEntry{
		Time:    r.Time,
		Level:   r.Level.String(),
		Message: r.Message,
	}

	fields := make(map[string]any)
	r.Attrs(func(attr slog.Attr) bool {
		attrutil.FlattenAttr(fields, "", attr, attrutil.NaNString)
		return true
	})
	if len(fields) > 0 {
		data, err := json.Marshal(fields)
		if err != nil {
			mebsuta.ReportError(mebsuta.LoadErrorHandler(&h.errorHandler), mebsuta.HandlerError{Component: "database", Operation: "marshal", Err: fmt.Errorf("marshal fields: %w", err)})
			data = []byte("{}")
		}
		entry.Fields = json.RawMessage(data)
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

// dsnCredRe matches common credential patterns in DSNs: user:pass@host, user:pass@tcp(host),
// password=xxx, and similar.
var dsnCredRe = regexp.MustCompile(`:[^:@/]+@|password=[^&\s]+|passwd=[^&\s]+`)

// sanitizeDBError removes credential-like substrings from database error messages.
func sanitizeDBError(err error) string {
	if err == nil {
		return "<nil>"
	}
	return dsnCredRe.ReplaceAllString(err.Error(), ":***@")
}

var (
	_ slog.Handler                = (*Handler)(nil)
	_ io.Closer                   = (*Handler)(nil)
	_ mebsuta.SelfBufferedHandler = (*Handler)(nil)
)
