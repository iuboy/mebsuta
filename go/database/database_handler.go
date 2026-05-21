package database

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iuboy/mebsuta/go"
	"github.com/iuboy/mebsuta/go/config"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func loadDBErrorHandler(p *atomic.Pointer[mebsuta.ErrorHandler]) mebsuta.ErrorHandler {
	v := p.Load()
	if v == nil {
		return nil
	}
	return *v
}

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

func (dbLogEntry) TableName() string {
	return "logs"
}

// DatabaseHandler writes log records in batches to a SQL database (MySQL or Postgres) via GORM.
type DatabaseHandler struct {
	mebsuta.LevelHandler
	cfg          config.DatabaseConfig
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

// NewDatabaseHandler creates a DatabaseHandler that connects to the database specified in cfg at the given log level.
func NewDatabaseHandler(cfg config.DatabaseConfig, level slog.Level) (*DatabaseHandler, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("mebsuta: %w", err)
	}

	var dialector gorm.Dialector
	switch cfg.DriverName {
	case "mysql":
		dialector = mysql.Open(cfg.DataSourceName)
	case "postgres":
		dialector = postgres.Open(cfg.DataSourceName)
	}

	gdb, err := gorm.Open(dialector, &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("mebsuta: connect %s database: %w", cfg.DriverName, err)
	}

	sqlDB, err := gdb.DB()
	if err != nil {
		return nil, fmt.Errorf("mebsuta: get database connection: %w", err)
	}

	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	if cfg.MaxConnLifetime > 0 {
		sqlDB.SetConnMaxLifetime(cfg.MaxConnLifetime)
	}

	batchSize := cfg.BatchSize
	batchInterval := cfg.BatchInterval
	retryDelay := cfg.RetryDelay

	ctx, cancel := context.WithCancel(context.Background())

	h := &DatabaseHandler{
		LevelHandler: mebsuta.LevelHandler{Level: level},
		cfg:          cfg,
		db:           gdb,
		table:        cfg.TableName,
		entries:      make(chan dbLogEntry, batchSize*10),
		ctx:          ctx,
		cancel:       cancel,
	}
	eh := mebsuta.DefaultErrorHandler
	h.errorHandler.Store(&eh)

	h.wg.Add(1)
	go h.run(batchSize, batchInterval, retryDelay)

	return h, nil
}

func (h *DatabaseHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.closed.Load() {
		return nil
	}

	entry := h.recordToDBEntry(r)

	// Error and Audit records: retry loop to avoid dropping.
	if r.Level >= slog.LevelError {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			h.sendMu.Lock()
			if h.closed.Load() {
				h.sendMu.Unlock()
				return nil
			}
			select {
			case h.entries <- entry:
				h.sendMu.Unlock()
				return nil
			default:
				h.sendMu.Unlock()
				runtime.Gosched()
			}
		}
		h.errCount.Add(1)
		mebsuta.ReportError(loadDBErrorHandler(&h.errorHandler), "database", fmt.Errorf("buffer full timeout for %v record, dropped", r.Level))
		return nil
	}

	h.sendMu.Lock()
	if h.closed.Load() {
		h.sendMu.Unlock()
		return nil
	}
	select {
	case h.entries <- entry:
		h.sendMu.Unlock()
		return nil
	default:
		h.sendMu.Unlock()
		h.errCount.Add(1)
		mebsuta.ReportError(loadDBErrorHandler(&h.errorHandler), "database", fmt.Errorf("buffer full, log dropped"))
		return nil
	}
}

func (h *DatabaseHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &mebsuta.AttrsSub[*DatabaseHandler]{Parent: h, Attrs: attrs}
}

func (h *DatabaseHandler) WithGroup(name string) slog.Handler {
	return &mebsuta.GroupSub[*DatabaseHandler]{Parent: h, Group: name}
}

func (h *DatabaseHandler) Close() error {
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

func (h *DatabaseHandler) run(batchSize int, batchInterval, retryDelay time.Duration) {
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

func (h *DatabaseHandler) flush(batch []dbLogEntry, retryDelay time.Duration) {
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
		mebsuta.ReportError(loadDBErrorHandler(&h.errorHandler), "database", fmt.Errorf("batch insert failed (attempt %d/%d): %w", i+1, finalFlushRetries, dbErr))
		if i < finalFlushRetries-1 {
			time.Sleep(retryDelay)
		}
	}
}

func (h *DatabaseHandler) recordToDBEntry(r slog.Record) dbLogEntry {
	entry := dbLogEntry{
		Time:    r.Time,
		Level:   r.Level.String(),
		Message: r.Message,
	}

	fields := make(map[string]any)
	r.Attrs(func(attr slog.Attr) bool {
		fields[attr.Key] = attr.Value
		return true
	})
	if len(fields) > 0 {
		data, err := json.Marshal(fields)
		if err != nil {
			data = []byte("{}")
		}
		entry.Fields = json.RawMessage(data)
	}

	return entry
}

func (h *DatabaseHandler) setErrorHandler(fn mebsuta.ErrorHandler) {
	h.errorHandler.Store(&fn)
}

// SelfBuffered marks DatabaseHandler as having built-in async buffering.
func (*DatabaseHandler) SelfBuffered() {}

var (
	_ slog.Handler                = (*DatabaseHandler)(nil)
	_ io.Closer                   = (*DatabaseHandler)(nil)
	_ mebsuta.SelfBufferedHandler = (*DatabaseHandler)(nil)
)
