package database

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/config"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// =============================================================================
// DatabaseHandler — 数据库输出 slog.Handler
// =============================================================================

const (
	finalFlushTimeout = 10 * time.Second
	finalFlushRetries = 3
)

// dbLogEntry 是写入数据库的日志条目。
type dbLogEntry struct {
	Time    time.Time       `gorm:"column:time"`
	Level   string          `gorm:"column:level"`
	Message string          `gorm:"column:msg"`
	Fields  json.RawMessage `gorm:"type:json"`
}

// TableName 实现 GORM TableName 接口。
func (dbLogEntry) TableName() string {
	return "logs"
}

// DatabaseHandler 将日志记录批量写入 SQL 数据库。
// 实现 slog.Handler 和 io.Closer 接口。
// 支持 MySQL 和 Postgres（通过 GORM）。
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
	errCount     atomic.Int64
	errorHandler atomic.Pointer[mebsuta.ErrorHandler]
}

// NewDatabaseHandler 创建输出到数据库的 slog.Handler。
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

// Handle 处理一条日志记录，转换为 dbLogEntry 并发送到缓冲通道。
func (h *DatabaseHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.closed.Load() {
		return nil
	}

	entry := h.recordToDBEntry(r)

	// recover 防止 Close() 关闭 channel 后并发 send 导致 panic。
	defer func() {
		if r := recover(); r != nil {
			h.errCount.Add(1)
			mebsuta.ReportError(mebsuta.LoadErrorHandler(&h.errorHandler), "database", fmt.Errorf("send on closed channel, log dropped"))
		}
	}()

	select {
	case h.entries <- entry:
		return nil
	default:
		h.errCount.Add(1)
		mebsuta.ReportError(mebsuta.LoadErrorHandler(&h.errorHandler), "database", fmt.Errorf("buffer full, log dropped"))
		return nil
	}
}

// WithAttrs 返回带有预置属性的新 DatabaseHandler。
// 预置属性会在 Handle 中序列化到 JSON Fields。
func (h *DatabaseHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &dbAttrsHandler{
		DatabaseHandler: h,
		attrs:           attrs,
	}
}

// WithGroup 返回带有分组前缀的新 DatabaseHandler。
func (h *DatabaseHandler) WithGroup(name string) slog.Handler {
	return &dbGroupHandler{
		DatabaseHandler: h,
		group:           name,
	}
}

// dbAttrsHandler 在 Handle 时注入预置属性。
type dbAttrsHandler struct {
	*DatabaseHandler
	attrs []slog.Attr
	group string
}

func (h *dbAttrsHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.group != "" {
		newR := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
		r.Attrs(func(attr slog.Attr) bool {
			newR.AddAttrs(slog.Attr{Key: h.group + "." + attr.Key, Value: attr.Value})
			return true
		})
		newR.AddAttrs(h.attrs...)
		return h.DatabaseHandler.Handle(ctx, newR)
	}
	for _, attr := range h.attrs {
		r.AddAttrs(attr)
	}
	return h.DatabaseHandler.Handle(ctx, r)
}

func (h *dbAttrsHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	merged = append(merged, h.attrs...)
	if h.group != "" {
		for _, a := range attrs {
			merged = append(merged, slog.Attr{Key: h.group + "." + a.Key, Value: a.Value})
		}
	} else {
		merged = append(merged, attrs...)
	}
	return &dbAttrsHandler{
		DatabaseHandler: h.DatabaseHandler,
		attrs:           merged,
		group:           h.group,
	}
}

func (h *dbAttrsHandler) WithGroup(name string) slog.Handler {
	return &dbGroupHandler{
		DatabaseHandler: h.DatabaseHandler,
		group:           name,
		attrs:           h.attrs,
	}
}

// dbGroupHandler 在 Handle 时将属性归组。
type dbGroupHandler struct {
	*DatabaseHandler
	group string
	attrs []slog.Attr
}

func (h *dbGroupHandler) Handle(ctx context.Context, r slog.Record) error {
	newR := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(attr slog.Attr) bool {
		newR.AddAttrs(slog.Attr{Key: h.group + "." + attr.Key, Value: attr.Value})
		return true
	})
	newR.AddAttrs(h.attrs...)
	return h.DatabaseHandler.Handle(ctx, newR)
}

func (h *dbGroupHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, len(h.attrs), len(h.attrs)+len(attrs))
	copy(merged, h.attrs)
	for _, a := range attrs {
		merged = append(merged, slog.Attr{Key: h.group + "." + a.Key, Value: a.Value})
	}
	return &dbAttrsHandler{
		DatabaseHandler: h.DatabaseHandler,
		attrs:           merged,
		group:           h.group,
	}
}

func (h *dbGroupHandler) WithGroup(name string) slog.Handler {
	return &dbGroupHandler{
		DatabaseHandler: h.DatabaseHandler,
		group:           h.group + "." + name,
		attrs:           h.attrs,
	}
}

// Close 关闭数据库连接。先 flush 缓冲区中的日志。
func (h *DatabaseHandler) Close() error {
	if !h.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(h.entries)
	h.wg.Wait()
	h.cancel()

	sqlDB, err := h.db.DB()
	if err != nil {
		return fmt.Errorf("mebsuta: get database connection for close: %w", err)
	}
	return sqlDB.Close()
}

// =============================================================================
// 批量写入
// =============================================================================

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
		mebsuta.ReportError(mebsuta.LoadErrorHandler(&h.errorHandler), "database", fmt.Errorf("batch insert failed (attempt %d/%d): %w", i+1, finalFlushRetries, dbErr))
		if i < finalFlushRetries-1 {
			time.Sleep(retryDelay)
		}
	}
}

// =============================================================================
// 辅助
// =============================================================================

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

// setErrorHandler 设置内部错误处理函数（由 buildHandler 传播调用）。
func (h *DatabaseHandler) setErrorHandler(fn mebsuta.ErrorHandler) {
	h.errorHandler.Store(&fn)
}

// 编译期断言
var (
	_ slog.Handler = (*DatabaseHandler)(nil)
	_ io.Closer    = (*DatabaseHandler)(nil)
)
