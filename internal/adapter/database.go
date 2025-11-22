package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"github.com/influxdata/influxdb-client-go/v2/api"
	"github.com/iuboy/mebsuta/config"
	"github.com/iuboy/mebsuta/core"
	"go.uber.org/zap"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type LogStore interface {
	InsertBatch(ctx context.Context, entries []LogEntry) error
	Close() error
}

func newDBAdapter(config config.DatabaseConfig) (core.WriteSyncer, error) {
	var backend LogStore

	switch config.DriverName {
	case "mysql", "postgres":
		var dialector gorm.Dialector
		if config.DriverName == "mysql" {
			dialector = mysql.Open(config.DataSourceName)
		} else {
			dialector = postgres.Open(config.DataSourceName)
		}

		gdb, err := gorm.Open(dialector, &gorm.Config{})
		if err != nil {
			return nil, err
		}

		sqlDB, _ := gdb.DB()
		sqlDB.SetMaxIdleConns(config.MaxIdleConns)
		sqlDB.SetMaxOpenConns(config.MaxOpenConns)
		sqlDB.SetConnMaxLifetime(config.MaxConnLifetime)

		backend = &sqlStore{
			db:        gdb,
			table:     config.TableName,
			batchSize: config.BatchSize,
		}

	case "influxdb":
		options := influxdb2.DefaultOptions()
		if config.BatchSize > 0 {
			options.SetBatchSize(uint(config.BatchSize))
		}
		client := influxdb2.NewClientWithOptions(config.TimeSeries.URL, config.TimeSeries.Token, options)
		writeAPI := client.WriteAPI(config.TimeSeries.Org, config.TimeSeries.Bucket)

		errCh := writeAPI.Errors()
		errors := make(chan error, 100)

		backend = &influxDBBackend{
			writeAPI:  writeAPI,
			client:    client,
			batchSize: config.BatchSize,
			errCh:     errCh,
			errors:    errors,
		}

		go func() {
			for err := range errCh {
				fmt.Fprintf(os.Stderr, "influxdb write error: %v\n", err)
				// 尝试将错误发送到外部可访问的通道
				select {
				case errors <- err:
				default:
					// 如果通道满了，记录日志
					fmt.Fprintf(os.Stderr, "influxdb error channel full, dropping error: %v\n", err)
				}
			}
		}()
	default:
		return nil, fmt.Errorf("unsupported driver: %s", config.DriverName)
	}

	return newAsyncWriter(config, backend), nil
}

type LogEntry struct {
	Time    time.Time       `json:"time" gorm:"column:time"`
	Level   string          `json:"level" gorm:"column:level"`
	Message string          `json:"msg" gorm:"column:msg"`
	Caller  string          `json:"caller" gorm:"column:caller"`
	Stack   string          `json:"stack" gorm:"column:stack"`
	Fields  json.RawMessage `json:"fields" gorm:"type:json"`
}

type sqlStore struct {
	db        *gorm.DB
	table     string
	batchSize int
}

func (s *sqlStore) InsertBatch(ctx context.Context, entries []LogEntry) error {
	if len(entries) == 0 {
		return nil
	}
	return s.db.WithContext(ctx).Table(s.table).CreateInBatches(entries, s.batchSize).Error
	// return s.db.WithContext(ctx).Table(s.table).Create(&entries).Error
}

func (s *sqlStore) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

type influxDBBackend struct {
	client    influxdb2.Client
	writeAPI  api.WriteAPI // 使用非阻塞 API 进行高效批量写入
	batchSize int
	errCh     <-chan error
	errors    chan error
}

// NewinfluxDBBackend 创建新的 InfluxDB 适配器实例
// func NewinfluxDBBackend(url, token, org, bucket string) *influxDBBackend {
// 	client := influxdb2.NewClient(url, token)

// 	// 使用异步写入 API（带缓冲），更适合批量操作
// 	writeAPI := client.WriteAPI(org, bucket)

// 	// 可选配置：设置批处理大小（例如 1000 条自动 flush）
// 	// writeAPI.SetBatchSize(1000)
// 	// writeAPI.SetFlushInterval(1000) // ms

// 	backend := &influxDBBackend{
// 		url:      url,
// 		token:    token,
// 		org:      org,
// 		bucket:   bucket,
// 		client:   client,
// 		writeAPI: writeAPI,
// 	}

// 	return backend
// }

// InsertBatch 批量插入日志条目
func (b *influxDBBackend) InsertBatch(ctx context.Context, entries []LogEntry) error {
	if len(entries) == 0 {
		return nil
	}

	// 将日志条目转换为 InfluxDB Points 并写入缓冲区
	for _, entry := range entries {
		tags := map[string]string{
			"level":  entry.Level,
			"caller": entry.Caller,
		}

		fields := map[string]interface{}{
			"message": entry.Message,
			"stack":   entry.Stack,
		}

		var parsedFields map[string]interface{}
		if err := json.Unmarshal(entry.Fields, &parsedFields); err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse fields for log entry: %v\n", err)
			continue // 跳过解析失败的字段
		}

		for k, v := range parsedFields {
			fields[k] = v
		}

		pt := influxdb2.NewPoint(
			"logs",
			tags,
			fields,
			entry.Time,
		)

		// 添加到写入缓冲队列
		b.writeAPI.WritePoint(pt)
	}

	// 显式触发 flush，确保所有点发送
	// 注意：Flush 是同步调用，会阻塞直到完成或出错
	// b.writeAPI.Flush()
	return nil
}

// Close 关闭客户端并清理资源
func (b *influxDBBackend) Close() error {
	if b.client != nil {
		// 先 flush 剩余数据（如果有）
		b.writeAPI.Flush()

		b.client.Close()
		b.client = nil
		b.writeAPI = nil
	}
	return nil
}

func (b *influxDBBackend) HasError() error {
	select {
	case err := <-b.errors:
		return err
	default:
		return nil
	}
}

type asyncWriter struct {
	config  config.DatabaseConfig
	backend LogStore
	entries chan *core.LogEvent
	cancel  context.CancelFunc
}

func newAsyncWriter(config config.DatabaseConfig, backend LogStore) *asyncWriter {
	ctx, cancel := context.WithCancel(context.Background())
	aw := &asyncWriter{
		config:  config,
		backend: backend,
		entries: make(chan *core.LogEvent, config.BatchSize*10),
		cancel:  cancel,
	}
	go aw.run(ctx)
	return aw
}

func (w *asyncWriter) WriteEvent(event *core.LogEvent) error {
	select {
	case w.entries <- event:
	default:
		fmt.Fprintln(os.Stderr, "db log dropped: channel full (event)")
	}
	return nil
}

func (w *asyncWriter) Write(p []byte) (int, error) {
	event := &core.LogEvent{
		Timestamp: time.Now().UTC(),
		Level:     "unknown",
		Message:   "raw_byte_log_entry: " + string(sanitizeJSONFragment(p)),
		Fields:    map[string]any{"raw_bytes": string(p)},
	}
	_ = w.WriteEvent(event)
	return len(p), nil
}

func (w *asyncWriter) Sync() error { return nil }

func (w *asyncWriter) Close() error {
	w.cancel()
	close(w.entries)
	return w.backend.Close()
}

func (w *asyncWriter) run(ctx context.Context) {
	ticker := time.NewTicker(w.config.BatchInterval)
	defer ticker.Stop()

	var batch []LogEntry

	for {
		select {
		case event, ok := <-w.entries:
			if !ok {
				// channel closed
				goto flush
			}
			fieldsBytes, err := json.Marshal(event.Fields)
			if err != nil {
				zap.L().Warn("marshal fields failed, skip", zap.Error(err))
				fieldsBytes = []byte("{}")
			}

			entry := LogEntry{
				Time:    event.Timestamp,
				Level:   event.Level,
				Message: event.Message,
				Caller:  event.Caller,
				Stack:   event.Stack,
				Fields:  json.RawMessage(fieldsBytes),
			}
			batch = append(batch, entry)

			// 达到批次大小立即发送
			if len(batch) >= w.config.BatchSize {
				_ = w.backend.InsertBatch(ctx, batch)
				batch = batch[:0]
				w.checkBackendErrors()
			}
		case <-ticker.C:
			// 定时 flush
			if len(batch) > 0 {
				_ = w.backend.InsertBatch(ctx, batch)
				batch = batch[:0]
				if ib, ok := w.backend.(*influxDBBackend); ok {
					if err := ib.HasError(); err != nil {
						fmt.Fprintf(os.Stderr, "detected backend error: %v\n", err)
					}
				}
			}
		case <-ctx.Done():
			goto flush
		}
	}

flush:
	// 最后 flush 剩余数据
	if len(batch) > 0 {
		// 使用带超时的 context
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()

		var err error
		for i := 0; i < 3; i++ {
			err = w.backend.InsertBatch(ctx, batch)
			if err == nil {
				break
			}
			time.Sleep(w.config.RetryDelay)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to flush batch to database: %v", err)
		}
	}
}

func (w *asyncWriter) checkBackendErrors() {
	if ib, ok := w.backend.(*influxDBBackend); ok {
		if err := ib.HasError(); err != nil {
			fmt.Fprintf(os.Stderr, "detected backend error: %v\n", err)
		}
	}
}

func sanitizeJSONFragment(data []byte) []byte {
	var buf bytes.Buffer
	for _, b := range data {
		if b >= 32 && b <= 126 {
			buf.WriteByte(b)
		} else if b == '\n' || b == '\t' || b == '\r' {
			buf.WriteByte(' ')
		}
	}
	return buf.Bytes()
}

// func toString(v interface{}) string {
// 	if v == nil {
// 		return ""
// 	}
// 	s, ok := v.(string)
// 	if ok {
// 		return s
// 	}
// 	return fmt.Sprintf("%v", v)
// }
