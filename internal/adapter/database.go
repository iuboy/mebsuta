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
	meberrors "github.com/iuboy/mebsuta/errors"
	"github.com/iuboy/mebsuta/metrics"
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
			return nil, meberrors.Wrap(err, meberrors.ErrCodeDBConnectFailed, fmt.Sprintf("连接%s数据库失败", config.DriverName))
		}

		sqlDB, err := gdb.DB()
		if err != nil {
			return nil, meberrors.Wrap(err, meberrors.ErrCodeDBConnect, "获取数据库连接失败")
		}

		sqlDB.SetMaxIdleConns(config.MaxIdleConns)
		sqlDB.SetMaxOpenConns(config.MaxOpenConns)
		sqlDB.SetConnMaxLifetime(config.MaxConnLifetime)

		// 更新连接池指标
		metrics.GetMetrics().SetActiveConns(float64(config.MaxOpenConns))
		metrics.GetMetrics().SetIdleConns(float64(config.MaxIdleConns))

		backend = &sqlStore{
			db:         gdb,
			table:      config.TableName,
			batchSize:  config.BatchSize,
			driverName: config.DriverName,
		}

	case "influxdb":
		options := influxdb2.DefaultOptions()
		if config.BatchSize > 0 {
			options.SetBatchSize(uint(config.BatchSize))
		}
		client := influxdb2.NewClientWithOptions(config.TimeSeries.URL, config.TimeSeries.Token, options)
		writeAPI := client.WriteAPI(config.TimeSeries.Org, config.TimeSeries.Bucket)

		errCh := writeAPI.Errors()
		errorChan := make(chan error, 100)

		// 创建上下文用于goroutine控制
		errCtx, errCancel := context.WithCancel(context.Background())

		backend = &influxDBBackend{
			writeAPI:  writeAPI,
			client:    client,
			batchSize: config.BatchSize,
			errCh:     errCh,
			errors:    errorChan,
			url:       config.TimeSeries.URL,
			org:       config.TimeSeries.Org,
			bucket:    config.TimeSeries.Bucket,
			errCancel: errCancel,
			errCtx:    errCtx,
		}

		// 监听InfluxDB写入错误（添加上下文控制）
		go func() {
			defer metrics.GetMetrics().DecGoroutine()
			defer close(errorChan)
			metrics.GetMetrics().IncGoroutine()

			for {
				select {
				case err, ok := <-errCh:
					if !ok {
						return
					}
					metrics.GetMetrics().IncLogError("influxdb_write", "influxdb")
					fmt.Fprintf(os.Stderr, "influxdb write error: %v\n", err)
					select {
					case errorChan <- err:
					default:
						metrics.GetMetrics().IncLogError("error_channel_full", "influxdb")
						fmt.Fprintf(os.Stderr, "influxdb error channel full, dropping error: %v\n", err)
					}
				case <-errCtx.Done():
					return
				}
			}
		}()
	default:
		return nil, meberrors.ErrUnsupportedType(fmt.Sprintf("不支持的数据库驱动: %s", config.DriverName))
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
	db         *gorm.DB
	table      string
	batchSize  int
	driverName string
}

// InsertBatch 批量插入日志到SQL数据库
func (s *sqlStore) InsertBatch(ctx context.Context, entries []LogEntry) error {
	if len(entries) == 0 {
		return nil
	}

	start := time.Now()
	err := s.db.WithContext(ctx).Table(s.table).CreateInBatches(entries, s.batchSize).Error
	latency := time.Since(start).Seconds()

	// 记录metrics
	metrics.GetMetrics().ObserveBatchLatency(latency)
	metrics.GetMetrics().ObserveBatchSize(float64(len(entries)))
	metrics.GetMetrics().IncBatchWrite()

	if err != nil {
		metrics.GetMetrics().IncBatchFailure()
		metrics.GetMetrics().IncLogError("batch_insert", s.driverName)
		return meberrors.Wrap(err, meberrors.ErrCodeDBWrite, fmt.Sprintf("批量插入%s数据库失败", s.driverName))
	}

	return nil
}

// Close 关闭数据库连接
func (s *sqlStore) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return meberrors.Wrap(err, meberrors.ErrCodeDBConnect, "获取数据库连接失败")
	}

	if err := sqlDB.Close(); err != nil {
		return meberrors.Wrap(err, meberrors.ErrCodeDBConnect, fmt.Sprintf("关闭%s数据库连接失败", s.driverName))
	}

	return nil
}

type influxDBBackend struct {
	client    influxdb2.Client
	writeAPI  api.WriteAPI
	batchSize int
	errCh     <-chan error
	errors    chan error
	url       string
	org       string
	bucket    string
	errCancel context.CancelFunc // 用于停止goroutine
	errCtx    context.Context    // 用于goroutine控制
}

// InsertBatch 批量插入日志到InfluxDB
func (b *influxDBBackend) InsertBatch(ctx context.Context, entries []LogEntry) error {
	if len(entries) == 0 {
		return nil
	}

	start := time.Now()
	successCount := 0

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
			metrics.GetMetrics().IncLogError("parse_fields", "influxdb")
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
		successCount++
	}

	// 记录metrics
	latency := time.Since(start).Seconds()
	metrics.GetMetrics().ObserveBatchLatency(latency)
	metrics.GetMetrics().ObserveBatchSize(float64(len(entries)))
	metrics.GetMetrics().IncBatchWrite()

	if successCount == 0 {
		return meberrors.ErrDBWrite("所有日志条目解析失败")
	}

	return nil
}

// Close 关闭InfluxDB客户端并清理资源
func (b *influxDBBackend) Close() error {
	if b.client != nil {
		// 停止错误监听goroutine
		if b.errCancel != nil {
			b.errCancel()
			b.errCancel = nil
		}

		// 先 flush 剩余数据（如果有）
		// 注意: InfluxDB v2的Flush()方法不返回错误，错误通过Errors() channel异步返回
		b.writeAPI.Flush()

		// 检查是否有pending的错误
		select {
		case err := <-b.errors:
			if err != nil {
				return fmt.Errorf("InfluxDB flush检测到错误: %w", err)
			}
		default:
			// 没有pending错误
		}

		b.client.Close()
		b.client = nil
		b.writeAPI = nil
	}
	return nil
}

// HasError 检查是否有写入错误
func (b *influxDBBackend) HasError() error {
	select {
	case err := <-b.errors:
		return meberrors.Wrap(err, meberrors.ErrCodeDBWrite, "InfluxDB写入错误")
	default:
		return nil
	}
}

type asyncWriter struct {
	config     config.DatabaseConfig
	backend    LogStore
	entries    chan *core.LogEvent
	cancel     context.CancelFunc
	outputType string
	capacity   int
}

// newAsyncWriter 创建异步写入器
func newAsyncWriter(config config.DatabaseConfig, backend LogStore) *asyncWriter {
	ctx, cancel := context.WithCancel(context.Background())
	capacity := config.BatchSize * 10
	aw := &asyncWriter{
		config:     config,
		backend:    backend,
		entries:    make(chan *core.LogEvent, capacity),
		cancel:     cancel,
		outputType: config.DriverName,
		capacity:   capacity,
	}
	go aw.run(ctx)
	return aw
}

// WriteEvent 写入日志事件
func (w *asyncWriter) WriteEvent(event *core.LogEvent) error {
	select {
	case w.entries <- event:
		// 更新缓冲区使用率
		usage := float64(len(w.entries)) / float64(w.capacity)
		metrics.GetMetrics().SetBufferUsage(usage)
		return nil
	default:
		metrics.GetMetrics().IncBufferFull()
		metrics.GetMetrics().IncLogDropped("buffer_full", w.outputType)
		fmt.Fprintln(os.Stderr, "db log dropped: channel full (event)")
		return fmt.Errorf("buffer full, log dropped")
	}
}

// Write 实现io.Writer接口
func (w *asyncWriter) Write(p []byte) (int, error) {
	event := &core.LogEvent{
		Timestamp: time.Now().UTC(),
		Level:     "unknown",
		Message:   "raw_byte_log_entry: " + string(sanitizeJSONFragment(p)),
		Fields:    map[string]any{"raw_bytes": string(p)},
	}
	if err := w.WriteEvent(event); err != nil {
		return 0, fmt.Errorf("写入事件失败: %w", err)
	}
	return len(p), nil
}

// Sync 同步缓冲区
// 注意: 这是异步写入器，Sync只能确保当前缓冲区中的数据已发送给后端，
// 但不能保证数据已持久化到数据库。如果需要强一致性，请使用同步写入器。
func (w *asyncWriter) Sync() error {
	// 检查后端是否有pending错误
	if ib, ok := w.backend.(*influxDBBackend); ok {
		if err := ib.HasError(); err != nil {
			return err
		}
	}
	// 对于异步写入器，我们无法直接等待数据持久化
	// 只能确保数据已发送到缓冲队列
	return nil
}

// Close 关闭异步写入器
func (w *asyncWriter) Close() error {
	w.cancel()
	close(w.entries)
	return w.backend.Close()
}

// run 运行异步写入循环
func (w *asyncWriter) run(ctx context.Context) {
	defer metrics.GetMetrics().DecGoroutine()
	metrics.GetMetrics().IncGoroutine()

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
				metrics.GetMetrics().IncLogError("marshal_fields", w.outputType)
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

			// 更新缓冲区使用率
			usage := float64(len(w.entries)) / float64(w.capacity)
			metrics.GetMetrics().SetBufferUsage(usage)

			// 达到批次大小立即发送
			if len(batch) >= w.config.BatchSize {
				if err := w.backend.InsertBatch(ctx, batch); err != nil {
					fmt.Fprintf(os.Stderr, "batch insert failed: %v\n", err)
				}
				batch = batch[:0]
				w.checkBackendErrors()
			}
		case <-ticker.C:
			// 定时 flush
			if len(batch) > 0 {
				if err := w.backend.InsertBatch(ctx, batch); err != nil {
					fmt.Fprintf(os.Stderr, "timed flush failed: %v\n", err)
				}
				batch = batch[:0]
				w.checkBackendErrors()
			}
		case <-ctx.Done():
			goto flush
		}
	}

flush:
	// 最后 flush 剩余数据
	if len(batch) > 0 {
		// 使用带超时的 context
		flushCtx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()

		var err error
		for i := 0; i < 3; i++ {
			err = w.backend.InsertBatch(flushCtx, batch)
			if err == nil {
				break
			}
			metrics.GetMetrics().IncBatchFailure()
			time.Sleep(w.config.RetryDelay)
		}
		if err != nil {
			metrics.GetMetrics().IncLogError("flush_failed", w.outputType)
			fmt.Fprintf(os.Stderr, "failed to flush batch to database: %v\n", err)
		}
	}
}

// checkBackendErrors 检查后端错误
func (w *asyncWriter) checkBackendErrors() {
	if ib, ok := w.backend.(*influxDBBackend); ok {
		if err := ib.HasError(); err != nil {
			metrics.GetMetrics().IncLogError("backend_error", w.outputType)
			fmt.Fprintf(os.Stderr, "detected backend error: %v\n", err)
		}
	}
}

// sanitizeJSONFragment 清理JSON片段，移除不可打印字符
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
