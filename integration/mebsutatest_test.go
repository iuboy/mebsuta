// File: integration_test.go
// 🧪 使用 Docker 容器运行真实数据库，进行高保真集成测试
//
//go:build integration
// +build integration

package mebsuta_test

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/config"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/testcontainers/testcontainers-go"
	mysqlcontainer "github.com/testcontainers/testcontainers-go/modules/mysql"
	postgrescontainer "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	TestLogFile     = "/tmp/mebsuta-integration-test.log"
	TestServiceName = "integration-test-app"
	TestRequestID   = "req-test-123"
)

// ================== 1. Mock Syslog Server ==================
type syslogServer struct {
	listener net.Listener
	msgCh    chan string
	done     chan struct{}
	once     sync.Once
	stopped  int32 // 原子操作标志
}

func startMockSyslog(t *testing.T) *syslogServer {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	s := &syslogServer{
		listener: listener,
		msgCh:    make(chan string, 500),
		done:     make(chan struct{}),
	}

	go func() {
		<-s.done
		s.listener.Close()
		s.once.Do(func() {
			close(s.msgCh)
		})
	}()

	go func() {
		for {
			conn, err := s.listener.Accept()
			if err != nil {
				return
			}
			go s.handleConn(t, conn)
		}
	}()

	return s
}

func (s *syslogServer) handleConn(t *testing.T, conn net.Conn) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		// 检查服务器是否已停止
		if atomic.LoadInt32(&s.stopped) != 0 {
			return
		}
		select {
		case <-s.done:
			return
		case s.msgCh <- scanner.Text():
		}
	}
}

func (s *syslogServer) Addr() string {
	return s.listener.Addr().String()
}

func (s *syslogServer) Stop() {
	atomic.StoreInt32(&s.stopped, 1)
	close(s.done)
}

func (s *syslogServer) GetEntries(timeout time.Duration) []string {
	var entries []string
	timer := time.NewTimer(timeout)
	defer timer.Stop()

loop:
	for {
		select {
		case msg, ok := <-s.msgCh:
			if !ok {
				break loop
			}
			entries = append(entries, msg)
		case <-timer.C:
			break loop
		}
	}
	return entries
}

// ================== 2. 启动 MySQL 容器 ==================
func startMySQLContainer(t *testing.T) (*sql.DB, string, func()) {
	ctx := context.Background()

	container, err := mysqlcontainer.Run(ctx,
		"mysql:8.4",
		testcontainers.WithImage("mysql:8.4"),
		testcontainers.WithEnv(map[string]string{
			"MYSQL_ROOT_PASSWORD": "test",
			"MYSQL_DATABASE":      "logs",
		}),
		testcontainers.WithWaitStrategy(
			wait.ForLog("port: 3306").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, container.Terminate(ctx))
	})

	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "3306/tcp")
	require.NoError(t, err)

	dsn := fmt.Sprintf("root:test@tcp(%s)/logs", net.JoinHostPort(host, port.Port()))

	var db *sql.DB
	require.Eventually(t, func() bool {
		db, err = sql.Open("mysql", dsn)
		if err != nil {
			return false
		}
		err = db.Ping()
		if err != nil {
			db.Close()
			return false
		}
		return true
	}, 15*time.Second, 500*time.Millisecond)

	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS logs (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            time DATETIME(6) NOT NULL,
            level VARCHAR(10) NOT NULL,
            msg TEXT,
            caller VARCHAR(256),
            stack TEXT,
            fields JSON,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `)
	require.NoError(t, err)

	return db, dsn, func() {
		db.Close()
	}
}

// ================== 3. 启动 PostgreSQL 容器 ==================
func startPostgreSQLContainer(t *testing.T) (*sql.DB, string, func()) {
	ctx := context.Background()

	container, err := postgrescontainer.Run(ctx,
		"postgres:16",
		testcontainers.WithImage("postgres:16"),
		testcontainers.WithEnv(map[string]string{
			"POSTGRES_USER":     "postgres",
			"POSTGRES_PASSWORD": "test",
			"POSTGRES_DB":       "logs",
		}),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, container.Terminate(ctx))
	})

	// 使用 testcontainers 提供的连接字符串方法
	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	var db *sql.DB
	require.Eventually(t, func() bool {
		db, err = sql.Open("postgres", connStr)
		if err != nil {
			t.Logf("PostgreSQL 连接失败: %v", err)
			return false
		}
		err = db.Ping()
		if err != nil {
			t.Logf("PostgreSQL Ping 失败: %v", err)
			db.Close()
			return false
		}
		return true
	}, 20*time.Second, 500*time.Millisecond)

	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS logs (
            id SERIAL PRIMARY KEY,
            time TIMESTAMP(6) NOT NULL,
            level VARCHAR(10) NOT NULL,
            msg TEXT,
            caller VARCHAR(256),
            stack TEXT,
            fields JSONB,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `)
	require.NoError(t, err)

	return db, connStr, func() {
		db.Close()
	}
}

// ================== 4. 设置测试 ==================
func setupTest(t *testing.T) (*sql.DB, *syslogServer) {
	os.Remove(TestLogFile)

	syslogSrv := startMockSyslog(t)
	t.Cleanup(syslogSrv.Stop)

	db, mysqlDSN, cleanupDB := startMySQLContainer(t)
	t.Cleanup(cleanupDB)

	cfg := config.LoggerConfig{
		ServiceName: TestServiceName,
		Outputs: []config.OutputConfig{
			{
				Type:     config.Stdout,
				Level:    config.InfoLevel,
				Encoding: config.JSON,
				Enabled:  true,
			},
			{
				Type:     config.File,
				Level:    config.DebugLevel,
				Encoding: config.JSON,
				Enabled:  true,
				File: &config.FileConfig{
					Path:            TestLogFile,
					MaxSizeMB:       10,
					MaxBackups:      2,
					MaxAgeDays:      7,
					Compress:        false,
					RotateOnStartup: true,
					LocalTime:       true,
				},
			},
			{
				Type:     config.DB,
				Level:    config.WarnLevel,
				Encoding: config.JSON,
				Enabled:  true,
				Database: &config.DatabaseConfig{
					DriverName:     "mysql",
					DataSourceName: mysqlDSN,
					TableName:      "logs",
					BatchSize:      2,
					BatchInterval:  200 * time.Millisecond,
				},
			},
			{
				Type:     config.Syslog,
				Level:    config.InfoLevel,
				Encoding: config.JSON,
				Enabled:  true,
				Syslog: &config.SyslogConfig{
					Network:       "tcp",
					Address:       syslogSrv.Addr(),
					Tag:           "test-tag",
					Facility:      16,
					RFC5424:       true,
					JSONInMessage: true,
					BufferSize:    100,
					TimeZone:      "UTC",
				},
			},
		},
		Encoder: config.EncoderConfig{
			TimeFormat:    time.RFC3339Nano,
			TimeZone:      "UTC",
			MessageKey:    "msg",
			LevelKey:      "level",
			TimeKey:       "ts",
			CallerKey:     "caller",
			StacktraceKey: "stacktrace",
			EnableCaller:  true,
			CustomFields:  map[string]string{"env": "test"},
		},
	}

	err := mebsuta.Init(cfg)
	require.NoError(t, err)

	// 使用标准 context key 类型
	mebsuta.SetContextExtractor(func(ctx context.Context) []zap.Field {
		if id, ok := ctx.Value(mebsuta.RequestContextKey).(string); ok {
			return []zap.Field{zap.String("request_id", id)}
		}
		return nil
	})

	t.Cleanup(func() {
		mebsuta.Sync()
		time.Sleep(200 * time.Millisecond)
	})

	return db, syslogSrv
}

// ================== 5. 主测试 ==================
func TestExternalAppLoggingFlow(t *testing.T) {
	db, syslogSrv := setupTest(t)

	ctx := context.WithValue(context.Background(), mebsuta.RequestContextKey, TestRequestID)
	logger := mebsuta.WithContext(ctx)

	logger.Debug("Debug message")
	logger.Info("Info message")
	logger.Warn("警告: 即将过期")
	logger.Error("数据库连接失败", zap.String("host", "db1.internal"))

	logger.Sugar().Infof("用户登录: %s", "alice")
	logger.Sugar().Errorf("订单失败: %s", "ORDER123")

	logger.Info("HTTP 请求",
		zap.String("method", "POST"),
		zap.String("path", "/api/v1/user"),
		zap.Int("status", 500))

	logger.Error("panic 模拟",
		zap.Int("code", 999),
		zap.Stack("stack"),
	)

	mebsuta.Sync()
	time.Sleep(800 * time.Millisecond)

	t.Run("File Output", func(t *testing.T) {
		content, err := os.ReadFile(TestLogFile)
		require.NoError(t, err)
		assert.Contains(t, string(content), `"level":"warn"`)
		assert.Contains(t, string(content), `"request_id":"`+TestRequestID+`"`)
		assert.Contains(t, string(content), `"method":"POST"`)
		assert.Contains(t, string(content), `"env":"test"`)
	})

	t.Run("Syslog Output", func(t *testing.T) {
		messages := syslogSrv.GetEntries(800 * time.Millisecond)
		assert.Greater(t, len(messages), 5)
		found := false
		for _, msg := range messages {
			if strings.Contains(msg, `"path":"/api/v1/user"`) {
				found = true
				assert.Contains(t, msg, `"request_id":"`+TestRequestID+`"`)
				break
			}
		}
		assert.True(t, found, "syslog 未收到结构化日志")
	})

	t.Run("MySQL DB Write", func(t *testing.T) {
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM logs WHERE level = 'error' OR level = 'warn'").Scan(&count)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, count, 3)

		var msg, fields string
		err = db.QueryRow("SELECT msg, fields FROM logs WHERE msg LIKE '%数据库连接失败%' ORDER BY time DESC LIMIT 1").
			Scan(&msg, &fields)
		require.NoError(t, err)
		assert.Contains(t, msg, "数据库连接失败")
		assert.Contains(t, fields, "host")
		assert.Contains(t, fields, "db1.internal")
		assert.Contains(t, fields, "request_id")
		assert.Contains(t, fields, TestRequestID)
	})

	t.Log("所有集成测试通过！真实数据库写入验证成功。")
}

// ================== 6. 采样功能集成测试 ==================
func TestSamplingIntegration(t *testing.T) {
	os.Remove(TestLogFile)

	cfg := config.LoggerConfig{
		ServiceName: TestServiceName,
		Sampling: config.SamplingConfig{
			Enabled:    true,
			Initial:    5,
			Thereafter: 3,
			Window:     500 * time.Millisecond,
		},
		Outputs: []config.OutputConfig{
			{
				Type:     config.File,
				Level:    config.InfoLevel,
				Encoding: config.JSON,
				Enabled:  true,
				File: &config.FileConfig{
					Path:       TestLogFile,
					MaxSizeMB:  10,
					MaxBackups: 2,
					MaxAgeDays: 7,
				},
			},
		},
	}

	// 使用独立的 logger 实例避免全局状态冲突
	logger, err := mebsuta.CreateLogger(cfg)
	require.NoError(t, err)
	defer logger.Sync()

	// 记录 20 条日志
	for i := 0; i < 20; i++ {
		logger.Info(fmt.Sprintf("日志消息 %d", i))
	}

	// 等待文件写入完成
	time.Sleep(1 * time.Second)

	// 等待文件存在
	require.Eventually(t, func() bool {
		_, err := os.Stat(TestLogFile)
		return err == nil
	}, 2*time.Second, 100*time.Millisecond, "日志文件应该被创建")

	// 读取文件并计数
	content, err := os.ReadFile(TestLogFile)
	require.NoError(t, err)

	lines := strings.Split(string(content), "\n")
	count := 0
	for _, line := range lines {
		if strings.Contains(line, `"level":"info"`) {
			count++
		}
	}

	// 前 5 条全部记录，之后每 3 条记录 1 条
	// 5 + ceil((20-5)/3) = 5 + 5 = 10 条左右
	t.Logf("记录了 %d 条日志", count)
	assert.Greater(t, count, 8, "应该记录至少 8 条日志")
	assert.Less(t, count, 15, "应该记录少于 15 条日志")
}

// ================== 7. PostgreSQL 集成测试 ==================
func TestPostgreSQLIntegration(t *testing.T) {
	// 清理之前的 logger
	mebsuta.Sync()
	time.Sleep(200 * time.Millisecond)

	db, pgDSN, cleanupDB := startPostgreSQLContainer(t)
	defer cleanupDB()

	cfg := config.LoggerConfig{
		ServiceName: TestServiceName,
		Outputs: []config.OutputConfig{
			{
				Type:     config.DB,
				Level:    config.InfoLevel,
				Encoding: config.JSON,
				Enabled:  true,
				Database: &config.DatabaseConfig{
					DriverName:     "postgres",
					DataSourceName: pgDSN,
					TableName:      "logs",
					BatchSize:      5,
					BatchInterval:  500 * time.Millisecond,
				},
			},
		},
	}

	// 使用独立的 logger 实例避免全局状态冲突
	logger, err := mebsuta.CreateLogger(cfg)
	require.NoError(t, err)
	defer logger.Sync()

	// 记录不同级别的日志
	logger.Info("PostgreSQL Info 日志", zap.String("type", "pg_test"))
	logger.Warn("PostgreSQL Warn 日志")
	logger.Error("PostgreSQL Error 日志", zap.Int("code", 500))

	// 等待批量写入完成（批量间隔是 500ms）
	time.Sleep(1 * time.Second)

	// 验证数据库写入
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM logs").Scan(&count)
	require.NoError(t, err)
	t.Logf("数据库中有 %d 条日志", count)
	assert.GreaterOrEqual(t, count, 3)

	// 验证字段
	var msg string
	err = db.QueryRow("SELECT msg FROM logs WHERE msg LIKE '%PostgreSQL Info%' LIMIT 1").Scan(&msg)
	require.NoError(t, err)
	assert.Contains(t, msg, "PostgreSQL Info")

	t.Log("PostgreSQL 集成测试通过")
}

// ================== 8. Builder 模式集成测试 ==================
func TestBuilderIntegration(t *testing.T) {
	os.Remove(TestLogFile)

	cfg, err := config.NewLoggerConfigBuilder("builder-test").
		AddFileOutput(config.InfoLevel, config.JSON, TestLogFile,
			config.WithFileRotation(10, 2, 7),
		).
		Build()

	require.NoError(t, err)

	// 使用独立的 logger 实例进行测试
	logger, err := mebsuta.CreateLogger(*cfg)
	require.NoError(t, err)
	defer logger.Sync()

	logger.Info("Builder 模式测试")
	logger.Error("错误日志")

	// 等待文件被写入
	time.Sleep(500 * time.Millisecond)

	// 验证文件写入
	content, err := os.ReadFile(TestLogFile)
	require.NoError(t, err)
	assert.Contains(t, string(content), "Builder 模式测试")

	t.Log("Builder 模式集成测试通过")
}

// ================== 9. 并发安全集成测试 ==================
func TestConcurrencyIntegration(t *testing.T) {
	os.Remove(TestLogFile)

	cfg := config.LoggerConfig{
		ServiceName: "concurrency-test",
		Outputs: []config.OutputConfig{
			{
				Type:     config.File,
				Level:    config.InfoLevel,
				Encoding: config.JSON,
				Enabled:  true,
				File: &config.FileConfig{
					Path:       TestLogFile,
					MaxSizeMB:  10,
					MaxBackups: 2,
					MaxAgeDays: 7,
				},
			},
		},
	}

	// 使用独立的 logger 实例进行测试
	logger, err := mebsuta.CreateLogger(cfg)
	require.NoError(t, err)
	defer logger.Sync()

	// 并发写入
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				logger.Info(fmt.Sprintf("goroutine-%d message-%d", id, j))
			}
			done <- true
		}(i)
	}

	// 等待所有 goroutine 完成
	for i := 0; i < 10; i++ {
		<-done
	}

	// 等待文件写入完成
	time.Sleep(1000 * time.Millisecond)

	// 验证文件内容
	content, err := os.ReadFile(TestLogFile)
	require.NoError(t, err)

	lines := strings.Split(string(content), "\n")
	count := 0
	for _, line := range lines {
		if strings.Contains(line, `"level":"info"`) {
			count++
		}
	}

	assert.Equal(t, 1000, count, "应该记录所有 1000 条日志")

	t.Log("并发安全集成测试通过")
}

// ================== 10. 错误处理集成测试 ==================
func TestErrorHandlingIntegration(t *testing.T) {
	// 清理之前的 logger
	mebsuta.Sync()
	time.Sleep(100 * time.Millisecond)

	t.Run("无效数据库配置", func(t *testing.T) {
		cfg := config.LoggerConfig{
			ServiceName: TestServiceName,
			Outputs: []config.OutputConfig{
				{
					Type:     config.DB,
					Level:    config.InfoLevel,
					Encoding: config.JSON,
					Enabled:  true,
					Database: &config.DatabaseConfig{
						DriverName:     "mysql",
						DataSourceName: "invalid-dsn",
						TableName:      "logs",
					},
				},
			},
		}

		err := mebsuta.Init(cfg)
		// 初始化应该成功，但数据库写入会失败
		// 错误会记录到 stderr，不会导致程序崩溃
		assert.NoError(t, err)

		mebsuta.Info("测试日志")
		mebsuta.Sync()
	})

	t.Run("空文件路径", func(t *testing.T) {
		cfg := config.LoggerConfig{
			ServiceName: TestServiceName,
			Outputs: []config.OutputConfig{
				{
					Type:     config.File,
					Level:    config.InfoLevel,
					Encoding: config.JSON,
					Enabled:  true,
					File: &config.FileConfig{
						Path:      "",
						MaxSizeMB: 10,
					},
				},
			},
		}

		_, err := mebsuta.CreateLogger(cfg)
		// 应该返回错误，因为文件路径为空
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "文件路径不能为空")
	})

	t.Run("无效输出类型", func(t *testing.T) {
		cfg := config.LoggerConfig{
			ServiceName: TestServiceName,
			Outputs: []config.OutputConfig{
				{
					Type:    config.OutputType("invalid-type"),
					Level:   config.InfoLevel,
					Enabled: true,
				},
			},
		}

		_, err := mebsuta.CreateLogger(cfg)
		// 应该返回错误
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "无效的输出类型")
	})
}

// ================== 11. Syslog 集成测试 ==================
func TestSyslogIntegration(t *testing.T) {
	// 清理之前的 logger
	mebsuta.Sync()
	time.Sleep(100 * time.Millisecond)
	os.Remove(TestLogFile)

	// 启动 mock syslog server
	syslogSrv := startMockSyslog(t)
	defer syslogSrv.Stop()

	cfg := config.LoggerConfig{
		ServiceName: TestServiceName,
		Outputs: []config.OutputConfig{
			{
				Type:     config.Syslog,
				Level:    config.InfoLevel,
				Encoding: config.JSON,
				Enabled:  true,
				Syslog: &config.SyslogConfig{
					Network:       "tcp",
					Address:       syslogSrv.Addr(),
					Tag:           "mebsuta-test",
					Facility:      16, // local use
					RFC5424:       true,
					JSONInMessage: true,
					BufferSize:    100,
					TimeZone:      "Local",
				},
			},
		},
		Encoder: config.EncoderConfig{
			TimeFormat:   time.RFC3339,
			TimeZone:     "Local",
			MessageKey:   "msg",
			LevelKey:     "level",
			TimeKey:      "ts",
			EnableCaller: true,
		},
	}

	logger, err := mebsuta.CreateLogger(cfg)
	require.NoError(t, err)
	defer logger.Sync()

	// 添加字段验证上下文提取和字段传递
	logger = logger.With(
		zap.String("request_id", "syslog-test-123"),
		zap.String("component", "syslog-test"),
	)

	// 记录各种级别的日志
	logger.Debug("这是 Debug 消息 - 不应该发送到 syslog")
	logger.Info("这是 Info 消息", zap.String("user", "alice"))
	logger.Warn("这是 Warn 消息", zap.Int("retry_count", 3))
	logger.Error("这是 Error 消息", zap.String("error_code", "E500"))

	// 记录结构化数据
	logger.Info("用户操作",
		zap.String("action", "login"),
		zap.String("user_id", "12345"),
		zap.String("ip", "192.168.1.100"),
	)

	// 等待 syslog 消息
	time.Sleep(500 * time.Millisecond)

	// 验证 syslog 消息
	messages := syslogSrv.GetEntries(800 * time.Millisecond)

	t.Logf("收到 %d 条 syslog 消息", len(messages))

	// 至少应该收到 Info、Warn、Error 级别的消息
	assert.Greater(t, len(messages), 3, "应该至少收到 3 条 syslog 消息")

	// 验证特定内容
	foundUserAction := false
	foundRequestId := false
	foundComponent := false

	for _, msg := range messages {
		if strings.Contains(msg, `"action":"login"`) {
			foundUserAction = true
			assert.Contains(t, msg, `"user_id":"12345"`)
			assert.Contains(t, msg, `"ip":"192.168.1.100"`)
		}
		if strings.Contains(msg, `"request_id":"syslog-test-123"`) {
			foundRequestId = true
		}
		if strings.Contains(msg, `"component":"syslog-test"`) {
			foundComponent = true
		}
	}

	assert.True(t, foundUserAction, "应该找到用户操作日志")
	assert.True(t, foundRequestId, "应该找到 request_id")
	assert.True(t, foundComponent, "应该找到 component 字段")

	t.Log("Syslog 集成测试通过")
}
