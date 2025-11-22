// File: mebsutatest_integration_test.go
// 🧪 使用 Docker 容器运行真实数据库，进行高保真集成测试

package mebsuta_test

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/testcontainers/testcontainers-go"
	mysqlcontainer "github.com/testcontainers/testcontainers-go/modules/mysql"
	"github.com/testcontainers/testcontainers-go/wait"
)

type contextKey string

const (
	TestLogFile                = "/tmp/mebsuta-integration-test.log"
	TestServiceName            = "integration-test-app"
	TestRequestID              = "req-test-123"
	requestIDKey    contextKey = "request_id"
)

var (
	syslogMessagesCh = make(chan string, 500)
	syslogDone       = make(chan struct{})
)

// ================== 1. Mock Syslog Server ==================
func startMockSyslog(t *testing.T) (string, func()) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		for {
			select {
			case <-syslogDone:
				return
			default:
			}
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleSyslogConn(t, conn)
		}
	}()

	addr := listener.Addr().String()
	return addr, func() {
		close(syslogDone)
		listener.Close()
		time.Sleep(10 * time.Millisecond)
	}
}

func handleSyslogConn(t *testing.T, conn net.Conn) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		select {
		case syslogMessagesCh <- scanner.Text():
		default:
			t.Log("syslog channel full")
		}
	}
}

func getSyslogEntries(timeout time.Duration) []string {
	var entries []string
	timer := time.NewTimer(timeout)
	defer timer.Stop()

loop:
	for {
		select {
		case msg := <-syslogMessagesCh:
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
	// ✅ 获取容器映射的动态端口（走 Docker 内部网络）
	port, err := container.MappedPort(ctx, "3306/tcp")
	require.NoError(t, err)

	// ✅ 构建 DSN：使用返回的 host:port（通常是 localhost + 随机 high port）
	dsn := fmt.Sprintf("root:test@tcp(%s)/logs", net.JoinHostPort(host, port.Port()))

	// 等待数据库可连接
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

	// 创建表
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

// ================== 3. 设置测试 ==================
func setupTest(t *testing.T) *sql.DB {
	os.Remove(TestLogFile)

	close(syslogDone)
	syslogMessagesCh = make(chan string, 500)
	syslogDone = make(chan struct{})

	// 启动 mock syslog server
	syslogAddr, shutdownSyslog := startMockSyslog(t)
	t.Cleanup(shutdownSyslog)

	// 启动 MySQL 容器并获取真实 DSN
	db, mysqlDSN, cleanupDB := startMySQLContainer(t)
	t.Cleanup(cleanupDB)

	// ✅ 使用动态 DSN（如：root:test@tcp(localhost:32788)/logs）
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
					DataSourceName: mysqlDSN, // ✅ 动态传入！
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
					Address:       syslogAddr,
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

	mebsuta.SetContextExtractor(func(ctx context.Context) []zap.Field {
		if id, ok := ctx.Value(requestIDKey).(string); ok {
			return []zap.Field{zap.String("request_id", id)}
		}
		t.Log("❌ ContextExtractor 未取到 request_id")
		return nil
	})

	t.Cleanup(func() {
		mebsuta.Sync()
		time.Sleep(200 * time.Millisecond)
	})

	return db
}

// ================== 4. 主测试 ==================
func TestExternalAppLoggingFlow(t *testing.T) {
	db := setupTest(t)

	ctx := context.WithValue(context.Background(), requestIDKey, TestRequestID)
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

	// ========== 验证 ==========
	t.Run("✅ File Output", func(t *testing.T) {
		content, err := os.ReadFile(TestLogFile)
		require.NoError(t, err)
		assert.Contains(t, string(content), `"level":"warn"`)
		assert.Contains(t, string(content), `"request_id":"`+TestRequestID+`"`)
		assert.Contains(t, string(content), `"method":"POST"`)
		assert.Contains(t, string(content), `"env":"test"`)
	})

	t.Run("✅ Syslog Output", func(t *testing.T) {
		messages := getSyslogEntries(800 * time.Millisecond)
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

	t.Run("✅ MySQL DB Write", func(t *testing.T) {
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM logs WHERE level = 'error' OR level = 'warn'").Scan(&count)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, count, 3, "数据库应写入至少 3 条 warn/error 日志")

		// 检查字段
		var msg, fields string
		err = db.QueryRow("SELECT msg, fields FROM logs WHERE level = 'error' ORDER BY time DESC LIMIT 1").
			Scan(&msg, &fields)
		require.NoError(t, err)
		assert.Contains(t, msg, "数据库连接失败")
		assert.Contains(t, fields, `"host":"db1.internal"`)
		assert.Contains(t, fields, `"request_id":"`+TestRequestID+`"`)
	})

	t.Log("✅ 所有集成测试通过！真实数据库写入验证成功。")
}
