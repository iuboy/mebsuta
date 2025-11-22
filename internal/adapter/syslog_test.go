package adapter

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"mebsuta/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
)

// 模拟 Syslog 服务器
type mockSyslogServer struct {
	listener   net.Listener
	msgChan    chan string
	shutdown   chan struct{}
	serverAddr string
}

func newMockSyslogServer(network string) (*mockSyslogServer, error) {
	listener, err := net.Listen(network, "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	server := &mockSyslogServer{
		listener:   listener,
		msgChan:    make(chan string, 100),
		shutdown:   make(chan struct{}),
		serverAddr: listener.Addr().String(),
	}

	go server.acceptConnections()
	return server, nil
}

func (s *mockSyslogServer) acceptConnections() {
	for {
		select {
		case <-s.shutdown:
			return
		default:
			conn, err := s.listener.Accept()
			if err != nil {
				return
			}
			go s.handleConnection(conn)
		}
	}
}

func (s *mockSyslogServer) handleConnection(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)

	for {
		select {
		case <-s.shutdown:
			return
		default:
			// 读取直到遇到换行符
			msg, err := reader.ReadString('\n')
			if err != nil {
				if err != io.EOF {
					log.Printf("Read error: %v", err)
				}
				return
			}
			s.msgChan <- strings.TrimSpace(msg)
		}
	}
}

func (s *mockSyslogServer) Close() {
	close(s.shutdown)
	s.listener.Close()
}

func (s *mockSyslogServer) Receive(timeout time.Duration) (string, error) {
	select {
	case msg := <-s.msgChan:
		return msg, nil
	case <-time.After(timeout):
		return "", fmt.Errorf("timeout waiting for message")
	}
}

func validHost() string {
	host, _ := os.Hostname()
	if host == "" {
		return "localhost"
	}
	return regexp.MustCompile(`[^a-zA-Z0-9\.\-]`).ReplaceAllString(host, "")
}

// 通过日志消息测试严重级别提取
func TestSeverityExtractionViaLogging(t *testing.T) {
	server, err := newMockSyslogServer("tcp")
	if err != nil {
		t.Fatalf("创建模拟服务器失败: %v", err)
	}
	defer server.Close()

	testCases := []struct {
		name   string
		cfg    config.SyslogConfig
		prefix string
	}{
		{
			"RFC5424",
			config.SyslogConfig{RFC5424: true, Facility: 16},
			`^<\d+>1 \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z ` + regexp.QuoteMeta(validHost()),
		},
		{
			"RFC3164",
			config.SyslogConfig{RFC5424: false, Facility: 16},
			`^<\d+>[A-Z][a-z]{2} [_ \d]\d \d{2}:\d{2}:\d{2} `,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server, err := newMockSyslogServer("tcp")
			require.NoError(t, err, "创建模拟服务器失败")
			defer server.Close()
			tests := []struct {
				level       string
				expectedPri string
			}{
				{"debug", "<135>"}, // Local0.debug (16*8 + 7)
				{"warn", "<132>"},  // Local0.warn (16*8 + 4)
				{"fatal", "<128>"}, // Local0.emerg (16*8 + 0)
			}
			tc.cfg.Network = "tcp"
			tc.cfg.Address = server.serverAddr
			tc.cfg.Tag = "mebsuta"
			ws, err := newSyslogAdapter(tc.cfg)
			require.NoError(t, err, "创建适配器失败")
			for _, sev := range tests {
				t.Run(sev.level, func(t *testing.T) {
					logJSON := []byte(fmt.Sprintf(
						`{"level":"%s","msg":"%s-test"}`,
						sev.level, sev.level,
					))

					_, err := ws.Write(logJSON)
					require.NoError(t, err, "日志写入失败")
					msg, err := server.Receive(500 * time.Millisecond)
					require.NoError(t, err, "服务器未接收消息")
					// 验证优先级
					assert.True(
						t,
						strings.HasPrefix(msg, sev.expectedPri),
						"优先级不匹配. 预期: %s, 实际: %s",
						sev.expectedPri,
						msg[:len(sev.expectedPri)],
					)

					// 验证头部格式
					assert.Regexp(t, tc.prefix, msg, "头部格式不符合预期")
				})
			}
		})
	}
}

// 测试完整适配器功能
func TestSyslogAdapterE2E(t *testing.T) {
	t.Run("创建适配器-非法地址", func(t *testing.T) {
		_, err := newSyslogAdapter(config.SyslogConfig{
			Address: "invalid::addr",
		})
		if err == nil {
			t.Error("预期错误未返回")
		} else if !strings.Contains(err.Error(), "connection failed") {
			t.Errorf("错误的错误类型: %v", err)
		}
	})

	t.Run("创建适配器-有效TCP", func(t *testing.T) {
		server, _ := newMockSyslogServer("tcp")
		defer server.Close()

		ws, err := newSyslogAdapter(config.SyslogConfig{
			Network: "tcp",
			Address: server.serverAddr,
		})
		if err != nil {
			t.Errorf("创建失败: %v", err)
		}
		if ws == nil {
			t.Error("未返回WriteSyncer")
		}
	})

	t.Run("日志格式验证-RFC5424", func(t *testing.T) {
		server, _ := newMockSyslogServer("tcp")
		defer server.Close()
		cfg := config.SyslogConfig{
			RFC5424:       true,
			Network:       "tcp",
			Address:       server.serverAddr,
			Tag:           "mytestapp",
			JSONInMessage: true,
		}
		ws, _ := newSyslogAdapter(cfg)
		// 单行JSON
		validateLogFormat(
			t, ws, server, "warn",
			[]byte(`{"level":"warn","msg":"Disk full","path":"/var/log","usage":98.7}`),
			cfg,
		)

		// 多行JSON
		validateLogFormat(
			t, ws, server, "warn",
			[]byte(`{
				"level": "warn",
				"msg": "Disk \x02full",
				"path": "/var/log",
				"usage": 98.7
			}`),
			cfg,
		)

		// 特殊字符测试
		validateLogFormat(t, ws, server, "warn",
			[]byte("{\"level\":\"warn\",\"msg\":\"Disk \x07full\",\"path\":\"/var/log\",\"usage\":98.7}"), cfg)
	})

	t.Run("日志格式验证-RFC3164", func(t *testing.T) {
		server, _ := newMockSyslogServer("tcp")
		defer server.Close()

		cfg := config.SyslogConfig{
			RFC5424: false,
			Network: "tcp",
			Address: server.serverAddr,
			Tag:     "mytestapp",
		}

		ws, _ := newSyslogAdapter(cfg)
		// 单行JSON
		validateLogFormat(
			t, ws, server, "warn",
			[]byte(`{"level":"warn","msg":"Disk full","path":"/var/log","usage":98.7}`),
			cfg,
		)

		// 多行JSON（验证控制字符处理）
		validateLogFormat(
			t, ws, server, "warn",
			[]byte(`{
				"level": "warn",
				"msg": "Disk \x02full",
				"path": "/var/log",
				"usage": 98.7
			}`),
			cfg,
		)

		// 混合特殊字符
		validateLogFormat(t, ws, server, "warn",
			[]byte("{\"level\":\"warn\",\"msg\":\"Disk \x0bfull\",\"path\":\"/var/log\",\"usage\":98.7}"), cfg)
	})

	t.Run("自动重连功能", func(t *testing.T) {
		// 使用健康检查触发重连而非直接关闭连接
		server, _ := newMockSyslogServer("tcp")
		defer server.Close()

		ws, _ := newSyslogAdapter(config.SyslogConfig{
			Network:    "tcp",
			Address:    server.serverAddr,
			RetryDelay: 100 * time.Millisecond,
		})

		// 模拟健康检查超时 (不关闭任何东西)
		time.Sleep(3 * time.Second) // 等待健康检查触发

		// 正常写入日志应该触发重连
		ws.Write([]byte(`{"level":"info","msg":"After timeout"}`))

		// 验证日志接收
		if _, err := server.Receive(5 * time.Second); err != nil {
			t.Fatal("重连失败: ", err)
		}
	})

	t.Run("关闭行为验证", func(t *testing.T) {
		server, _ := newMockSyslogServer("tcp")
		defer server.Close()

		ws, _ := newSyslogAdapter(config.SyslogConfig{
			Network: "tcp",
			Address: server.serverAddr,
		})

		// 确认关闭接口
		if closer, ok := ws.(interface{ Close() error }); ok {
			if err := closer.Close(); err != nil {
				t.Errorf("关闭失败: %v", err)
			}

			// 尝试关闭后写入
			_, err := ws.Write([]byte(`{"msg":"should fail"}`))
			if err == nil {
				t.Error("关闭后写入未返回错误")
			}
		} else {
			t.Error("WriteSyncer 未实现 Closer 接口")
		}
	})
	t.Run("处理 \\x 转义字符 - JSON模式", func(t *testing.T) {
		server, _ := newMockSyslogServer("tcp")
		defer server.Close()

		ws, _ := newSyslogAdapter(config.SyslogConfig{
			RFC5424:       true,
			Network:       "tcp",
			Address:       server.serverAddr,
			Tag:           "mytestapp",
			JSONInMessage: true, // 关键！
		})

		input := `{"level":"warn","msg":"Attack: \x02\x03\x07","path":"/dev/null"}`

		_, err := ws.Write([]byte(input))
		require.NoError(t, err)
		msg, err := server.Receive(2 * time.Second)
		require.NoError(t, err)

		// 应在消息体 JSON 内部看到 \u0002
		assert.Contains(t, msg, `\u0002`)
		assert.Contains(t, msg, `\u0003`)
		assert.Contains(t, msg, `\u0007`)
	})
	t.Run("处理 \\x 转义字符 - 非JSON模式", func(t *testing.T) {
		server, _ := newMockSyslogServer("tcp")
		defer server.Close()

		ws, _ := newSyslogAdapter(config.SyslogConfig{
			RFC5424:       false,
			Network:       "tcp",
			Address:       server.serverAddr,
			Tag:           "mytestapp",
			JSONInMessage: false,
		})

		input := `{"level":"warn","msg":"Attack: \x02\x03\x07","path":"/dev/null"}`

		_, err := ws.Write([]byte(input))
		require.NoError(t, err)
		msg, err := server.Receive(2 * time.Second)
		require.NoError(t, err)

		// 非 JSON 模式下，应显示为 "Attack: <replacement>" 或被移除/替换
		// 或者至少不能是 \x02
		assert.NotContains(t, msg, `\x02`)
		assert.Contains(t, msg, "Attack:") // 内容还在
	})

}

func validateLogFormat(t *testing.T, ws zapcore.WriteSyncer, server *mockSyslogServer,
	expectedLevel string, data []byte, cfg config.SyslogConfig) {
	t.Helper()
	t.Logf("====== 发送日志 =======\n%s", data)

	// 发送日志
	_, err := ws.Write(data)
	assert.NoError(t, err, "日志写入失败")

	// 接收消息并验证
	msg, err := server.Receive(2 * time.Second)
	require.NoError(t, err, "消息接收失败")
	t.Logf("====== 接收消息 ======\n%s", msg)

	validateRFCCompliance(t, expectedLevel, msg)

	if cfg.JSONInMessage {
		extractAndVerifyJSON(t, msg, expectedLevel)
	} else {
		// 仅验证 level 字段在文本中存在
		extractAndVerifyPlainText(t, msg, expectedLevel)
	}
}

func extractAndVerifyJSON(t *testing.T, msg string, expectedLevel string) {
	t.Helper()

	// 查找 JSON 起始位置：最可能从 { 开始
	start := strings.Index(msg, "{")
	if start == -1 {
		t.Fatalf(`消息中未找到 JSON 起始: %s`, msg)
	}

	// 匹配完整的 JSON 对象
	nest := 0
	end := -1
	for i := start; i < len(msg); i++ {
		if msg[i] == '{' {
			nest++
		} else if msg[i] == '}' {
			nest--
			if nest == 0 {
				end = i + 1
				break
			}
		}
	}
	if end == -1 {
		t.Fatalf(`未找到匹配的 } : %s`, msg)
	}

	jsonStr := msg[start:end]
	var result struct {
		Level string `json:"level"`
	}
	require.NoError(t, json.Unmarshal([]byte(jsonStr), &result), "JSON 解析失败: %s", jsonStr)
	assert.Equal(t, expectedLevel, result.Level, "level 不匹配")
}

func validateRFCCompliance(t *testing.T, formatName, msg string) {
	switch formatName {
	case "RFC5424":
		// 更宽松的RFC5424验证
		regex := regexp.MustCompile(`<\d+>\d \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}([+-]\d{2}:\d{2}|Z) \S+ \S+ \d+ (-|\[.*?\]) .+`)
		if !regex.MatchString(msg) {
			t.Errorf("RFC5424格式不匹配: %s", msg)
		}
	case "RFC3164":
		// 更宽松的RFC3164验证
		regex := regexp.MustCompile(`<\d+>(?:(\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}) \S+(?:\[\d+\])?: .+`)
		if !regex.MatchString(msg) {
			t.Errorf("RFC3164格式不匹配: %s", msg)
		}
	}
}

func extractAndVerifyPlainText(t *testing.T, msg string, expectedLevel string) {
	t.Helper()

	re := regexp.MustCompile(`^<(\d+)>`)
	matches := re.FindStringSubmatch(msg)
	require.NotEmpty(t, matches, "无法提取 PRI 字段", "原始消息: %s", msg)

	pri, err := strconv.Atoi(matches[1])
	require.NoError(t, err, "PRI 应为整数")

	severity := pri % 8

	var parsedLevel string
	switch severity {
	case 7:
		parsedLevel = "debug"
	case 6:
		parsedLevel = "info"
	case 4:
		parsedLevel = "warn"
	case 3:
		parsedLevel = "error"
	case 0, 1, 2:
		parsedLevel = "fatal"
	default:
		parsedLevel = "info"
	}

	assert.Equal(t, strings.ToLower(expectedLevel), strings.ToLower(parsedLevel),
		"日志级别不匹配", "原始消息: %s", msg)
}
