package telemetry

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestValidate(t *testing.T) {
	t.Run("noop mode skips checks", func(t *testing.T) {
		cfg := Config{} // 空 endpoint：无需校验
		_, err := cfg.Validate()
		require.NoError(t, err, "空 endpoint 必须通过校验")
	})

	t.Run("service name required when endpoint set", func(t *testing.T) {
		cfg := Config{Endpoint: "http://fwd:4318"}
		_, err := cfg.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "ServiceName")
	})

	t.Run("sampling rate out of range rejected", func(t *testing.T) {
		for _, rate := range []float64{-0.1, -1.5, 1.5} {
			cfg := Config{Endpoint: "http://fwd:4318", ServiceName: "s", SamplingRate: rate}
			_, err := cfg.Validate()
			require.Error(t, err, "SamplingRate %v 必须被拒绝", rate)
		}
	})

	t.Run("defaults filled", func(t *testing.T) {
		cfg := Config{Endpoint: "http://fwd:4318", ServiceName: "s"}
		out, err := cfg.Validate()
		require.NoError(t, err)
		require.Equal(t, float64(1), out.SamplingRate, "SamplingRate 应为 1（0 → 全采样），且不得回写调用方")
		require.Equal(t, All, out.Signals, "Signals 应为 All（0 → 全信号）")
		require.Zero(t, cfg.SamplingRate, "调用方副本被修改：SamplingRate = %v", cfg.SamplingRate)
	})
}

func TestCanonicalEndpoint(t *testing.T) {
	cases := []struct {
		raw      string
		wantHost string
		wantSec  bool // true → 明文 HTTP（insecure）
	}{
		{"fwd:4318", "fwd:4318", true},                           // 裸 host:port → 局域网 HTTP
		{"http://fwd:4318", "fwd:4318", true},                    // 显式 HTTP
		{"https://otel.example.com", "otel.example.com", false},  // 显式 TLS
		{"http://fwd:4318/v1/traces?x=1#frag", "fwd:4318", true}, // path/query/fragment 被丢弃
	}
	for _, tc := range cases {
		host, insecure, err := canonicalEndpoint(tc.raw)
		require.NoError(t, err, "canonicalEndpoint(%q)", tc.raw)
		require.Equal(t, tc.wantHost, host, "canonicalEndpoint(%q) 的 host", tc.raw)
		require.Equal(t, tc.wantSec, insecure, "canonicalEndpoint(%q) 的 insecure", tc.raw)
	}

	for _, bad := range []string{"ftp://fwd:4318", "http://", "://missing-scheme"} {
		_, _, err := canonicalEndpoint(bad)
		require.Error(t, err, "canonicalEndpoint(%q) 必须失败", bad)
	}
}

func TestSignalsString(t *testing.T) {
	cases := map[Signals]string{
		None:          "none",
		Traces:        "traces",
		Traces | Logs: "traces|logs",
		All:           "traces|metrics|logs",
		Signals(99):   "traces|metrics", // 99 = 0b1100011：无 Logs 位，未知位被忽略
	}
	for sig, want := range cases {
		require.Equal(t, want, sig.String(), "Signals(%d).String()", uint8(sig))
	}
}

// 编译期守护：Config 必须保持调用方可复制的纯值类型。
var _ = Config{ShutdownTimeout: time.Second}

func TestConfig_RenderRedactsSecrets(t *testing.T) {
	cfg := Config{
		ServiceName: "svc",
		Endpoint:    "http://fwd:4318",
		Headers: map[string]string{
			"authorization": "Bearer super-secret-token",
			"x-tenant":      "acme",
		},
		Database: &DatabaseConfig{
			Driver: "postgres",
			DSN:    "postgres://auditor:hunter2@db.internal:5432/logs",
		},
	}

	for _, got := range []string{cfg.String(), cfg.GoString()} {
		require.NotContains(t, got, "super-secret-token", "String/GoString 不得泄漏 Header 值")
		require.NotContains(t, got, "hunter2", "String/GoString 不得泄漏 DSN 密码")
		require.Contains(t, got, "authorization:***", "Header 键保留、值脱敏")
		require.Contains(t, got, `"***"`, "DSN 整体遮蔽")
	}
	require.Equal(t, cfg.String(), cfg.String(), "渲染必须确定（日志稳定）")
}

// TestValidateHeaders:头名必须为 RFC 7230 token;认证头随明文端点
// 发送被拒绝(F4)——此前非法头名到导出时才失败,认证凭据随明文线路
// 静默外发。
func TestValidateHeaders(t *testing.T) {
	for name, cfg := range map[string]Config{
		"bad header name":     {ServiceName: "s", Endpoint: "http://fwd:4318", Headers: map[string]string{"Bad Header": "v"}},
		"auth over plaintext": {ServiceName: "s", Endpoint: "http://fwd:4318", Headers: map[string]string{"Authorization": "Bearer t"}},
		"auth over bare host": {ServiceName: "s", Endpoint: "fwd:4318", Headers: map[string]string{"authorization": "Bearer t"}},
		"empty header value":  {ServiceName: "s", Endpoint: "http://fwd:4318", Headers: map[string]string{"X-Token": ""}},
	} {
		_, err := cfg.Validate()
		require.Error(t, err, "%s must be rejected", name)
	}
	// https + 认证头合法。
	ok := Config{ServiceName: "s", Endpoint: "https://fwd:4318", Headers: map[string]string{"Authorization": "Bearer t"}}
	_, err := ok.Validate()
	require.NoError(t, err, "auth over https is legitimate")
}
