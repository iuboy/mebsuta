package database

import (
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// validConfig 返回能通过 Validate 的 Config，供测试中修改。
// DSN 内嵌一个假密码，让脱敏断言有东西可
// 检查。
func validConfig() Config {
	return Config{
		Driver: "postgres",
		DSN:    "postgres://loguser:s3cr3t-pw@127.0.0.1:5432/logs?sslmode=disable",
		Table:  "logs",
	}
}

// cfgWith 返回应用了变更的 validConfig 副本。
func cfgWith(mutate func(*Config)) Config {
	c := validConfig()
	mutate(&c)
	return c
}

// TestConfig_RetryDelayDefaultAndCap 验证 RetryDelay 规范化：
// 未设置 → 500ms，超过 MaxRetryDelay（30s，与 syslog
// handler 一致）的值被钳制——否则误配成数分钟的延迟会
// 成倍放大最坏 flush 时间，并让 Close 的排空每次重试都拖延。
func TestConfig_RetryDelayDefaultAndCap(t *testing.T) {
	cfg, err := validConfig().Validate()
	require.NoError(t, err)
	require.Equal(t, 500*time.Millisecond, cfg.RetryDelay, "unset RetryDelay should default to 500ms")

	cfg, err = cfgWith(func(c *Config) { c.RetryDelay = 10 * time.Minute }).Validate()
	require.NoError(t, err)
	require.Equal(t, MaxRetryDelay, cfg.RetryDelay, "oversized RetryDelay should be clamped to MaxRetryDelay")
	require.Equal(t, 30*time.Second, MaxRetryDelay, "MaxRetryDelay must stay aligned with the syslog handler's cap")

	cfg, err = cfgWith(func(c *Config) { c.RetryDelay = 2 * time.Second }).Validate()
	require.NoError(t, err)
	require.Equal(t, 2*time.Second, cfg.RetryDelay, "in-range RetryDelay must be preserved")
}

// TestConfig_MaxRecordBytes 验证记录大小上界的规范化：
// 未设置/为负 → DefaultMaxRecordBytes，超过 MaxRecordBytesCap 的值被
// 钳制，范围内取值保留。
func TestConfig_MaxRecordBytes(t *testing.T) {
	cfg, err := validConfig().Validate()
	require.NoError(t, err)
	require.Equal(t, DefaultMaxRecordBytes, cfg.MaxRecordBytes, "unset MaxRecordBytes should default to DefaultMaxRecordBytes")

	cfg, err = cfgWith(func(c *Config) { c.MaxRecordBytes = -1 }).Validate()
	require.NoError(t, err)
	require.Equal(t, DefaultMaxRecordBytes, cfg.MaxRecordBytes, "negative MaxRecordBytes should default")

	cfg, err = cfgWith(func(c *Config) { c.MaxRecordBytes = 64 * 1024 * 1024 }).Validate()
	require.NoError(t, err)
	require.Equal(t, MaxRecordBytesCap, cfg.MaxRecordBytes, "oversized MaxRecordBytes should be clamped to MaxRecordBytesCap")

	cfg, err = cfgWith(func(c *Config) { c.MaxRecordBytes = 4096 }).Validate()
	require.NoError(t, err)
	require.Equal(t, 4096, cfg.MaxRecordBytes, "in-range MaxRecordBytes must be preserved")
}

// TestConfig_StringRedactsCredentials 钉住脱敏配置要求：
// 用 %v / %+v / %#v 渲染 Config 绝不能携带 DSN 的
// 凭据，无论 key=value 还是 user:password@ 形式的 DSN。
func TestConfig_StringRedactsCredentials(t *testing.T) {
	kv := cfgWith(func(c *Config) {
		c.DSN = "host=db.internal user=loguser password=hunter2 dbname=logs sslmode=verify-full"
		c.BatchSize = 42
		c.Level = slog.LevelWarn
	})
	url := cfgWith(func(c *Config) { c.Level = slog.LevelDebug })

	for name, cfg := range map[string]Config{"key-value DSN": kv, "url DSN": url} {
		rendered := []string{
			fmt.Sprintf("%v", cfg),
			fmt.Sprintf("%+v", cfg),
			fmt.Sprintf("%#v", cfg),
			cfg.String(),
			cfg.GoString(),
		}
		for _, out := range rendered {
			require.NotContains(t, out, "hunter2", "%s: rendered config must not contain the password: %s", name, out)
			require.NotContains(t, out, "s3cr3t-pw", "%s: rendered config must not contain the password: %s", name, out)
		}
		for _, out := range []string{kv.String(), kv.GoString()} {
			require.Contains(t, out, "password=***", "%s: key=value credentials must be redacted: %s", name, out)
		}
		for _, out := range []string{url.String(), url.GoString()} {
			require.Contains(t, out, ":***@", "%s: URL-style credentials must be redacted: %s", name, out)
		}
	}

	// 健全性检查：脱敏渲染仍保留有用字段。
	out := kv.String()
	require.Contains(t, out, "Table:logs")
	require.Contains(t, out, "BatchSize:42")
	require.Contains(t, out, "Level:WARN")
}

// TestConfig_Sanitize 验证 Sanitize：DSN 被脱敏，其余
// 每个字段保留，且原始 Config 不被改动（值
// 接收者——调用方必须能一边继续记录脱敏副本，一边
// 把原始 Config 传给 NewHandler）。
func TestConfig_Sanitize(t *testing.T) {
	cfg := cfgWith(func(c *Config) { c.BatchSize = 42; c.Table = "audit" })
	s := cfg.Sanitize()

	require.NotContains(t, s.DSN, "s3cr3t-pw", "sanitized DSN must not contain the password")
	require.Contains(t, s.DSN, ":***@", "sanitized DSN must carry the redaction marker")
	require.Equal(t, cfg.Driver, s.Driver)
	require.Equal(t, 42, s.BatchSize)
	require.Equal(t, "audit", s.Table)
	require.Equal(t, cfg.RetryDelay, s.RetryDelay)
	require.Contains(t, cfg.DSN, "s3cr3t-pw", "the original Config must be untouched")

	require.Empty(t, Config{}.Sanitize().DSN, "empty DSN stays empty")
}

// TestConfig_StringSignerField 验证 IntegritySigner 字段渲染为
// 其算法标识（绝非 signer 值本身），未设置时为 <nil>。
func TestConfig_StringSignerField(t *testing.T) {
	cfg := cfgWith(func(*Config) {})
	require.Contains(t, cfg.String(), "IntegritySigner:<nil>")

	cfg = cfgWith(func(c *Config) { c.IntegritySigner = mockSigner{} })
	require.Contains(t, cfg.String(), "IntegritySigner:MOCK")
	require.Contains(t, cfg.GoString(), "IntegritySigner:MOCK")
}
