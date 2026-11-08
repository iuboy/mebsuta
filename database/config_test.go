package database

import (
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// validConfig returns a Config that passes Validate, for mutation in tests.
// The DSN embeds a fake password so redaction assertions have something to
// look for.
func validConfig() Config {
	return Config{
		Driver: "postgres",
		DSN:    "postgres://loguser:s3cr3t-pw@127.0.0.1:5432/logs?sslmode=disable",
		Table:  "logs",
	}
}

// cfgWith returns a copy of validConfig with mutations applied.
func cfgWith(mutate func(*Config)) Config {
	c := validConfig()
	mutate(&c)
	return c
}

// TestConfig_RetryDelayDefaultAndCap verifies the RetryDelay normalization:
// unset → 500ms, values above MaxRetryDelay (30s, matching the syslog
// handler) are clamped — a misconfigured multi-minute delay would otherwise
// multiply into the worst-case flush time and stall Close's drain per retry.
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

// TestConfig_MaxRecordBytes verifies the record-size bound normalization:
// unset/negative → DefaultMaxRecordBytes, values above MaxRecordBytesCap are
// clamped, in-range values preserved.
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

// TestConfig_StringRedactsCredentials pins the sanitized-config requirement:
// rendering a Config with %v / %+v / %#v must never carry the DSN's
// credentials, in either key=value or user:password@ DSN shapes.
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

	// Sanity: the redacted renders still carry the useful fields.
	out := kv.String()
	require.Contains(t, out, "Table:logs")
	require.Contains(t, out, "BatchSize:42")
	require.Contains(t, out, "Level:WARN")
}

// TestConfig_Sanitize verifies Sanitize: the DSN is redacted, every other
// field is preserved, and the original Config is left untouched (value
// receiver — callers must be able to keep logging the sanitized copy while
// passing the original to NewHandler).
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

// TestConfig_StringSignerField verifies the IntegritySigner field renders as
// its algorithm identifier (never the signer value itself) and as <nil> when
// unset.
func TestConfig_StringSignerField(t *testing.T) {
	cfg := cfgWith(func(*Config) {})
	require.Contains(t, cfg.String(), "IntegritySigner:<nil>")

	cfg = cfgWith(func(c *Config) { c.IntegritySigner = mockSigner{} })
	require.Contains(t, cfg.String(), "IntegritySigner:MOCK")
	require.Contains(t, cfg.GoString(), "IntegritySigner:MOCK")
}
