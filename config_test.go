package mebsuta

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// =============================================================================
// ConfigError
// =============================================================================

func TestConfigError_Fields(t *testing.T) {
	err := &ConfigError{Field: "Path", Msg: "file path is required"}
	require.Equal(t, "Path", err.Field)
	require.Equal(t, "file path is required", err.Msg)
	require.Contains(t, err.Error(), "Path")
	require.Contains(t, err.Error(), "file path is required")
}

func TestConfigError_ErrorFormat(t *testing.T) {
	err := &ConfigError{Field: "Address", Msg: "syslog address is required"}
	require.Equal(t, "Address: syslog address is required", err.Error())
}

// =============================================================================
// FileConfig Validate
// =============================================================================

func TestFileConfig_DefaultsApplied(t *testing.T) {
	cfg := FileConfig{}
	validated, err := cfg.Validate()
	require.NoError(t, err)

	require.Equal(t, slog.LevelInfo, validated.Level)
	require.Equal(t, "json", validated.Format)
}

func TestFileConfig_CustomValuesPreserved(t *testing.T) {
	cfg := FileConfig{
		Level:  slog.LevelDebug,
		Format: "console",
	}
	validated, err := cfg.Validate()
	require.NoError(t, err)

	require.Equal(t, slog.LevelDebug, validated.Level)
	require.Equal(t, "console", validated.Format)
}

// =============================================================================
// StdoutConfig Validate
// =============================================================================

func TestStdoutConfig_ZeroValue(t *testing.T) {
	cfg := StdoutConfig{}
	validated, err := cfg.Validate()
	require.NoError(t, err)
	require.Equal(t, slog.LevelInfo, validated.Level)
	require.Equal(t, "json", validated.Format)
}

func TestStdoutConfig_DefaultsApplied(t *testing.T) {
	cfg := StdoutConfig{}
	validated, err := cfg.Validate()
	require.NoError(t, err)
	require.Equal(t, slog.LevelInfo, validated.Level)
	require.Equal(t, "json", validated.Format)
}

func TestStdoutConfig_CustomValuesPreserved(t *testing.T) {
	cfg := StdoutConfig{
		Level:  slog.LevelWarn,
		Format: "console",
	}
	validated, err := cfg.Validate()
	require.NoError(t, err)
	require.Equal(t, slog.LevelWarn, validated.Level)
	require.Equal(t, "console", validated.Format)
}

func TestStdoutConfig_DoesNotModifyOriginal(t *testing.T) {
	cfg := StdoutConfig{}
	original := cfg

	_, err := cfg.Validate()
	require.NoError(t, err)

	require.Nil(t, cfg.Level)
	require.Equal(t, "", cfg.Format)
	require.Equal(t, original, cfg)
}

func TestStdoutConfig_Idempotent(t *testing.T) {
	cfg := StdoutConfig{}

	first, err := cfg.Validate()
	require.NoError(t, err)

	second, err := first.Validate()
	require.NoError(t, err)

	require.Equal(t, first, second)
}

// =============================================================================
// AsyncConfig Validate
// =============================================================================

func TestAsyncConfig_ZeroValue(t *testing.T) {
	cfg := AsyncConfig{}
	validated, err := cfg.Validate()
	require.NoError(t, err)
	require.Equal(t, 256, validated.BufferSize)
}

func TestAsyncConfig_DefaultApplied(t *testing.T) {
	cfg := AsyncConfig{BufferSize: 0}
	validated, err := cfg.Validate()
	require.NoError(t, err)
	require.Equal(t, 256, validated.BufferSize)
}

func TestAsyncConfig_NegativeBufferDefaulted(t *testing.T) {
	cfg := AsyncConfig{BufferSize: -1}
	validated, err := cfg.Validate()
	require.NoError(t, err)
	require.Equal(t, 256, validated.BufferSize)
}

func TestAsyncConfig_CustomValuePreserved(t *testing.T) {
	cfg := AsyncConfig{BufferSize: 1024}
	validated, err := cfg.Validate()
	require.NoError(t, err)
	require.Equal(t, 1024, validated.BufferSize)
}

func TestAsyncConfig_DoesNotModifyOriginal(t *testing.T) {
	cfg := AsyncConfig{BufferSize: 0}
	original := cfg

	_, err := cfg.Validate()
	require.NoError(t, err)

	require.Equal(t, 0, cfg.BufferSize)
	require.Equal(t, original, cfg)
}

func TestAsyncConfig_Idempotent(t *testing.T) {
	cfg := AsyncConfig{}

	first, err := cfg.Validate()
	require.NoError(t, err)

	second, err := first.Validate()
	require.NoError(t, err)

	require.Equal(t, first, second)
}

// =============================================================================
// SamplingConfig Validate
// =============================================================================

func TestSamplingConfig_ZeroValue_Disabled(t *testing.T) {
	cfg := SamplingConfig{}
	validated, err := cfg.Validate()
	require.NoError(t, err)
	require.False(t, validated.Enabled)
	// When disabled, zero values stay zero — no defaults applied
	require.Equal(t, 0, validated.Initial)
	require.Equal(t, 0, validated.Thereafter)
	require.Equal(t, time.Duration(0), validated.Window)
}

func TestSamplingConfig_Disabled_NoDefaultsApplied(t *testing.T) {
	cfg := SamplingConfig{Enabled: false, Initial: 0, Thereafter: 0}
	validated, err := cfg.Validate()
	require.NoError(t, err)
	require.Equal(t, 0, validated.Initial)
	require.Equal(t, 0, validated.Thereafter)
	require.Equal(t, time.Duration(0), validated.Window)
}

func TestSamplingConfig_Enabled_DefaultsApplied(t *testing.T) {
	cfg := SamplingConfig{Enabled: true}
	validated, err := cfg.Validate()
	require.NoError(t, err)
	require.Equal(t, 100, validated.Initial)
	require.Equal(t, 10, validated.Thereafter)
	require.Equal(t, time.Second, validated.Window)
}

func TestSamplingConfig_Enabled_NegativeValuesDefaulted(t *testing.T) {
	cfg := SamplingConfig{
		Enabled:    true,
		Initial:    -5,
		Thereafter: -1,
		Window:     -time.Second,
	}
	validated, err := cfg.Validate()
	require.NoError(t, err)
	require.Equal(t, 100, validated.Initial)
	require.Equal(t, 10, validated.Thereafter)
	require.Equal(t, time.Second, validated.Window)
}

func TestSamplingConfig_Enabled_CustomValuesPreserved(t *testing.T) {
	cfg := SamplingConfig{
		Enabled:    true,
		Initial:    50,
		Thereafter: 5,
		Window:     2 * time.Second,
	}
	validated, err := cfg.Validate()
	require.NoError(t, err)
	require.Equal(t, 50, validated.Initial)
	require.Equal(t, 5, validated.Thereafter)
	require.Equal(t, 2*time.Second, validated.Window)
}

func TestSamplingConfig_DoesNotModifyOriginal(t *testing.T) {
	cfg := SamplingConfig{Enabled: true}
	original := cfg

	_, err := cfg.Validate()
	require.NoError(t, err)

	require.Equal(t, original.Enabled, cfg.Enabled)
	require.Equal(t, 0, cfg.Initial)
	require.Equal(t, 0, cfg.Thereafter)
	require.Equal(t, time.Duration(0), cfg.Window)
}

func TestSamplingConfig_Idempotent(t *testing.T) {
	cfg := SamplingConfig{Enabled: true}

	first, err := cfg.Validate()
	require.NoError(t, err)

	second, err := first.Validate()
	require.NoError(t, err)

	require.Equal(t, first, second)
}

func TestSamplingConfig_Idempotent_Disabled(t *testing.T) {
	cfg := SamplingConfig{Enabled: false}

	first, err := cfg.Validate()
	require.NoError(t, err)

	second, err := first.Validate()
	require.NoError(t, err)

	require.Equal(t, first, second)
}
