package adapter_test

import (
	"testing"

	"github.com/iuboy/mebsuta/config"
	"github.com/iuboy/mebsuta/internal/adapter"
	"github.com/stretchr/testify/assert"
)

// TestCreateSyncer 测试 CreateSyncer 函数
func TestCreateSyncer(t *testing.T) {
	t.Run("Stdout类型", func(t *testing.T) {
		cfg := config.OutputConfig{
			Type:     config.Stdout,
			Level:    config.InfoLevel,
			Encoding: config.JSON,
			Enabled:  true,
		}

		syncer, err := adapter.CreateSyncer(cfg)
		assert.NoError(t, err)
		assert.NotNil(t, syncer)
		if syncer != nil {
			syncer.Close()
		}
	})

	t.Run("File类型", func(t *testing.T) {
		cfg := config.OutputConfig{
			Type:     config.File,
			Level:    config.InfoLevel,
			Encoding: config.JSON,
			Enabled:  true,
			File: &config.FileConfig{
				Path:       "/tmp/test.log",
				MaxSizeMB:  10,
				MaxBackups: 3,
				MaxAgeDays: 7,
			},
		}

		syncer, err := adapter.CreateSyncer(cfg)
		assert.NoError(t, err)
		assert.NotNil(t, syncer)
		if syncer != nil {
			syncer.Sync()
			syncer.Close()
		}
	})

	t.Run("DB类型-缺少配置", func(t *testing.T) {
		cfg := config.OutputConfig{
			Type:     config.DB,
			Level:    config.InfoLevel,
			Encoding: config.JSON,
			Enabled:  true,
		}

		syncer, err := adapter.CreateSyncer(cfg)
		assert.Error(t, err)
		assert.Nil(t, syncer)
	})

	t.Run("不支持类型", func(t *testing.T) {
		cfg := config.OutputConfig{
			Type:    config.OutputType("unknown"),
			Level:   config.InfoLevel,
			Enabled: true,
		}

		syncer, err := adapter.CreateSyncer(cfg)
		assert.Error(t, err)
		assert.Nil(t, syncer)
	})
}
