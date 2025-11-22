package core

import (
	"mebsuta/config"
	"sync/atomic"
	"time"

	"go.uber.org/zap/zapcore"
)

type dynamicSampler struct {
	zapcore.Core
	settings   atomic.Value
	ticker     *time.Ticker
	localCount int32
}

type samplingSettings struct {
	initial    int
	thereafter int
	window     time.Duration
}

// newSampler 创建动态采样器
func newSampler(core zapcore.Core, cfg config.SamplingConfig) (zapcore.Core, error) {
	if !cfg.Enabled {
		return core, nil
	}

	s := &dynamicSampler{
		Core:   core,
		ticker: time.NewTicker(cfg.Window),
	}

	s.updateSettings(cfg)

	// 定期重置计数器
	go s.resetLoop()

	return s, nil
}

func (s *dynamicSampler) updateSettings(cfg config.SamplingConfig) {
	settings := samplingSettings{
		initial:    cfg.Initial,
		thereafter: cfg.Thereafter,
		window:     cfg.Window,
	}
	s.settings.Store(settings)
}

func (s *dynamicSampler) resetLoop() {
	for range s.ticker.C {
		atomic.StoreInt32(&s.localCount, 0)
	}
}

func (s *dynamicSampler) Close() {
	s.ticker.Stop()
	s.Core.Sync()
}

func (s *dynamicSampler) With(fields []zapcore.Field) zapcore.Core {
	return &dynamicSampler{
		Core:     s.Core.With(fields),
		settings: s.settings,
		ticker:   s.ticker,
	}
}

func (s *dynamicSampler) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if ent.Level >= zapcore.ErrorLevel {
		return s.Core.Check(ent, ce)
	}

	settings := s.settings.Load().(samplingSettings)
	count := atomic.AddInt32(&s.localCount, 1)

	if count <= int32(settings.initial) ||
		(count-int32(settings.initial))%int32(settings.thereafter) == 0 {
		return s.Core.Check(ent, ce)
	}
	return ce
}
