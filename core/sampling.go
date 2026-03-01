package core

import (
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/iuboy/mebsuta/config"
	"go.uber.org/zap/zapcore"
)

// dynamicSampler 动态日志采样器
// 根据时间窗口和采样策略减少日志输出，避免日志爆炸
type dynamicSampler struct {
	zapcore.Core
	settings   atomic.Value
	ticker     *time.Ticker
	localCount int32
	stopChan   chan struct{}
	stopped    *atomic.Bool
}

// samplingSettings 采样配置
type samplingSettings struct {
	initial    int           // 初始采样数量
	thereafter int           // 后续采样间隔
	window     time.Duration // 时间窗口
}

// newSampler 创建动态采样器
// core: 底层日志核心
// cfg: 采样配置
func newSampler(core zapcore.Core, cfg config.SamplingConfig) (zapcore.Core, error) {
	if !cfg.Enabled {
		return core, nil
	}

	stopped := atomic.Bool{}
	s := &dynamicSampler{
		Core:     core,
		ticker:   time.NewTicker(cfg.Window),
		stopChan: make(chan struct{}),
		stopped:  &stopped,
	}

	s.updateSettings(cfg)

	// 定期重置计数器（使用goroutine）
	go s.resetLoop()

	return s, nil
}

// updateSettings 更新采样配置
func (s *dynamicSampler) updateSettings(cfg config.SamplingConfig) {
	settings := samplingSettings{
		initial:    cfg.Initial,
		thereafter: cfg.Thereafter,
		window:     cfg.Window,
	}
	s.settings.Store(settings)
}

// resetLoop 定期重置采样计数器
func (s *dynamicSampler) resetLoop() {
	defer func() {
		if r := recover(); r != nil {
			// 使用 fmt 输出到 stderr，因为日志系统可能不可用
			fmt.Fprintf(os.Stderr, "采样器resetLoop发生panic: %v\n", r)
			// panic后goroutine将退出，采样计数器不再重置
			// 调用者需要重新创建采样器以恢复正常功能
		}
	}()

	for {
		select {
		case <-s.ticker.C:
			atomic.StoreInt32(&s.localCount, 0)
		case <-s.stopChan:
			// 收到停止信号，退出goroutine
			return
		}
	}
}

// Sync 同步日志缓冲区
func (s *dynamicSampler) Sync() error {
	return s.Core.Sync()
}

// Close 关闭采样器，释放资源
func (s *dynamicSampler) Close() error {
	// 防止重复关闭
	if s.stopped.Swap(true) {
		return nil
	}

	// 停止ticker
	s.ticker.Stop()

	// 发送停止信号，等待goroutine退出
	close(s.stopChan)

	// 同步底层日志核心
	if err := s.Core.Sync(); err != nil {
		return fmt.Errorf("采样器关闭时同步失败: %w", err)
	}

	return nil
}

// With 添加字段到采样器
func (s *dynamicSampler) With(fields []zapcore.Field) zapcore.Core {
	// 返回包装器以避免共享ticker和stopChan导致的资源泄漏
	return &samplerWrapper{
		sampler: s,
		fields:  fields,
	}
}

// samplerWrapper 包装器，避免克隆ticker和stopChan
type samplerWrapper struct {
	sampler *dynamicSampler
	fields  []zapcore.Field
}

func (w *samplerWrapper) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	return w.sampler.Check(ent, ce)
}

func (w *samplerWrapper) With(fields []zapcore.Field) zapcore.Core {
	return &samplerWrapper{
		sampler: w.sampler,
		fields:  append(w.fields, fields...),
	}
}

func (w *samplerWrapper) Enabled(level zapcore.Level) bool {
	return w.sampler.Enabled(level)
}

func (w *samplerWrapper) Write(ent zapcore.Entry, fields []zapcore.Field) error {
	// 合并包装器的字段和传入的字段
	combinedFields := append(w.fields, fields...)
	return w.sampler.Write(ent, combinedFields)
}

func (w *samplerWrapper) Sync() error {
	return w.sampler.Sync()
}

// Check 检查是否应该记录日志
func (s *dynamicSampler) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	// 错误级别的日志始终记录
	if ent.Level >= zapcore.ErrorLevel {
		return s.Core.Check(ent, ce)
	}

	// 获取采样配置
	settings := s.settings.Load().(samplingSettings)
	count := atomic.AddInt32(&s.localCount, 1)

	// 检查是否应该采样
	if count <= int32(settings.initial) ||
		(count-int32(settings.initial))%int32(settings.thereafter) == 0 {
		return s.Core.Check(ent, ce)
	}

	// 跳过此日志
	return ce
}
