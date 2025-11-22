package core

import (
	"crypto/sha1"
	"errors"
	"fmt"
	"mebsuta/config"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	encoderCache = make(map[string]zapcore.Encoder)
)

const (
	maxEncoderCacheSize = 10
)

type SycerFactory func(config.OutputConfig) (WriteSyncer, error)

// NewLogger 创建新日志器
func NewLogger(cfg config.LoggerConfig, factory SycerFactory) (*zap.Logger, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("配置验证失败: %w", err)
	}

	cores, err := buildCores(cfg, factory)
	if err != nil {
		return nil, err
	}

	coreTee := zapcore.NewTee(cores...)

	// 应用采样
	if cfg.Sampling.Enabled {
		var err error
		coreTee, err = newSampler(coreTee, cfg.Sampling)
		if err != nil {
			return nil, fmt.Errorf("采样器初始化失败: %w", err)
		}
	}

	opts := []zap.Option{
		zap.AddCaller(),
		zap.AddStacktrace(cfg.Encoder.StackLevel.ZapLevel()),
	}

	if cfg.Encoder.EnableCaller {
		opts = append(opts, zap.WithCaller(true))
	}

	logger := zap.New(coreTee, opts...)

	// 添加全局字段
	if cfg.ServiceName != "" {
		logger = logger.With(zap.String("service", cfg.ServiceName))
	}

	for k, v := range cfg.Encoder.CustomFields {
		logger = logger.With(zap.String(k, v))
	}

	return logger, nil
}

func buildCores(cfg config.LoggerConfig, factory SycerFactory) ([]zapcore.Core, error) {
	var cores []zapcore.Core

	for _, out := range cfg.Outputs {
		if !out.Enabled {
			continue
		}

		// 创建同步器
		syncer, err := factory(out)
		if err != nil {
			return nil, fmt.Errorf("创建同步器失败: %w", err)
		}

		// 创建编码器
		encoder := getEncoder(cfg.Encoder, out.Encoding)
		enabler := levelEnablerForOutput(cfg, out)

		if ev, ok := syncer.(EventWriteSyncer); ok {
			cores = append(cores, NewStructuredCore(encoder, enabler, syncer, ev))
		} else {
			core := zapcore.NewCore(encoder, syncer, enabler)
			cores = append(cores, core)
		}
	}

	if len(cores) == 0 {
		return nil, errors.New("没有启用的日志输出")
	}

	return cores, nil
}

func getEncoder(encCfg config.EncoderConfig, encoding config.EncodingType) zapcore.Encoder {
	h := sha1.New()

	// 应用默认配置
	defaultCfg := *encCfg.ApplyDefaults()

	// 使用 strings.Builder 构建配置字符串，只包含影响 encoder 的关键字段
	var b strings.Builder
	// 预分配容量，减少重新分配
	b.Grow(512)

	// 按照 createEncoder 中使用的字段顺序添加
	b.WriteString(string(encoding))
	b.WriteByte('|')
	b.WriteString(defaultCfg.TimeFormat)
	b.WriteByte('|')
	b.WriteString(defaultCfg.TimeZone)
	b.WriteByte('|')
	b.WriteString(defaultCfg.MessageKey)
	b.WriteByte('|')
	b.WriteString(defaultCfg.LevelKey)
	b.WriteByte('|')
	b.WriteString(defaultCfg.TimeKey)
	b.WriteByte('|')
	b.WriteString(defaultCfg.CallerKey)
	b.WriteByte('|')
	b.WriteString(defaultCfg.StacktraceKey)
	b.WriteByte('|')
	b.WriteString(strconv.FormatBool(defaultCfg.ShortCaller))
	b.WriteByte('|')
	b.WriteString(strconv.FormatBool(defaultCfg.EnableCaller))

	// 写入哈希
	h.Write([]byte(b.String()))
	cacheKey := fmt.Sprintf("%x", h.Sum(nil))

	// 清理缓存（如果超过最大大小）
	if len(encoderCache) >= maxEncoderCacheSize {
		for k := range encoderCache {
			delete(encoderCache, k)
			break
		}
	}

	// 检查缓存
	if encoder, ok := encoderCache[cacheKey]; ok {
		return encoder
	}

	// 创建新的编码器
	encoder := createEncoder(defaultCfg, encoding)
	encoderCache[cacheKey] = encoder
	return encoder
}

func createEncoder(cfg config.EncoderConfig, encoding config.EncodingType) zapcore.Encoder {
	encoderConfig := zapcore.EncoderConfig{
		MessageKey:     cfg.MessageKey,
		LevelKey:       cfg.LevelKey,
		TimeKey:        cfg.TimeKey,
		NameKey:        "logger",
		CallerKey:      cfg.CallerKey,
		StacktraceKey:  cfg.StacktraceKey,
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     createTimeEncoder(cfg),
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   createCallerEncoder(cfg),
	}

	switch encoding {
	case config.Console:
		return zapcore.NewConsoleEncoder(encoderConfig)
	default: // JSON
		jsonEnc := zapcore.NewJSONEncoder(encoderConfig)
		if enc, ok := jsonEnc.(interface{ SetEscapeHTML(bool) }); ok {
			enc.SetEscapeHTML(false)
		}
		return jsonEnc
	}
}

func createTimeEncoder(cfg config.EncoderConfig) zapcore.TimeEncoder {
	loc, err := time.LoadLocation(cfg.TimeZone)
	if err != nil {
		loc = time.UTC
	}

	return func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
		enc.AppendString(t.In(loc).Format(cfg.TimeFormat))
	}
}

func createCallerEncoder(cfg config.EncoderConfig) zapcore.CallerEncoder {
	if cfg.ShortCaller {
		return zapcore.ShortCallerEncoder
	}
	return zapcore.FullCallerEncoder
}

func levelEnablerForOutput(cfg config.LoggerConfig, out config.OutputConfig) zapcore.LevelEnabler {
	return zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		return lvl >= out.Level.ZapLevel() ||
			(cfg.DebugMode && lvl == zapcore.DebugLevel)
	})
}
