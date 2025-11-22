package adapter

import (
	"errors"
	"fmt"
	"io"
	"mebsuta/config"
	"mebsuta/core"

	"go.uber.org/zap/zapcore"
)

// WriteSyncer 扩展接口
type WriteSyncer interface {
	zapcore.WriteSyncer
	io.Closer
}

// CreateSyncer 根据输出配置创建同步器
func CreateSyncer(out config.OutputConfig) (core.WriteSyncer, error) {
	if !out.Enabled {
		return nil, fmt.Errorf("输出类型已被禁用: %s", out.Type)
	}

	switch out.Type {
	case config.Stdout:
		return newStdoutAdapter()
	case config.File:
		if out.File == nil {
			return nil, errors.New("文件配置缺失")
		}
		return newFileAdapter(*out.File)
	case config.DB:
		if out.Database == nil {
			return nil, errors.New("数据库配置缺失")
		}
		return newDBAdapter(*out.Database)
	case config.Syslog:
		if out.Syslog == nil {
			return nil, errors.New("Syslog配置缺失")
		}
		return newSyslogAdapter(*out.Syslog)
	default:
		return nil, fmt.Errorf("不支持的输出类型: %s", out.Type)
	}
}
