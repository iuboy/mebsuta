package adapter

import (
	"fmt"
	"io"

	"github.com/iuboy/mebsuta/config"
	"github.com/iuboy/mebsuta/core"
	meberrors "github.com/iuboy/mebsuta/errors"
	"go.uber.org/zap/zapcore"
)

// WriteSyncer 扩展接口，结合WriteSyncer和Closer
type WriteSyncer interface {
	zapcore.WriteSyncer
	io.Closer
}

// CreateSyncer 根据输出配置创建同步器
// out: 输出配置
// 返回: WriteSyncer实例或错误
func CreateSyncer(out config.OutputConfig) (core.WriteSyncer, error) {
	if !out.Enabled {
		return nil, meberrors.ErrOutputDisabled(fmt.Sprintf("输出类型 %s 已被禁用", out.Type))
	}

	switch out.Type {
	case config.Stdout:
		return newStdoutAdapter()
	case config.File:
		if out.File == nil {
			return nil, meberrors.ErrMissingConfig("文件配置缺失")
		}
		return newFileAdapter(*out.File)
	case config.DB:
		if out.Database == nil {
			return nil, meberrors.ErrMissingConfig("数据库配置缺失")
		}
		return newDBAdapter(*out.Database)
	case config.Syslog:
		if out.Syslog == nil {
			return nil, meberrors.ErrMissingConfig("Syslog配置缺失")
		}
		return newSyslogAdapter(*out.Syslog)
	default:
		return nil, meberrors.ErrUnsupportedType(fmt.Sprintf("不支持的输出类型: %s", out.Type))
	}
}
