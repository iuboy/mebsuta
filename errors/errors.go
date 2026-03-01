// Package errors 提供统一的错误处理机制
package errors

import (
	"fmt"
	"runtime"
	"strings"
)

// ErrorCode 定义错误码类型
type ErrorCode string

const (
	// 配置相关错误
	ErrCodeInvalidConfig  ErrorCode = "INVALID_CONFIG"
	ErrCodeMissingConfig  ErrorCode = "MISSING_CONFIG"
	ErrCodeValidateFailed ErrorCode = "VALIDATE_FAILED"

	// 初始化相关错误
	ErrCodeInitFailed     ErrorCode = "INIT_FAILED"
	ErrCodeLoggerNotReady ErrorCode = "LOGGER_NOT_READY"

	// 输出相关错误
	ErrCodeCreateSyncer    ErrorCode = "CREATE_SYNCER"
	ErrCodeOutputDisabled  ErrorCode = "OUTPUT_DISABLED"
	ErrCodeUnsupportedType ErrorCode = "UNSUPPORTED_TYPE"

	// 数据库相关错误
	ErrCodeDBConnect       ErrorCode = "DB_CONNECT"
	ErrCodeDBWrite         ErrorCode = "DB_WRITE"
	ErrCodeDBFlush         ErrorCode = "DB_FLUSH"
	ErrCodeDBConnectFailed ErrorCode = "DB_CONNECT_FAILED"

	// 文件相关错误
	ErrCodeFileCreate  ErrorCode = "FILE_CREATE"
	ErrCodeFileWrite   ErrorCode = "FILE_WRITE"
	ErrCodeInvalidPath ErrorCode = "INVALID_PATH"

	// Syslog相关错误
	ErrCodeSyslogConnect ErrorCode = "SYSLOG_CONNECT"
	ErrCodeSyslogWrite   ErrorCode = "SYSLOG_WRITE"

	// 采样相关错误
	ErrCodeSamplerInit ErrorCode = "SAMPLER_INIT"

	// 编码器相关错误
	ErrCodeEncoderCreate ErrorCode = "ENCODER_CREATE"

	// 通用错误
	ErrCodeInternal ErrorCode = "INTERNAL_ERROR"
	ErrCodeTimeout  ErrorCode = "TIMEOUT"
	ErrCodeCanceled ErrorCode = "CANCELED"
)

// MebsutaError 自定义错误类型
type MebsutaError struct {
	Code        ErrorCode
	Message     string
	Err         error
	stackTrace_ string // 调用栈信息
}

// StackTrace 返回调用栈信息
func (e *MebsutaError) StackTrace() string {
	return e.stackTrace_
}

// Error 实现error接口
func (e *MebsutaError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// FullStack 返回完整的错误信息，包含调用栈
func (e *MebsutaError) FullStack() string {
	var sb strings.Builder
	sb.WriteString(e.Error())
	if e.stackTrace_ != "" {
		sb.WriteString("\n调用栈:\n")
		sb.WriteString(e.stackTrace_)
	}
	if e.Err != nil {
		sb.WriteString("\n包装错误: ")
		sb.WriteString(e.Err.Error())
	}
	return sb.String()
}

// Unwrap 支持错误解包
func (e *MebsutaError) Unwrap() error {
	return e.Err
}

// New 创建新的错误，自动捕获调用栈
func New(code ErrorCode, message string) *MebsutaError {
	return &MebsutaError{
		Code:        code,
		Message:     message,
		stackTrace_: captureStackTrace(1),
	}
}

// Wrap 包装错误，自动捕获调用栈
func Wrap(err error, code ErrorCode, message string) *MebsutaError {
	return &MebsutaError{
		Code:        code,
		Message:     message,
		Err:         err,
		stackTrace_: captureStackTrace(2),
	}
}

// Wrapf 包装错误（格式化消息），自动捕获调用栈
func Wrapf(err error, code ErrorCode, format string, args ...interface{}) *MebsutaError {
	return &MebsutaError{
		Code:        code,
		Message:     fmt.Sprintf(format, args...),
		Err:         err,
		stackTrace_: captureStackTrace(2),
	}
}

// 预定义的常用错误构造函数
var (
	// 配置错误
	ErrInvalidConfig  = func(msg string) *MebsutaError { return New(ErrCodeInvalidConfig, msg) }
	ErrMissingConfig  = func(msg string) *MebsutaError { return New(ErrCodeMissingConfig, msg) }
	ErrValidateFailed = func(msg string) *MebsutaError { return New(ErrCodeValidateFailed, msg) }

	// 初始化错误
	ErrInitFailed     = func(msg string) *MebsutaError { return New(ErrCodeInitFailed, msg) }
	ErrLoggerNotReady = func(msg string) *MebsutaError { return New(ErrCodeLoggerNotReady, msg) }

	// 输出错误
	ErrCreateSyncer    = func(msg string) *MebsutaError { return New(ErrCodeCreateSyncer, msg) }
	ErrOutputDisabled  = func(msg string) *MebsutaError { return New(ErrCodeOutputDisabled, msg) }
	ErrUnsupportedType = func(msg string) *MebsutaError { return New(ErrCodeUnsupportedType, msg) }

	// 数据库错误
	ErrDBConnect = func(msg string) *MebsutaError { return New(ErrCodeDBConnect, msg) }
	ErrDBWrite   = func(msg string) *MebsutaError { return New(ErrCodeDBWrite, msg) }
	ErrDBFlush   = func(msg string) *MebsutaError { return New(ErrCodeDBFlush, msg) }

	// 文件错误
	ErrFileCreate  = func(msg string) *MebsutaError { return New(ErrCodeFileCreate, msg) }
	ErrFileWrite   = func(msg string) *MebsutaError { return New(ErrCodeFileWrite, msg) }
	ErrInvalidPath = func(msg string) *MebsutaError { return New(ErrCodeInvalidPath, msg) }

	// Syslog错误
	ErrSyslogConnect = func(msg string) *MebsutaError { return New(ErrCodeSyslogConnect, msg) }
	ErrSyslogWrite   = func(msg string) *MebsutaError { return New(ErrCodeSyslogWrite, msg) }

	// 采样错误
	ErrSamplerInit = func(msg string) *MebsutaError { return New(ErrCodeSamplerInit, msg) }

	// 编码器错误
	ErrEncoderCreate = func(msg string) *MebsutaError { return New(ErrCodeEncoderCreate, msg) }

	// 通用错误
	ErrInternal = func(msg string) *MebsutaError { return New(ErrCodeInternal, msg) }
	ErrTimeout  = func(msg string) *MebsutaError { return New(ErrCodeTimeout, msg) }
	ErrCanceled = func(msg string) *MebsutaError { return New(ErrCodeCanceled, msg) }
)

// IsMebsutaError 判断是否为MebsutaError
func IsMebsutaError(err error) bool {
	_, ok := err.(*MebsutaError)
	return ok
}

// GetCode 获取错误码
func GetCode(err error) ErrorCode {
	if me, ok := err.(*MebsutaError); ok {
		return me.Code
	}
	return ""
}

// GetMessage 获取错误消息
func GetMessage(err error) string {
	if me, ok := err.(*MebsutaError); ok {
		return me.Message
	}
	return ""
}

// captureStackTrace 捕获调用栈信息
// skip 跳过的调用栈帧数
func captureStackTrace(skip int) string {
	const maxDepth = 32
	pcs := make([]uintptr, maxDepth)
	n := runtime.Callers(skip+1, pcs)
	if n == 0 {
		return ""
	}

	var sb strings.Builder
	frames := runtime.CallersFrames(pcs[:n])
	for {
		frame, more := frames.Next()
		// 格式: 文件:行号 函数名
		sb.WriteString(fmt.Sprintf("    %s:%d %s\n", frame.File, frame.Line, frame.Function))
		if !more {
			break
		}
	}
	return sb.String()
}

// WithStack 为现有错误添加调用栈信息
func WithStack(err error) *MebsutaError {
	if me, ok := err.(*MebsutaError); ok {
		if me.stackTrace_ == "" {
			me.stackTrace_ = captureStackTrace(1)
		}
		return me
	}
	// 对于非MebsutaError，包装它
	return &MebsutaError{
		Code:        ErrCodeInternal,
		Message:     "wrapped error",
		Err:         err,
		stackTrace_: captureStackTrace(1),
	}
}
