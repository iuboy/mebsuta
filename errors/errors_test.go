package errors_test

import (
	"errors"
	"fmt"
	"testing"

	meberrors "github.com/iuboy/mebsuta/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewError 测试创建自定义错误
func TestNewError(t *testing.T) {
	err := meberrors.New(meberrors.ErrCodeValidateFailed, "测试错误消息")

	assert.True(t, meberrors.IsMebsutaError(err))
	assert.Equal(t, meberrors.ErrCodeValidateFailed, meberrors.GetCode(err))
	assert.Equal(t, "测试错误消息", meberrors.GetMessage(err))
}

// TestWrap 测试错误包装
func TestWrap(t *testing.T) {
	// 原始错误
	originalErr := fmt.Errorf("数据库连接失败")

	// 包装错误
	wrappedErr := meberrors.Wrap(originalErr, meberrors.ErrCodeDBConnect, "无法连接数据库")

	require.True(t, meberrors.IsMebsutaError(wrappedErr))
	assert.Equal(t, meberrors.ErrCodeDBConnect, meberrors.GetCode(wrappedErr))
	assert.Equal(t, "无法连接数据库", meberrors.GetMessage(wrappedErr))

	// 使用errors.Is检查原始错误
	assert.True(t, errors.Is(wrappedErr, originalErr))
}

// TestWrapMultiple 测试多次包装
func TestWrapMultiple(t *testing.T) {
	err1 := fmt.Errorf("底层错误")
	err2 := meberrors.Wrap(err1, meberrors.ErrCodeDBWrite, "写入失败")
	err3 := meberrors.Wrap(err2, meberrors.ErrCodeInternal, "批量写入失败")

	assert.True(t, meberrors.IsMebsutaError(err3))
	assert.Equal(t, meberrors.ErrCodeInternal, meberrors.GetCode(err3))
	assert.Equal(t, "批量写入失败", meberrors.GetMessage(err3))

	// 验证错误链
	assert.True(t, errors.Is(err3, err1))
	assert.True(t, errors.Is(err3, err2))
}

// TestErrorMethods 测试标准错误方法
func TestErrorMethods(t *testing.T) {
	err := meberrors.New(meberrors.ErrCodeInternal, "内部错误")

	// 测试Error()方法
	assert.Contains(t, err.Error(), meberrors.ErrCodeInternal)
	assert.Contains(t, err.Error(), "内部错误")
}

// TestIsMebsutaError 测试错误类型判断
func TestIsMebsutaError(t *testing.T) {
	// 自定义错误
	customErr := meberrors.New(meberrors.ErrCodeValidateFailed, "验证失败")
	assert.True(t, meberrors.IsMebsutaError(customErr))

	// 标准错误
	stdErr := fmt.Errorf("标准错误")
	assert.False(t, meberrors.IsMebsutaError(stdErr))

	// nil错误
	assert.False(t, meberrors.IsMebsutaError(nil))
}

// TestGetCode 测试获取错误码
func TestGetCode(t *testing.T) {
	testCases := []struct {
		name         string
		err          error
		expectedCode meberrors.ErrorCode
	}{
		{
			name:         "自定义错误",
			err:          meberrors.New(meberrors.ErrCodeDBConnect, "连接失败"),
			expectedCode: meberrors.ErrCodeDBConnect,
		},
		{
			name:         "标准错误",
			err:          fmt.Errorf("标准错误"),
			expectedCode: "",
		},
		{
			name:         "nil错误",
			err:          nil,
			expectedCode: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			code := meberrors.GetCode(tc.err)
			assert.Equal(t, tc.expectedCode, code)
		})
	}
}

// TestGetMessage 测试获取错误消息
func TestGetMessage(t *testing.T) {
	testCases := []struct {
		name            string
		err             error
		expectedMessage string
	}{
		{
			name:            "自定义错误",
			err:             meberrors.New(meberrors.ErrCodeValidateFailed, "配置验证失败"),
			expectedMessage: "配置验证失败",
		},
		{
			name:            "标准错误",
			err:             fmt.Errorf("标准错误消息"),
			expectedMessage: "",
		},
		{
			name:            "nil错误",
			err:             nil,
			expectedMessage: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			msg := meberrors.GetMessage(tc.err)
			assert.Equal(t, tc.expectedMessage, msg)
		})
	}
}

// TestUnwrap 测试错误解包
func TestUnwrap(t *testing.T) {
	originalErr := fmt.Errorf("原始错误")
	wrappedErr := meberrors.Wrap(originalErr, meberrors.ErrCodeInternal, "包装错误")

	// 测试Unwrap方法
	unwrapped := errors.Unwrap(wrappedErr)
	assert.Equal(t, originalErr, unwrapped)
}

// TestErrorsAs 测试错误类型转换
func TestErrorsAs(t *testing.T) {
	err := meberrors.New(meberrors.ErrCodeValidateFailed, "验证失败")

	var mebErr *meberrors.MebsutaError
	assert.True(t, errors.As(err, &mebErr))
	assert.Equal(t, meberrors.ErrCodeValidateFailed, mebErr.Code)
	assert.Equal(t, "验证失败", mebErr.Message)
}

// TestConvenienceFunctions 测试便利函数
func TestConvenienceFunctions(t *testing.T) {
	t.Run("ErrValidateFailed", func(t *testing.T) {
		err := meberrors.ErrValidateFailed("参数错误")
		assert.Equal(t, meberrors.ErrCodeValidateFailed, meberrors.GetCode(err))
		assert.Contains(t, err.Error(), "参数错误")
	})

	t.Run("ErrMissingConfig", func(t *testing.T) {
		err := meberrors.ErrMissingConfig("缺少数据库配置")
		assert.Equal(t, meberrors.ErrCodeMissingConfig, meberrors.GetCode(err))
		assert.Contains(t, err.Error(), "缺少数据库配置")
	})

	t.Run("ErrUnsupportedType", func(t *testing.T) {
		err := meberrors.ErrUnsupportedType("不支持的类型")
		assert.Equal(t, meberrors.ErrCodeUnsupportedType, meberrors.GetCode(err))
		assert.Contains(t, err.Error(), "不支持的类型")
	})

	t.Run("ErrDBConnect", func(t *testing.T) {
		err := meberrors.ErrDBConnect("连接超时")
		assert.Equal(t, meberrors.ErrCodeDBConnect, meberrors.GetCode(err))
		assert.Contains(t, err.Error(), "连接超时")
	})

	t.Run("ErrDBWrite", func(t *testing.T) {
		err := meberrors.ErrDBWrite("写入失败")
		assert.Equal(t, meberrors.ErrCodeDBWrite, meberrors.GetCode(err))
		assert.Contains(t, err.Error(), "写入失败")
	})

	t.Run("ErrEncoderCreate", func(t *testing.T) {
		err := meberrors.ErrEncoderCreate("编码器创建失败")
		assert.Equal(t, meberrors.ErrCodeEncoderCreate, meberrors.GetCode(err))
		assert.Contains(t, err.Error(), "编码器创建失败")
	})
}

// TestErrorCodes 测试错误码定义
func TestErrorCodes(t *testing.T) {
	codes := []meberrors.ErrorCode{
		meberrors.ErrCodeInvalidConfig,
		meberrors.ErrCodeMissingConfig,
		meberrors.ErrCodeValidateFailed,
		meberrors.ErrCodeInitFailed,
		meberrors.ErrCodeLoggerNotReady,
		meberrors.ErrCodeCreateSyncer,
		meberrors.ErrCodeOutputDisabled,
		meberrors.ErrCodeUnsupportedType,
		meberrors.ErrCodeDBConnect,
		meberrors.ErrCodeDBWrite,
		meberrors.ErrCodeDBFlush,
		meberrors.ErrCodeDBConnectFailed,
		meberrors.ErrCodeFileCreate,
		meberrors.ErrCodeFileWrite,
		meberrors.ErrCodeInvalidPath,
		meberrors.ErrCodeSyslogConnect,
		meberrors.ErrCodeSyslogWrite,
		meberrors.ErrCodeSamplerInit,
		meberrors.ErrCodeEncoderCreate,
		meberrors.ErrCodeInternal,
		meberrors.ErrCodeTimeout,
		meberrors.ErrCodeCanceled,
	}

	for _, code := range codes {
		assert.NotEmpty(t, code, "错误码不应为空")
	}
}

// TestChineseMessages 测试中文错误消息
func TestChineseMessages(t *testing.T) {
	err := meberrors.New(meberrors.ErrCodeValidateFailed, "配置验证失败")
	errMsg := err.Error()

	// 验证包含中文
	assert.Contains(t, errMsg, "配置验证失败")
	assert.Contains(t, errMsg, meberrors.ErrCodeValidateFailed)
}

// TestStackTrace 测试堆栈跟踪
func TestStackTrace(t *testing.T) {
	err := meberrors.New(meberrors.ErrCodeInternal, "内部错误")

	// 测试 StackTrace() 方法
	stackTrace := err.StackTrace()
	// 堆栈跟踪应该包含文件名和行号格式
	assert.NotEmpty(t, stackTrace)
}

// TestFullStack 测试完整堆栈信息
func TestFullStack(t *testing.T) {
	t.Run("无包装错误", func(t *testing.T) {
		err := meberrors.New(meberrors.ErrCodeInternal, "内部错误")
		fullStack := err.FullStack()

		assert.Contains(t, fullStack, "内部错误")
		assert.Contains(t, fullStack, meberrors.ErrCodeInternal)
	})

	t.Run("有包装错误", func(t *testing.T) {
		originalErr := fmt.Errorf("底层错误")
		wrappedErr := meberrors.Wrap(originalErr, meberrors.ErrCodeDBConnect, "连接失败")
		fullStack := wrappedErr.FullStack()

		assert.Contains(t, fullStack, "连接失败")
		assert.Contains(t, fullStack, "底层错误")
	})
}

// TestWrapf 测试格式化包装错误
func TestWrapf(t *testing.T) {
	originalErr := fmt.Errorf("数据库错误")
	wrappedErr := meberrors.Wrapf(originalErr, meberrors.ErrCodeDBWrite, "写入表 %s 失败，共 %d 条记录", "users", 100)

	require.True(t, meberrors.IsMebsutaError(wrappedErr))
	assert.Equal(t, meberrors.ErrCodeDBWrite, meberrors.GetCode(wrappedErr))
	assert.Contains(t, wrappedErr.Error(), "写入表 users 失败，共 100 条记录")
}

// TestWithStack 测试添加堆栈信息
func TestWithStack(t *testing.T) {
	t.Run("MebsutaError添加堆栈", func(t *testing.T) {
		err := meberrors.New(meberrors.ErrCodeInternal, "内部错误")
		// New 已经自动捕获堆栈，所以 FullStack 应该包含调用栈
		fullStack := err.FullStack()
		assert.Contains(t, fullStack, "调用栈")
	})

	t.Run("标准错误添加堆栈", func(t *testing.T) {
		originalErr := fmt.Errorf("标准错误")
		wrappedErr := meberrors.WithStack(originalErr)

		assert.True(t, meberrors.IsMebsutaError(wrappedErr))
		assert.Contains(t, wrappedErr.FullStack(), "标准错误")
		assert.Contains(t, wrappedErr.FullStack(), "调用栈")
	})
}
