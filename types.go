package mebsuta

// =============================================================================
// EncodingType — 日志输出编码格式
// =============================================================================

// EncodingType 定义日志输出编码格式。
type EncodingType string

const (
	// JSON 编码格式。
	JSON EncodingType = "json"
	// Console (Text) 编码格式，人类可读。
	Console EncodingType = "console"
)
