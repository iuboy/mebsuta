package mebsuta

import "log/slog"

// EncodingType 定义日志输出编码格式。
type EncodingType string

const (
	JSON    EncodingType = "json"
	Console EncodingType = "console"
)

// LevelAudit 是审计日志级别（等保 2.0 GB/T 22239、密评 GM/T 0054）。
// 严重性高于 Error，Error 级别的 handler 会接受 Audit 记录，采样器始终放行。
const LevelAudit slog.Level = slog.LevelError + 4 // 12

// Compile-time assertion: LevelAudit must be >= LevelError so that
// all handlers' `level >= slog.LevelError` checks include Audit records.
var _ [LevelAudit - slog.LevelError]struct{}
