package mebsuta

import "log/slog"

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

// =============================================================================
// LevelAudit — 审计日志级别
// =============================================================================

// LevelAudit 是审计日志级别，用于合规日志（等保 2.0 GB/T 22239、密评 GM/T 0054）。
// 严重性高于 Error：Error 级别的 handler 会接受 Audit 记录。
// 采样器始终放行 Audit 记录。
//
// Cross-reference: SPEC.md "Levels" section。
const LevelAudit slog.Level = slog.LevelError + 4 // 12
