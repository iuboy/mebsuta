package mebsuta

import "log/slog"

// EncodingType defines the log output encoding format.
type EncodingType string

const (
	JSON    EncodingType = "json"
	Console EncodingType = "console"
)

// EventType identifies the operation class for audit records.
type EventType string

const (
	EventLogin            EventType = "login"
	EventLogout           EventType = "logout"
	EventQuery            EventType = "query"
	EventCreate           EventType = "create"
	EventUpdate           EventType = "update"
	EventDelete           EventType = "delete"
	EventPermissionChange EventType = "permission_change"
	EventConfigChange     EventType = "config_change"
	EventKeyOperation     EventType = "key_operation"
	EventCryptoOperation  EventType = "crypto_operation"
	EventSystem           EventType = "system"
)

// LevelAudit 是审计日志级别（等保 2.0 GB/T 22239、密评 GM/T 0054）。
// 严重性高于 Error，Error 级别的 handler 会接受 Audit 记录，采样器始终放行。
const LevelAudit slog.Level = slog.LevelError + 4 // 12

// Compile-time assertion: LevelAudit must be >= LevelError so that
// all handlers' `level >= slog.LevelError` checks include Audit records.
var _ [LevelAudit - slog.LevelError]struct{}
