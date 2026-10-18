// Package audit provides compliance audit logging for Chinese cybersecurity standards
// (等保 2.0 GB/T 22239, 密评 GM/T 0054).
//
// This package is optional. Users who don't need compliance audit features
// can skip importing it entirely.
package audit

import (
	"context"
	"log/slog"
)

// LevelAudit is the audit log level (等保 2.0 GB/T 22239, 密评 GM/T 0054).
// Severity is above Error; handlers at Error level accept Audit records, and samplers always pass them through.
const LevelAudit slog.Level = slog.LevelError + 4 // 12

// Compile-time assertion: LevelAudit must be >= LevelError so that
// all handlers' `level >= slog.LevelError` checks include Audit records.
// A zero-size array [0]struct{} is valid Go, so equality (LevelAudit == LevelError)
// also passes this check.
var _ = [LevelAudit - slog.LevelError]struct{}{}

// EventType identifies the operation class for audit records.
type EventType string

// Audit event types.
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

// Audit logs at the Audit level for compliance records. The event type defaults to "system".
func Audit(msg string, args ...any) {
	AuditEvent(EventSystem, msg, args...)
}

// AuditContext logs at the Audit level with the given context. The event type defaults to "system".
func AuditContext(ctx context.Context, msg string, args ...any) {
	AuditEventContext(ctx, EventSystem, msg, args...)
}

// AuditEvent logs an audit record with an explicit event type.
func AuditEvent(eventType EventType, msg string, args ...any) {
	AuditEventContext(context.Background(), eventType, msg, args...)
}

// AuditEventContext logs an audit record with an explicit event type and context.
//
// The event_type is appended as the last key=value pair in the log attributes.
// Any "event_type" key inside args is DROPPED: last-wins deduplication only
// works for map-based (JSON) output — the Console/Text format emits BOTH
// pairs, and a first-wins log consumer would attribute the audit event to an
// attacker-influenced value. Dropping the caller's key keeps the authoritative
// eventType the single source of truth in every output format.
func AuditEventContext(ctx context.Context, eventType EventType, msg string, args ...any) {
	// M7: copy args into a fresh slice so we never mutate the caller's backing
	// array — a variadic append footgun that can corrupt the caller's data,
	// especially if a slice with spare capacity is reused across goroutines.
	allArgs := make([]any, 0, len(args)+2)
	for i := 0; i+1 < len(args); i += 2 {
		if k, ok := args[i].(string); ok && k == "event_type" {
			continue
		}
		allArgs = append(allArgs, args[i], args[i+1])
	}
	allArgs = append(allArgs, "event_type", string(eventType))
	slog.Log(ctx, LevelAudit, msg, allArgs...)
}
