// Package audit 提供面向中国网络安全标准的合规审计日志
// （等保 2.0 GB/T 22239、密评 GM/T 0054）。
//
// 本包为可选包，不需要合规审计能力的用户可以完全不引入。
package audit

import (
	"context"
	"log/slog"
)

// LevelAudit 为审计日志级别（等保 2.0 GB/T 22239、密评 GM/T 0054）。
// 严重度高于 Error；Error 级别的 handler 会接受 Audit 记录，采样器也始终放行。
const LevelAudit slog.Level = slog.LevelError + 4 // 12

// 编译期断言：LevelAudit 必须 >= LevelError，
// 以保证所有 handler 的 `level >= slog.LevelError` 检查都包含 Audit 记录。
// 零长数组 [0]struct{} 是合法 Go 代码，因此相等（LevelAudit == LevelError）
// 也能通过该检查。
var _ = [LevelAudit - slog.LevelError]struct{}{}

// EventType 标识审计记录所属的操作类别。
type EventType string

// 审计事件类型。
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

// Audit 以 Audit 级别记录合规日志。事件类型默认为 "system"。
func Audit(msg string, args ...any) {
	AuditEvent(EventSystem, msg, args...)
}

// AuditContext 以 Audit 级别携带 context 记录日志。事件类型默认为 "system"。
func AuditContext(ctx context.Context, msg string, args ...any) {
	AuditEventContext(ctx, EventSystem, msg, args...)
}

// AuditEvent 记录一条显式指定事件类型的审计记录。
func AuditEvent(eventType EventType, msg string, args ...any) {
	AuditEventContext(context.Background(), eventType, msg, args...)
}

// AuditEventContext 记录一条显式指定事件类型与 context 的审计记录。
//
// event_type 会作为最后一个 key=value 对追加到日志属性中。
// args 中任何 "event_type" 键都会被丢弃：last-wins 去重仅
// 对基于 map 的（JSON）输出有效——Console/Text 格式会把两个
// 键值对都输出，而采用 first-wins 的日志消费方会把审计事件归因于
// 一个可能受攻击者影响的值。丢弃调用方传入的键，可让权威的
// eventType 在每种输出格式中都保持唯一事实来源。
func AuditEventContext(ctx context.Context, eventType EventType, msg string, args ...any) {
	// M7：将 args 拷贝到新切片，绝不改动调用方的底层数组——
	// 变参 append 是个容易踩的坑，可能破坏调用方数据，
	// 尤其是带冗余容量的切片被多个 goroutine 复用时。
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
