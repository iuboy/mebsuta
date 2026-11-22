package mebsuta

import "log/slog"

// SeverityNumber 将 slog 级别映射到 OpenTelemetry 数值严重级刻度
// （1..24；见 OTel Logs Data Model 的 severity number 表）。
//
// slog 的级别以 4 为步长，而每个 OTel 严重级段恰好跨越一步，因此每个
// 级别都落在其段基值上：5（debug）、9（info）、13（warn）、17（error）。
// LevelAudit 映射到 21——fatal 段——因为它在设计上高于 Error，这样按
// SeverityNumber（而非文本）过滤的消费方仍能看到审计记录。
//
// 这是所有 OTel 对齐输出（mbta 与 otlp handler）共享的唯一规范映射；
// 将它从 mbta 中抽出可防止二者逐渐漂移。
func SeverityNumber(level slog.Level) int {
	switch {
	case level >= LevelAudit:
		return 21
	case level >= slog.LevelError:
		return 17
	case level >= slog.LevelWarn:
		return 13
	case level >= slog.LevelInfo:
		return 9
	default:
		return 5
	}
}
