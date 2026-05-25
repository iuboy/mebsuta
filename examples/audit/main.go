// audit: structured audit logging with event types
package main

import (
	"log/slog"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/audit"
)

func main() {
	logger, err := mebsuta.New()
	if err != nil {
		panic(err)
	}
	slog.SetDefault(logger)
	defer mebsuta.CloseAll(logger.Handler())

	audit.AuditEvent(audit.EventLogin, "user login",
		"actor", "user:42",
		"success", true,
		"ip", "192.168.1.1",
	)

	audit.AuditEvent(audit.EventPermissionChange, "role updated",
		"actor", "admin:1",
		"target", "user:42",
		"old_role", "viewer",
		"new_role", "editor",
	)

	audit.AuditEvent(audit.EventDelete, "record deleted",
		"actor", "user:42",
		"resource", "order:1001",
		"success", true,
	)

	audit.AuditEvent(audit.EventConfigChange, "config updated",
		"actor", "admin:1",
		"key", "max_connections",
		"old_value", "100",
		"new_value", "200",
	)
}
