package audit

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLevelAudit_Value(t *testing.T) {
	require.GreaterOrEqual(t, LevelAudit, slog.LevelError)
	require.Equal(t, slog.LevelError+4, LevelAudit)
}

func TestEventType_Values(t *testing.T) {
	events := map[EventType]string{
		EventLogin:            "login",
		EventLogout:           "logout",
		EventQuery:            "query",
		EventCreate:           "create",
		EventUpdate:           "update",
		EventDelete:           "delete",
		EventPermissionChange: "permission_change",
		EventConfigChange:     "config_change",
		EventKeyOperation:     "key_operation",
		EventCryptoOperation:  "crypto_operation",
		EventSystem:           "system",
	}
	for ev, want := range events {
		require.Equal(t, want, string(ev))
	}
}

func TestAudit_DefaultEventType(t *testing.T) {
	var buf bytes.Buffer
	h := slog.New(slog.NewJSONHandler(&buf, nil))
	slog.SetDefault(h)
	defer slog.SetDefault(slog.Default())

	Audit("system audit")

	var result map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &result), "invalid JSON")
	require.Equal(t, "system", result["event_type"])
}

func TestAuditEvent_ExplicitType(t *testing.T) {
	var buf bytes.Buffer
	h := slog.New(slog.NewJSONHandler(&buf, nil))
	slog.SetDefault(h)
	defer slog.SetDefault(slog.Default())

	AuditEvent(EventLogin, "user login", "actor", "user:42", "success", true, "ip", "127.0.0.1")

	var result map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &result), "invalid JSON")
	require.Equal(t, "login", result["event_type"])
	require.Equal(t, "user:42", result["actor"])
}
