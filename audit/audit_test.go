package audit

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
)

func TestLevelAudit_Value(t *testing.T) {
	if LevelAudit < slog.LevelError {
		t.Errorf("LevelAudit = %d, must be >= LevelError (%d)", LevelAudit, slog.LevelError)
	}
	if LevelAudit != slog.LevelError+4 {
		t.Errorf("LevelAudit = %d, want %d", LevelAudit, slog.LevelError+4)
	}
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
		if string(ev) != want {
			t.Errorf("EventType %s = %q, want %q", ev, ev, want)
		}
	}
}

func TestAudit_DefaultEventType(t *testing.T) {
	var buf bytes.Buffer
	h := slog.New(slog.NewJSONHandler(&buf, nil))
	slog.SetDefault(h)
	defer slog.SetDefault(slog.Default())

	Audit("system audit")

	var result map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if result["event_type"] != "system" {
		t.Errorf("event_type = %v, want system", result["event_type"])
	}
}

func TestAuditEvent_ExplicitType(t *testing.T) {
	var buf bytes.Buffer
	h := slog.New(slog.NewJSONHandler(&buf, nil))
	slog.SetDefault(h)
	defer slog.SetDefault(slog.Default())

	AuditEvent(EventLogin, "user login", "actor", "user:42", "success", true, "ip", "127.0.0.1")

	var result map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if result["event_type"] != "login" {
		t.Errorf("event_type = %v, want login", result["event_type"])
	}
	if result["actor"] != "user:42" {
		t.Errorf("actor = %v, want user:42", result["actor"])
	}
}
