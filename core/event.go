package core

import "time"

type LogEvent struct {
	Timestamp   time.Time      `json:"time"`
	Level       string         `json:"level"`
	Message     string         `json:"msg"`
	Caller      string         `json:"caller,omitempty"`
	Stack       string         `json:"stack,omitempty"`
	Fields      map[string]any `json:"fields,omitempty"`
	ServiceName string         `json:"service,omitempty"`
	RequestID   string         `json:"request_id,omitempty"`
	Host        string         `json:"host,omitempty"`
	PID         int            `json:"pid,omitempty"`
}

type EventWriteSyncer interface {
	WriteEvent(event *LogEvent) error
	Sync() error
	Close() error
}

type WriteSyncer interface {
	Sync() error
	Close() error
	Write(p []byte) (n int, err error)
}
