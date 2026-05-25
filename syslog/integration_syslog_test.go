//go:build integration

package syslog

import (
	"bufio"
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/iuboy/mebsuta"
	"github.com/stretchr/testify/require"
)

// captureSyslogTCP starts a TCP listener that captures raw syslog messages.
func captureSyslogTCP(t *testing.T) (string, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "listen")
	addr := ln.Addr().String()

	ch := make(chan string, 100)
	go func() {
		defer close(ch)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				scanner := bufio.NewScanner(c)
				scanner.Buffer(make([]byte, 8192), 8192)
				for scanner.Scan() {
					select {
					case ch <- scanner.Text():
					default:
					}
				}
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return addr, ch
}

// recvLine reads one line from the capture channel with timeout.
func recvLine(t *testing.T, ch <-chan string, timeout time.Duration) string {
	t.Helper()
	select {
	case line := <-ch:
		return line
	case <-time.After(timeout):
		t.Fatalf("timeout waiting for syslog message (%v)", timeout)
		return ""
	}
}

func TestIntegration_Syslog_RFC3164(t *testing.T) {
	addr, lines := captureSyslogTCP(t)

	h, err := NewHandler(Config{
		Network:    "tcp",
		Address:    addr,
		Tag:        "mebsuta-test",
		RFC5424:    false,
		RetryDelay: 200 * time.Millisecond,
	})
	require.NoError(t, err, "NewHandler")
	defer h.Close()

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "rfc3164-test-msg", 0)
	require.NoError(t, h.Handle(context.Background(), r), "Handle")

	line := recvLine(t, lines, 5*time.Second)
	require.Contains(t, line, "<6>", "should contain priority")
	require.Contains(t, line, "mebsuta-test", "should contain tag")
	require.Contains(t, line, "rfc3164-test-msg", "should contain message")
}

func TestIntegration_Syslog_RFC5424(t *testing.T) {
	addr, lines := captureSyslogTCP(t)

	h, err := NewHandler(Config{
		Network:    "tcp",
		Address:    addr,
		Tag:        "mebsuta-test",
		RFC5424:    true,
		RetryDelay: 200 * time.Millisecond,
	})
	require.NoError(t, err, "NewHandler")
	defer h.Close()

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "rfc5424-test-msg", 0)
	r.AddAttrs(slog.String("request_id", "req-123"))
	require.NoError(t, h.Handle(context.Background(), r), "Handle")

	line := recvLine(t, lines, 5*time.Second)
	require.Contains(t, line, "<6>1 ", "should contain RFC5424 header")
	require.Contains(t, line, "mebsuta-test", "should contain tag")
	require.Contains(t, line, "rfc5424-test-msg", "should contain message")
	require.Contains(t, line, `request_id="req-123"`, "should contain structured data")
}

func TestIntegration_Syslog_MultipleMessages(t *testing.T) {
	addr, lines := captureSyslogTCP(t)

	h, err := NewHandler(Config{
		Network:    "tcp",
		Address:    addr,
		Tag:        "mebsuta-test",
		RetryDelay: 200 * time.Millisecond,
	})
	require.NoError(t, err, "NewHandler")
	defer h.Close()

	const n = 20
	for i := range n {
		r := slog.NewRecord(time.Now(), slog.LevelInfo, "multi-test-msg", 0)
		r.AddAttrs(slog.Int("i", i))
		require.NoError(t, h.Handle(context.Background(), r), "Handle", i)
	}

	require.NoError(t, h.Flush(5*time.Second), "Flush")

	var count int
	timeout := time.After(10 * time.Second)
	for count < n {
		select {
		case <-lines:
			count++
		case <-timeout:
			t.Fatalf("timeout: received %d/%d messages", count, n)
		}
	}
}

func TestIntegration_Syslog_AuditLevel(t *testing.T) {
	addr, lines := captureSyslogTCP(t)

	h, err := NewHandler(Config{
		Network:    "tcp",
		Address:    addr,
		Tag:        "mebsuta-test",
		RFC5424:    true,
		Facility:   1,
		RetryDelay: 200 * time.Millisecond,
	})
	require.NoError(t, err, "NewHandler")
	defer h.Close()

	r := slog.NewRecord(time.Now(), mebsuta.LevelAudit, "audit-via-syslog", 0)
	require.NoError(t, h.Handle(context.Background(), r), "Handle")

	line := recvLine(t, lines, 5*time.Second)
	// Facility 1 * 8 + severity 2 (audit) = 10
	require.Contains(t, line, "<10>", "audit priority should be 10")
	require.Contains(t, line, "audit-via-syslog", "should contain message")
}
