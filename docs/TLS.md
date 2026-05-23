# Syslog TLS Configuration Guide

This guide explains how to configure TLS for secure syslog delivery.

## Overview

The SyslogHandler supports TLS encryption for secure log delivery. TLS is enabled via the `Secure` field in `SyslogConfig`, and certificate verification can be controlled with `TLSSkipVerify`.

## Basic TLS Configuration

### Enable TLS with Default Certificate Verification

The safest approach uses default certificate verification:

```go
syslogH, err := mebsuta.NewSyslogHandler(mebsuta.SyslogConfig{
    Network: "tcp",
    Address: "logs.example.com:6514",
    Secure:  true,
})
if err != nil {
    log.Fatal(err)
}

logger := slog.New(syslogH)
logger.Info("message sent over TLS")
```

**Default behavior**:
- TLS 1.2+ is used
- System certificate pool is trusted
- Server certificate hostname is verified
- Certificate expiration is checked

### Skip Certificate Verification (Not Recommended for Production)

For testing or internal networks with self-signed certificates:

```go
syslogH, err := mebsuta.NewSyslogHandler(mebsuta.SyslogConfig{
    Network:        "tcp",
    Address:        "internal-logs:6514",
    Secure:         true,
    TLSSkipVerify:  true,
})
```

**Warning**: `TLSSkipVerify: true` disables:
- Certificate chain validation
- Hostname verification
- Expiration checking

This should only be used in development or with explicit operational approval.

## Complete TLS Configuration Example

```go
package main

import (
    "log"
    "log/slog"
    "time"

    "github.com/iuboy/mebsuta"
)

func main() {
    syslogH, err := mebsuta.NewSyslogHandler(mebsuta.SyslogConfig{
        Network:     "tcp",
        Address:     "logs.example.com:6514",
        Secure:      true,
        Tag:         "myapp",
        Facility:    1,
        Reconnect:   true,
        RetryDelay:  500 * time.Millisecond,
        RFC5424:     true,
    })
    if err != nil {
        log.Fatal(err)
    }

    logger, err := mebsuta.New(
        mebsuta.UseSyslog(mebsuta.SyslogConfig{
            Network: "tcp",
            Address: "logs.example.com:6514",
            Secure:  true,
        }),
    )
    if err != nil {
        log.Fatal(err)
    }

    logger.Info("application started",
        "version", "1.0.0",
        "environment", "production",
    )
}
```

## Configuration Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Secure` | bool | `false` | Enable TLS encryption |
| `TLSSkipVerify` | bool | `false` | Skip certificate verification (not recommended) |
| `Tag` | string | `"mebsuta"` | Syslog tag identifier |
| `Facility` | int | `1` | Syslog facility (1=user-level) |
| `Reconnect` | bool | `true` | Auto-reconnect on connection loss |
| `RetryDelay` | `time.Duration` | `500ms` | Delay between reconnection attempts |
| `RFC5424` | bool | `false` | Use RFC5424 protocol (vs RFC3164) |

## Port Reference

Standard syslog ports:
- `514` - Plain TCP/UDP (RFC3164)
- `6514` - TLS encrypted (RFC5424/RFC5425)
- `601` - Plain TCP (RFC5424)

**Recommendation**: Use port `6514` for TLS connections.

## Certificate Configuration

### System Certificate Pool

By default, Go uses the system's trusted certificate pool:
- **Linux**: `/etc/ssl/certs/ca-certificates.crt`
- **macOS**: System Keychain
- **Windows**: Certificate Store

No additional configuration is required for certificates issued by public CAs.

### Custom Certificates

For environments with custom certificate authorities, the Go runtime must be configured to trust the custom CA. This is typically done at the process level via environment variables or system configuration.

## Security Best Practices

1. **Always enable certificate verification in production**
   ```go
   mebsuta.SyslogConfig{Secure: true}
   ```

2. **Use the standard TLS port (6514)**
   ```go
   Network: "tcp", Address: "logs.example.com:6514"
   ```

3. **Enable reconnection for reliability**
   ```go
   mebsuta.SyslogConfig{Reconnect: true}
   ```

4. **Monitor connection errors**
   ```go
   // SyslogHandler reports errors via the configured error handler
   syslogH, _ := mebsuta.NewSyslogHandler(mebsuta.SyslogConfig{
       Network: "tcp", Address: "logs:6514", Secure: true,
   })
   // Errors are available through metrics or custom error handlers
   ```

## Troubleshooting

### Certificate Verification Failed

**Error**: `x509: certificate signed by unknown authority`

**Solutions**:
1. Ensure the server certificate is issued by a trusted CA
2. For self-signed certificates, add the CA to the system trust store
3. (Not recommended) Use `TLSSkipVerify: true` for testing

### Connection Timeout

**Error**: Timeout connecting to syslog server

**Solutions**:
1. Verify the address and port are correct
2. Check firewall rules allow outbound connections to the syslog port
3. Ensure the syslog server is running and accessible
4. Increase retry delay if needed: `RetryDelay: 2 * time.Second`

### TLS Handshake Failure

**Error**: TLS handshake failure

**Solutions**:
1. Verify the server supports TLS on the specified port
2. Check that the server certificate is valid (not expired)
3. Ensure TLS protocol version compatibility (Go uses TLS 1.2+)

## Handler Chain with Syslog

**Important**: Do NOT wrap SyslogHandler in AsyncHandler. SyslogHandler has its own internal buffer:

```go
// Correct - Syslog without Async
logger, _ := mebsuta.New(
    mebsuta.UseSyslog(mebsuta.SyslogConfig{
        Network: "tcp", Address: "logs:6514", Secure: true,
    }),
)

// Incorrect - Async wrapping Syslog (double buffering)
// This will be rejected at construction time
```

See `SPEC.md` section "Handler Chain Composition" for details on prohibited combinations.
