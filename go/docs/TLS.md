# Syslog TLS Configuration Guide

This guide explains how to configure TLS for secure syslog delivery.

## Overview

The SyslogHandler supports TLS encryption for secure log delivery. TLS is enabled via the `WithSecure` option, and certificate verification can be controlled with `WithTLSSkipVerify`.

## Basic TLS Configuration

### Enable TLS with Default Certificate Verification

The safest approach uses default certificate verification:

```go
cfg, err := config.NewSyslogConfig(
    "tcp",                    // network
    "logs.example.com:6514",  // address (standard TLS syslog port)
    config.WithSecure(true),  // enable TLS
)
if err != nil {
    log.Fatal(err)
}

syslogH, err := mebsuta.NewSyslogHandler(cfg, slog.LevelInfo)
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
cfg, err := config.NewSyslogConfig(
    "tcp",
    "internal-logs:6514",
    config.WithSecure(true),              // enable TLS
    config.WithTLSSkipVerify(true),       // skip certificate verification
)
```

**Warning**: `WithTLSSkipVerify(true)` disables:
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

    "github.com/iuboy/mebsuta/go"
    "github.com/iuboy/mebsuta/go/config"
)

func main() {
    cfg, err := config.NewSyslogConfig(
        "tcp",
        "logs.example.com:6514",
        config.WithSecure(true),           // enable TLS
        config.WithSyslogTag("myapp"),     // optional: set syslog tag
        config.WithSyslogFacility(1),      // optional: user-level messages
        config.WithSyslogReconnect(true),  // optional: auto-reconnect
        config.WithSyslogRetryDelay(500*time.Millisecond),
        config.WithRFC5424(true),          // optional: use RFC5424 format
    )
    if err != nil {
        log.Fatal(err)
    }

    syslogH, err := mebsuta.NewSyslogHandler(cfg, slog.LevelInfo)
    if err != nil {
        log.Fatal(err)
    }

    logger, err := mebsuta.New(mebsuta.WithHandler(syslogH))
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

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `WithSecure` | bool | `false` | Enable TLS encryption |
| `WithTLSSkipVerify` | bool | `false` | Skip certificate verification (not recommended) |
| `WithSyslogTag` | string | `"mebsuta"` | Syslog tag identifier |
| `WithSyslogFacility` | int | `1` | Syslog facility (1=user-level) |
| `WithSyslogReconnect` | bool | `true` | Auto-reconnect on connection loss |
| `WithSyslogRetryDelay` | `time.Duration` | `500ms` | Delay between reconnection attempts |
| `WithRFC5424` | bool | `false` | Use RFC5424 protocol (vs RFC3164) |

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
   // Good
   config.WithSecure(true)

   // Avoid unless necessary
   config.WithTLSSkipVerify(false)  // or omit (defaults to false)
   ```

2. **Use the standard TLS port (6514)**
   ```go
   "tcp", "logs.example.com:6514"
   ```

3. **Enable reconnection for reliability**
   ```go
   config.WithSyslogReconnect(true)
   ```

4. **Monitor connection errors**
   ```go
   // SyslogHandler reports errors via the configured error handler
   cfg, _ := config.NewSyslogConfig("tcp", "logs:6514", config.WithSecure(true))
   syslogH, _ := mebsuta.NewSyslogHandler(cfg, slog.LevelInfo)

   // Errors are available through metrics or custom error handlers
   ```

## Troubleshooting

### Certificate Verification Failed

**Error**: `x509: certificate signed by unknown authority`

**Solutions**:
1. Ensure the server certificate is issued by a trusted CA
2. For self-signed certificates, add the CA to the system trust store
3. (Not recommended) Use `WithTLSSkipVerify(true)` for testing

### Connection Timeout

**Error**: Timeout connecting to syslog server

**Solutions**:
1. Verify the address and port are correct
2. Check firewall rules allow outbound connections to the syslog port
3. Ensure the syslog server is running and accessible
4. Increase retry delay if needed: `WithSyslogRetryDelay(2 * time.Second)`

### TLS Handshake Failure

**Error**: TLS handshake failure

**Solutions**:
1. Verify the server supports TLS on the specified port
2. Check that the server certificate is valid (not expired)
3. Ensure TLS protocol version compatibility (Go uses TLS 1.2+)

## Handler Chain with Syslog

**Important**: Do NOT wrap SyslogHandler in AsyncHandler. SyslogHandler has its own internal buffer:

```go
// ✅ Correct - Syslog without Async
cfg, _ := config.NewSyslogConfig("tcp", "logs:6514", config.WithSecure(true))
syslogH, _ := mebsuta.NewSyslogHandler(cfg, slog.LevelInfo)

logger, _ := mebsuta.New(
    mebsuta.WithHandler(syslogH),
)

// ❌ Incorrect - Async wrapping Syslog (double buffering)
// This will be rejected at construction time
```

See `SPEC.md` section "Handler Chain Composition" for details on prohibited combinations.
