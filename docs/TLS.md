# Syslog TLS 配置

## 基本用法

```go
syslogH, err := syslog.NewHandler(syslog.Config{
    Network: "tcp",
    Address: "logs.example.com:6514",
    TLS:     &mebsuta.TLSConfig{}, // 非 nil 即启用:系统信任池 + 主机名校验
})
```

默认行为：TLS 1.2+、系统证书池信任、服务器主机名验证。

## 跳过证书验证

仅用于开发或自签名证书环境：

```go
syslog.Config{
    Network: "tcp",
    Address: "internal-logs:6514",
    TLS:     &mebsuta.TLSConfig{InsecureSkipVerify: true},
}
```

## 完整配置

```go
syslogH, err := syslog.NewHandler(syslog.Config{
    Network:    "tcp",
    Address:    "logs.example.com:6514",
    Secure:     true,
    Tag:        "myapp",
    Facility:   1,
    Reconnect:  mebsuta.Ptr(true),
    RetryDelay: 500 * time.Millisecond,
})
```

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `TLS` | `*mebsuta.TLSConfig` | `nil` | 非 nil 启用 TLS（字段见 [mebsuta.TLSConfig](../README.md#tls--mtlstelemetry)） |
| `Tag` | string | `"mebsuta"` | Syslog 标识 |
| `Facility` | int | `1` | Syslog facility |
| `Reconnect` | `*bool` | `true` | 断线自动重连 |
| `RetryDelay` | `time.Duration` | `500ms` | 重连间隔 |
| `RFC3164` | bool | `false` | 使用 RFC3164 格式(默认 RFC5424) |

标准端口：`514`（明文）、`601`（RFC5424 明文）、`6514`（TLS，推荐）。

各 handler 的 TLS 字段统一为 `mebsuta.TLSConfig`（0.1.0-30 起）：CA/客户端证书对/SNI/InsecureSkipVerify 见 `tls.go`；MinVersion 固定 TLS 1.2，加密套件走 Go 默认。


## telemetry（OTLP/HTTP）TLS / mTLS

`telemetry.Config` 四件套：`TLSCAFile`（私有 CA，缺省系统池）、
`TLSCertFile`/`TLSKeyFile`（mTLS 客户端身份，必须成对）、`TLSServerName`
（SAN 覆写）。裸 `host:port` + TLS 字段升级为 TLS；显式 `http://` + TLS
字段被 `Validate` 拒绝。MinVersion TLS 1.2（对齐 syslog）。

## database（PostgreSQL / openGauss）mTLS

pgx DSN 原生支持，无需代码面：

```
postgres://u@h/db?sslmode=verify-full&sslrootcert=/etc/ca.pem&sslcert=/etc/client.pem&sslkey=/etc/client.key
```

mebsuta 侧 `dsnHasTLS` 仅用于无 TLS 告警启发；证书校验完全由驱动执行。
