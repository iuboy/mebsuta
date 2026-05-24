# Syslog TLS 配置

## 基本用法

```go
syslogH, err := syslog.NewHandler(syslog.Config{
    Network: "tcp",
    Address: "logs.example.com:6514",
    Secure:  true,
})
```

默认行为：TLS 1.2+、系统证书池信任、服务器主机名验证。

## 跳过证书验证

仅用于开发或自签名证书环境：

```go
syslog.Config{
    Network:       "tcp",
    Address:       "internal-logs:6514",
    Secure:        true,
    TLSSkipVerify: true,
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
    Reconnect:  mebsuta.BoolPtr(true),
    RetryDelay: 500 * time.Millisecond,
    RFC5424:    true,
})
```

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `Secure` | bool | `false` | 启用 TLS |
| `TLSSkipVerify` | bool | `false` | 跳过证书验证 |
| `Tag` | string | `"mebsuta"` | Syslog 标识 |
| `Facility` | int | `1` | Syslog facility |
| `Reconnect` | `*bool` | `true` | 断线自动重连 |
| `RetryDelay` | `time.Duration` | `500ms` | 重连间隔 |
| `RFC5424` | bool | `false` | 使用 RFC5424 格式 |

标准端口：`514`（明文）、`601`（RFC5424 明文）、`6514`（TLS，推荐）。
