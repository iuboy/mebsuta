package mebsuta

// TLS 共享结构（0.1.0-30，阶段 7；审查 F5）：syslog/telemetry/mbta 的
// TLS 配置收敛为一个形态。此前 syslog 只有 Secure/TLSSkipVerify 两个
// 开关（TLS 1.2 + 硬编码套件白名单，不支持私有 CA 与 mTLS）、mbta 五
// 个散字段、telemetry 四件套——三种写法各自漂移，安全语义（最小版本、
// 成对校验、CA 来源）各管各的。

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// TLSConfig 是各网络 handler 共享的 TLS 配置。nil（在宿主 Config 中）
// 表示不启用 TLS；非 nil 但字段全零 = 启用 TLS、系统信任池、主机名
// 校验——最常见的"只想加密"形态。
type TLSConfig struct {
	// CAFile 是私有 CA 的 PEM 文件；空则用系统信任池。
	CAFile string
	// CertFile/KeyFile 是 mTLS 客户端证书对；必须成对设置。
	CertFile string
	KeyFile  string
	// ServerName 覆写证书校验的主机名（端点与证书 SAN 不一致时）。
	ServerName string
	// InsecureSkipVerify 跳过证书校验——仅限开发/自签环境，各 handler
	// 会在启用时经错误链告警。
	InsecureSkipVerify bool
}

// Active 报告 TLS 是否启用（任意字段非零）。
func (c TLSConfig) Active() bool {
	return c.CAFile != "" || c.CertFile != "" || c.KeyFile != "" ||
		c.ServerName != "" || c.InsecureSkipVerify
}

// LoadTLSConfig 把 TLSConfig 加载为 *tls.Config。未启用（全零字段，
// 或宿主以 nil 区分时传零值）返回 (nil, nil)。证书/密钥必须成对；
// MinVersion 固定 TLS 1.2，加密套件走 Go 默认——Go 默认集是
// 安全面且随版本演进，硬编码白名单（F5 前的 syslog）会让现代套件
// 无法随升级启用。
func LoadTLSConfig(c TLSConfig) (*tls.Config, error) {
	if !c.Active() {
		return nil, nil
	}
	if (c.CertFile == "") != (c.KeyFile == "") {
		return nil, &ConfigError{Field: "TLS", Msg: "CertFile 与 KeyFile 必须成对设置"}
	}
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         c.ServerName,
		InsecureSkipVerify: c.InsecureSkipVerify, //nolint:gosec // 显式选项，各 handler 启用时告警
	}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, &ConfigError{Field: "TLS", Msg: fmt.Sprintf("read CAFile: %v", err)}
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, &ConfigError{Field: "TLS", Msg: fmt.Sprintf("CAFile %s contains no valid PEM certificate", c.CAFile)}
		}
		cfg.RootCAs = pool
	}
	if c.CertFile != "" {
		pair, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			return nil, &ConfigError{Field: "TLS", Msg: fmt.Sprintf("load client keypair: %v", err)}
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	return cfg, nil
}
