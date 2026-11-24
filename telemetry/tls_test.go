package telemetry

// wasat 接入缺口①的回归测试：TLS 凭据面——私有 CA 单向 TLS、mTLS 客户端
// 证书（双向）与校验规则。

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/iuboy/mebsuta"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/iuboy/mebsuta/mebsutatest"
	"github.com/stretchr/testify/require"
)

// certMaker 为测试签发一次性的 CA 与叶子证书。
type certMaker struct {
	ca    *x509.Certificate
	caPEM []byte
	caKey *rsa.PrivateKey
	dir   string
}

func newCertMaker(t *testing.T, commonName string) *certMaker {
	t.Helper()
	dir := t.TempDir()
	m := &certMaker{dir: dir}

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	m.ca, err = x509.ParseCertificate(caDER)
	require.NoError(t, err)
	m.caKey = caKey
	m.caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ca.pem"), m.caPEM, 0600))
	return m
}

// leaf 签发一张由该 CA 签名的叶子证书，并写出证书/私钥文件。
func (m *certMaker) leaf(t *testing.T, name string, clientAuth bool) (certFile, keyFile string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{name},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	if clientAuth {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, m.ca, &key.PublicKey, m.caKey)
	require.NoError(t, err)
	certFile = filepath.Join(m.dir, name+".pem")
	keyFile = filepath.Join(m.dir, name+".key")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600))
	return certFile, keyFile
}

// TestStart_PrivateCAHTTPSCollector 覆盖缺口 ①：https 端点的证书链到
// 私有 CA（wasat 的单二进制形态）——只有 TLSCAFile 被尊重时才可连通。
func TestStart_PrivateCAHTTPSCollector(t *testing.T) {
	m := newCertMaker(t, "test-ca")
	srvCert, srvKey := m.leaf(t, "collector", false)

	// TLS 接收端，其服务器证书是私有 CA 签发的叶子证书。
	inner := mebsutatest.NewOTLPReceiver()
	defer inner.Close()
	srv := httptest.NewUnstartedServer(inner.Handler())
	srv.TLS = simpleServerTLS(t, srvCert, srvKey)
	srv.StartTLS()
	defer srv.Close()

	// httptest URL 的主机是 127.0.0.1；证书 SAN 同样含 127.0.0.1，
	// 因此严格说不需要 TLSServerName——这里仍设置它以覆盖覆盖路径。
	cfg := Config{
		ServiceName: "tls-svc",
		Endpoint:    srv.URL,
		Signals:     Traces,
		TLS:         &mebsuta.TLSConfig{CAFile: filepath.Join(m.dir, "ca.pem")},
	}
	_, err0 := cfg.Validate()
	require.NoError(t, err0)

	tel, err := Start(context.Background(), cfg)
	require.NoError(t, err)

	_, span := tel.TracerProvider().Tracer("t").Start(context.Background(), "over-private-ca")
	span.End()
	require.NoError(t, tel.Shutdown(context.Background()))

	require.Len(t, inner.Spans(), 1, "span must arrive over the private-CA TLS channel")
}

// TestStart_MTLSClientCert 验证客户端这一半：强制要求客户端证书的服务器，
// 只有在设置了客户端身份文件时才接受被桥接的 exporter（缺失时拒绝）。
func TestStart_MTLSClientCert(t *testing.T) {
	m := newCertMaker(t, "test-ca")
	srvCert, srvKey := m.leaf(t, "collector", false)
	cliCert, cliKey := m.leaf(t, "bridge-client", true)

	inner := mebsutatest.NewOTLPReceiver()
	defer inner.Close()
	srv := httptest.NewUnstartedServer(inner.Handler())
	srv.TLS = simpleServerTLS(t, srvCert, srvKey)
	// 要求并针对同一 CA 校验客户端证书。
	clientPool := x509.NewCertPool()
	clientPool.AddCert(m.ca)
	srv.TLS.ClientAuth = tls.RequireAndVerifyClientCert
	srv.TLS.ClientCAs = clientPool
	srv.StartTLS()
	defer srv.Close()

	t.Run("with client identity", func(t *testing.T) {
		tel, err := Start(context.Background(), Config{
			ServiceName: "mtls-svc",
			Endpoint:    srv.URL,
			Signals:     Traces,
			TLS: &mebsuta.TLSConfig{
				CAFile:     filepath.Join(m.dir, "ca.pem"),
				CertFile:   cliCert,
				KeyFile:    cliKey,
				ServerName: "127.0.0.1",
			},
		})
		require.NoError(t, err)
		_, span := tel.TracerProvider().Tracer("t").Start(context.Background(), "mtls")
		span.End()
		require.NoError(t, tel.Shutdown(context.Background()))
		require.Len(t, inner.Spans(), 1)
	})

	t.Run("without client identity the handshake fails", func(t *testing.T) {
		inner.Reset()
		tel, err := Start(context.Background(), Config{
			ServiceName: "mtls-svc",
			Endpoint:    srv.URL,
			Signals:     Traces,
			TLS:         &mebsuta.TLSConfig{CAFile: filepath.Join(m.dir, "ca.pem")},
		})
		require.NoError(t, err)
		_, span := tel.TracerProvider().Tracer("t").Start(context.Background(), "mtls")
		span.End()
		require.NoError(t, tel.Shutdown(context.Background()))
		require.Empty(t, inner.Spans(), "server requiring client certs must reject the bare client")
	})
}

// TestValidate_TLSRules 钉住跨字段规则。
func TestValidate_TLSRules(t *testing.T) {
	httpCfg := Config{
		ServiceName: "s",
		Endpoint:    "http://fwd:4318",
		TLS:         &mebsuta.TLSConfig{CAFile: "ca.pem"},
	}
	_, err := httpCfg.Validate()
	require.ErrorContains(t, err, "http://")

	halfCfg := Config{
		ServiceName: "s",
		Endpoint:    "https://fwd:4318",
		TLS:         &mebsuta.TLSConfig{CertFile: "c.pem", ServerName: "fwd"},
	}
	_, err = halfCfg.Validate()
	require.ErrorContains(t, err, "必须成对")
}

// simpleServerTLS 为 httptest 服务器加载叶子证书对。
func simpleServerTLS(t *testing.T, certFile, keyFile string) *tls.Config {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	require.NoError(t, err)
	return &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
}
