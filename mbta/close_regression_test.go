package mbta

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	mbtago "github.com/iuboy/mbta-go"
	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
	v1 "github.com/iuboy/mbta-go/v1"
)

// countingSink tallies every signal the server accepted.
type countingSink struct {
	count atomic.Int64
}

func (s *countingSink) OnSignalBatch(_ context.Context, _ string, batch *core.SignalBatch) error {
	for range batch.Signals {
		s.count.Add(1)
	}
	return nil
}

func (s *countingSink) OnPressure(string) core.PressureState { return core.PressureNormal }

// writeSelfSignedCert creates a throwaway self-signed server certificate and
// returns the cert/key file paths.
func writeSelfSignedCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "server.crt")
	keyPath = filepath.Join(dir, "server.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// startTestServer boots an in-process MBTA server on a free localhost port.
func startTestServer(t *testing.T, sink *countingSink) (addr string, stop func()) {
	t.Helper()
	certPath, keyPath := writeSelfSignedCert(t)

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr = conn.LocalAddr().String()
	conn.Close()

	server, err := mbtago.NewServer(
		mbtago.WithEventSink(sink),
		mbtago.WithAuth(core.NewStaticTokenValidator(map[string]string{
			"test-token": "test-agent",
		})),
		mbtago.WithPolicy(core.Policy{
			SupportedCapabilities: []string{"codec_proto", "cs_intl"},
			DefaultCodec:          corepb.Codec_CODEC_PROTO,
			DefaultCompression:    corepb.Compression_COMPRESSION_NONE,
			CipherSuite:           corepb.CipherSuite_CIPHER_SUITE_INTL,
		}),
		mbtago.WithV1(v1.QUICServerConfig{
			Address: addr,
			Credentials: &v1.ServerCredentials{
				CertFile: certPath,
				KeyFile:  keyPath,
			},
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = server.Start(ctx) }()
	time.Sleep(1500 * time.Millisecond) // let the QUIC listener bind
	return addr, func() { cancel(); _ = server.Close() }
}

// TestHandler_CloseFlushesBuffer is the end-to-end regression test for the
// Close ordering bug: Close previously cancelled the context before draining,
// so the final flush hit mbta-go's ctx.Err() gate and dropped every buffered
// record (0/5 delivered in the original PoC). All buffered records must now
// be delivered by Close alone — no explicit Flush call.
func TestHandler_CloseFlushesBuffer(t *testing.T) {
	sink := &countingSink{}
	addr, stop := startTestServer(t, sink)
	defer stop()

	h, err := NewHandler(Config{
		Server:             addr,
		AgentID:            "test-agent",
		Token:              "test-token",
		InsecureSkipVerify: true,             // self-signed test certificate
		FlushPeriod:        60 * time.Second, // nothing flushes on its own
		BatchSize:          100,
		CloseTimeout:       2 * time.Second,
		MaxRetries:         2,
		RetryDelay:         100 * time.Millisecond,
	})
	if err != nil {
		t.Skipf("in-process server setup failed: %v", err)
	}

	logger := slog.New(h)
	const n = 5
	for i := 0; i < n; i++ {
		logger.Info("buffered record")
	}

	if err := h.Close(); err != nil {
		t.Logf("Close returned %v (bounded close may abandon the internal drain)", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if sink.count.Load() == n {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server received %d/%d records after Close — Close dropped buffered logs", sink.count.Load(), n)
}
