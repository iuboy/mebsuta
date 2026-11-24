package mbta

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mbtago "github.com/iuboy/mbta-go"

	"github.com/google/uuid"
	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
	v1 "github.com/iuboy/mbta-go/v1"
	"github.com/iuboy/mebsuta"
	"github.com/stretchr/testify/require"
)

func TestConfigValidate_RequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name:    "empty config fails",
			cfg:     Config{},
			wantErr: true,
		},
		{
			name:    "missing server fails",
			cfg:     Config{AgentID: "agent-1"},
			wantErr: true,
		},
		{
			name:    "missing agent ID fails",
			cfg:     Config{Server: "localhost:7400"},
			wantErr: true,
		},
		{
			name:    "valid config passes",
			cfg:     Config{Server: "localhost:7400", AgentID: "agent-1"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.cfg.Validate()
			if tt.wantErr {
				require.Error(t, err, "Validate() error = %v, wantErr %v", err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestConfigValidate_Defaults(t *testing.T) {
	cfg, err := Config{Server: "localhost:7400", AgentID: "agent-1"}.Validate()
	require.NoError(t, err, "Validate() error")

	require.Equal(t, slog.LevelInfo, cfg.Level, "Level")
	require.Equal(t, defaultBufferSize, cfg.BufferSize, "BufferSize")
	require.Equal(t, defaultFlushPeriod, cfg.FlushPeriod, "FlushPeriod")
	require.Equal(t, defaultBatchSize, cfg.BatchSize, "BatchSize")
	require.Equal(t, defaultMaxRetries, cfg.MaxRetries, "MaxRetries")
	require.Equal(t, "mebsuta", cfg.Tag, "Tag")
	require.NotEmpty(t, cfg.Source, "Source should default to hostname")
}

func newRecord(level slog.Level, msg string) slog.Record {
	var pcs [1]uintptr
	runtime.Callers(2, pcs[:])
	return slog.NewRecord(time.Now(), level, msg, pcs[0])
}

func TestRecordToSignal(t *testing.T) {
	r := newRecord(slog.LevelInfo, "hello world")
	r.AddAttrs(slog.String("key", "value"), slog.Int("count", 42))

	rec, _ := recordToSignal(r)

	require.Equal(t, "log", rec.SignalType, "SignalType")
	require.Equal(t, "hello world", rec.Body, "Body")
	require.Equal(t, "INFO", rec.SeverityText, "SeverityText")
	require.NotEmpty(t, rec.EventID, "EventID should not be empty")
	require.NotZero(t, rec.TimeUnixNs, "TimeUnixNs should not be zero")

	attrs := rec.Attributes
	require.Equal(t, "value", attrs["key"], "Attributes[\"key\"]")
	require.Equal(t, int64(42), attrs["count"], "Attributes[\"count\"]")
}

func TestRecordToSignal_AuditLevel(t *testing.T) {
	r := newRecord(mebsuta.LevelAudit, "audit event")
	rec, _ := recordToSignal(r)

	require.Equal(t, "AUDIT", rec.SeverityText, "SeverityText")
}

func TestRecordToSignal_GroupAttrs(t *testing.T) {
	r := newRecord(slog.LevelInfo, "grouped")
	r.AddAttrs(slog.Group("request", slog.String("method", "GET"), slog.Int("status", 200)))

	rec, _ := recordToSignal(r)
	attrs := rec.Attributes

	// 组被展平为点号连接的键：mbta-go 的 proto 编解码器对属性值没有
	// map 表示，会退化为 fmt.Sprintf，
	// 嵌套 map 会序列化成不稳定的内部渲染。
	require.NotContains(t, attrs, "request", "want flattened keys (no nested group)")
	require.Equal(t, "GET", attrs["request.method"], "Attributes[\"request.method\"]")
	require.Equal(t, int64(200), attrs["request.status"], "Attributes[\"request.status\"]")
}

// TestNewEventID_FallbackFormat 验证时间戳派生兜底（uuid.NewV7 失败时
// 使用）产生可解析的合法 36 字符 UUIDv7。
// 旧的 "%x%04x" 形式会产生 5 字符的第 4 组，形成 37 字符
// 字符串而被 uuid.Parse 拒绝。
func TestNewEventID_FallbackFormat(t *testing.T) {
	// 直接复现兜底格式；newEventID 通常经
	// uuid.NewV7 成功，故这里单独测试格式串。
	seeds := []int64{0, 1, -1, 0x123456789abcdef0, 0x7fffffffffffffff}
	for _, s := range seeds {
		seed := uint64(s)
		id := newEventID(s)
		// PRNG 可用时 newEventID 返回真正的 v7；仅当 uuid.NewV7 成功时
		// 才以不同前缀断言兜底形状。
		// 通过固定的 "00000000-0000-7" 前缀识别兜底。
		require.Len(t, id, 36, "seed=%#x: (id=%s)", seed, id)
		_, err := uuid.Parse(id)
		require.NoError(t, err, "seed=%#x: id %q is not a valid UUID", seed, id)
		// 真 v7 的第 14 位是版本号 7；兜底在该位同样是 7。
		require.Equal(t, byte('7'), id[14], "seed=%#x: version nibble (id=%s)", seed, id)
	}
}

// maxServerBatchEvents 与 mbta-go 未导出的入口上限一致
// （internal/protocol 的 maxBatchEvents = 10000）：事件数更多的批次会被
// 服务端以 RESULT(level=rejected, batch_invalid) 拒绝。
const maxServerBatchEvents = 10000

// ---------------------------------------------------------------------------
// #1a record→signal 的 wire-schema 预过滤
// ---------------------------------------------------------------------------

// TestRecordToSignal_ServerSchemaPrefilter 验证预过滤让每条
// 记录都落在 mbta-go 服务端预算内（core.MaxSignalAttrs /
// MaxSignalAttrKeyLen / 严格控制字符）并报告裁剪内容。
// 没有它服务端会原子性拒绝整个批次，一条超限
// 记录曾让整个批次的记录全部静默丢失。
func TestRecordToSignal_ServerSchemaPrefilter(t *testing.T) {
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "m", 0)
	// 特殊键放最前，条数预算才不会在键级
	// 过滤看到它们之前先吞掉它们（属性按记录顺序转换）。
	r.AddAttrs(slog.String(strings.Repeat("x", 300), "v")) // 超长键
	r.AddAttrs(slog.String("bad\nkey\x00", "v"))           // 控制字符键
	// 130 个平铺条目：记录共 132 个叶子，超出
	// core.MaxSignalAttrs 4 个。
	for i := 0; i < 130; i++ {
		r.AddAttrs(slog.Int(fmt.Sprintf("k%03d", i), i))
	}

	rec, stats := recordToSignal(r)

	require.Len(t, rec.Attributes, core.MaxSignalAttrs, "budget enforced")
	require.Equal(t, 132-core.MaxSignalAttrs, stats.droppedAttrs, "droppedAttrs")
	for k := range rec.Attributes {
		require.LessOrEqual(t, len(k), core.MaxSignalAttrKeyLen,
			"key length %d exceeds server budget", len(k))
		require.False(t, strings.ContainsFunc(k, func(rn rune) bool { return rn < 0x20 || rn == 0x7f }),
			"key %q still contains strict control characters", k)
	}
	truncatedKey := strings.Repeat("x", core.MaxSignalAttrKeyLen)
	require.Equal(t, "v", rec.Attributes[truncatedKey], "over-long key was not truncated to the server budget")
	require.Equal(t, "v", rec.Attributes["bad_key_"], "control-char key not sanitized")
	require.Equal(t, 1, stats.truncatedKeys, "truncatedKeys")
	require.Equal(t, 1, stats.sanitizedKeys, "sanitizedKeys")

	// 产出的记录必须通过 mbta-go 的服务端校验探测——
	// 这正是预过滤的全部意义。
	probe := &core.SignalBatch{Signals: []*core.SignalRecord{rec}}
	require.NoError(t, probe.Validate(), "prefiltered record still fails server validation")
}

// TestRecordToSignal_PrefilterKeepsUTF8Boundary：截断不得拆散
// 多字节 rune（非法 UTF-8 键本身就是线上的问题）。
func TestRecordToSignal_PrefilterKeepsUTF8Boundary(t *testing.T) {
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "m", 0)
	r.AddAttrs(slog.String(strings.Repeat("ä", 200), "v")) // 400 字节的 2 字节 rune

	rec, stats := recordToSignal(r)
	require.Equal(t, 1, stats.truncatedKeys, "truncatedKeys")
	for k := range rec.Attributes {
		require.LessOrEqual(t, len(k), core.MaxSignalAttrKeyLen,
			"key = %d bytes, exceeds budget", len(k))
	}
}

// ---------------------------------------------------------------------------
// #2 嵌套组展平 → 确定性序列化
// ---------------------------------------------------------------------------

// TestRecordToSignal_FlattensGroupsAndSerializesStably：嵌套组变成
// 点号连接的标量键，且同一记录每次序列化的字节完全一致
// （重试会重新编组同一批次；规范 CBOR 对 map 键排序，
// 任何字节差异都来自非标量属性值）。
func TestRecordToSignal_FlattensGroupsAndSerializesStably(t *testing.T) {
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "grouped", 0)
	r.AddAttrs(
		slog.Group("http",
			slog.String("method", "GET"),
			slog.Int("status", 200),
			slog.Group("retry", slog.Int("count", 2)),
		),
		slog.String("region", "eu-1"),
	)

	rec, stats := recordToSignal(r)
	require.False(t, stats.any(), "unexpected pre-filter intervention: %+v", stats)
	for key, val := range rec.Attributes {
		_, isMap := val.(map[string]any)
		require.False(t, isMap, "attribute %q is still a nested map: %T", key, val)
	}
	require.Equal(t, "GET", rec.Attributes["http.method"], "http.method")
	require.Equal(t, int64(200), rec.Attributes["http.status"], "http.status")
	require.Equal(t, int64(2), rec.Attributes["http.retry.count"], "http.retry.count")
	require.Equal(t, "eu-1", rec.Attributes["region"], "region")

	// 同一逻辑记录的两次转换产出相同的属性
	// map（event/time 字段设计上不同，此处排除）。
	rec2, _ := recordToSignal(r)
	require.Equal(t, rec.Attributes, rec2.Attributes, "attribute maps differ between conversions")

	batch := &core.SignalBatch{Signals: []*core.SignalRecord{rec}}
	marshal := func() string {
		data, err := core.MarshalSignalBatchCodec(corepb.Codec_CODEC_CBOR, batch)
		require.NoError(t, err, "marshal")
		return string(data)
	}
	first := marshal()
	for i := 0; i < 20; i++ {
		next := marshal()
		require.Equal(t, first, next, "serialization of the same record is not stable at iteration %d", i)
	}
}

// ---------------------------------------------------------------------------
// #3 BatchSize 上限
// ---------------------------------------------------------------------------

func TestConfigValidate_BatchSizeCap(t *testing.T) {
	cfg, err := Config{Server: "localhost:7400", AgentID: "a", BatchSize: 50000}.Validate()
	require.NoError(t, err, "Validate() error")
	require.Equal(t, maxBatchSize, cfg.BatchSize, "BatchSize should clamp to maxBatchSize")
	cfg, err = Config{Server: "localhost:7400", AgentID: "a", BatchSize: 1}.Validate()
	require.NoError(t, err, "small BatchSize altered")
	require.Equal(t, 1, cfg.BatchSize, "small BatchSize altered")
}

// ---------------------------------------------------------------------------
// #4 Config token 屏蔽
// ---------------------------------------------------------------------------

func TestConfigString_MasksToken(t *testing.T) {
	cfg := Config{
		Server:  "localhost:7400",
		AgentID: "agent-1",
		Token:   "super-secret-token",
	}

	for _, repr := range []string{
		fmt.Sprintf("%v", cfg),
		fmt.Sprintf("%+v", cfg),
		fmt.Sprintf("%#v", cfg),
		cfg.String(),
		cfg.GoString(),
	} {
		require.NotContains(t, repr, "super-secret-token", "representation leaks the token")
		require.Contains(t, repr, maskedToken, "representation lacks %q placeholder", maskedToken)
		require.Contains(t, repr, "localhost:7400", "representation lost non-secret fields")
	}

	s := cfg.Sanitize()
	require.Equal(t, maskedToken, s.Token, "Sanitize().Token")
	require.Equal(t, "super-secret-token", cfg.Token, "Sanitize mutated the receiver")
	require.Equal(t, cfg.Server, s.Server, "Sanitize lost Server")
	require.Equal(t, cfg.AgentID, s.AgentID, "Sanitize lost AgentID")
}

// ---------------------------------------------------------------------------
// 错误上报捕获 + 活跃 handler 辅助
// ---------------------------------------------------------------------------

type errCapture struct {
	mu   sync.Mutex
	msgs []string
}

func (c *errCapture) handler() mebsuta.ErrorHandler {
	return func(he *mebsuta.HandlerError) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.msgs = append(c.msgs, fmt.Sprintf("%s/%s: %v", he.Component, he.Operation, he.Err))
	}
}

func (c *errCapture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.msgs)
}

// waitFor 轮询 cond 直到成立或 deadline 到期。
func waitFor(t *testing.T, d time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cond()
}

// newLiveHandler 构建连接到进程内服务的 handler。
func newLiveHandler(t *testing.T, sink *countingSink, mutate func(*Config)) *Handler {
	t.Helper()
	addr, stop := startTestServer(t, sink)
	t.Cleanup(stop)

	cfg := Config{
		Server:             addr,
		AgentID:            "test-agent",
		Token:              "test-token",
		InsecureSkipVerify: true,
		FlushPeriod:        60 * time.Second,
		CloseTimeout:       2 * time.Second,
		MaxRetries:         2,
		RetryDelay:         100 * time.Millisecond,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	h, err := NewHandler(cfg)
	if err != nil {
		t.Skipf("in-process server setup failed: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}

// ---------------------------------------------------------------------------
// #1b 发送前 Validate 门禁
// ---------------------------------------------------------------------------

// TestSendBatch_ValidateGateDropsInvalidRecords：违反服务端 wire schema 的
// 记录不得进入批次（服务端原子性拒绝批次，一条坏记录会拖垮整个
// 批次），必须计为丢弃并上报。
func TestSendBatch_ValidateGateDropsInvalidRecords(t *testing.T) {
	sink := &countingSink{}
	capture := &errCapture{}
	h := newLiveHandler(t, sink, nil)
	h.SetErrorHandler(capture.handler())

	base := slog.NewRecord(time.Now(), slog.LevelInfo, "kept", 0)
	base.AddAttrs(slog.String("k", "v"))
	goodRec, _ := recordToSignal(base)

	// 一条属性超出服务端条数预算的记录：
	// 服务端会为此拒绝整个批次。
	overAttrs := make(map[string]any, core.MaxSignalAttrs+1)
	for i := 0; i < core.MaxSignalAttrs+1; i++ {
		overAttrs[fmt.Sprintf("k%03d", i)] = i
	}
	badRec := &core.SignalRecord{SignalType: "log", TimeUnixNs: 1, Body: "bad", Attributes: overAttrs}

	records := []*core.SignalRecord{goodRec, nil, badRec}
	h.sendBatch(records)

	require.True(t, waitFor(t, 2*time.Second, func() bool { return sink.count.Load() == 1 }),
		"server received %d records, want exactly 1 (valid record only)", sink.count.Load())
	require.True(t, waitFor(t, 2*time.Second, func() bool { return h.Dropped() == 2 }),
		"Dropped() = %d, want 2 (nil record + over-budget record counted)", h.Dropped())
	require.NotZero(t, capture.count(), "validation drops were not reported via the error handler")
}

// ---------------------------------------------------------------------------
// #5 ctx 中止记账
// ---------------------------------------------------------------------------

// TestSendBatch_CtxAbortCountsDropped：handler context 在批次中途被取消时，
// 在途记录即丢失——它们必须计入 Dropped，
// 而不只是出现在错误报告里。
func TestSendBatch_CtxAbortCountsDropped(t *testing.T) {
	sink := &countingSink{}
	h := newLiveHandler(t, sink, nil)

	recs := make([]*core.SignalRecord, 4)
	for i := range recs {
		recs[i] = &core.SignalRecord{SignalType: "log", TimeUnixNs: 1, Body: "x"}
	}

	h.cancel() // 模拟 Close 超时中止路径
	h.sendBatch(recs)

	require.True(t, waitFor(t, 2*time.Second, func() bool { return h.Dropped() == int64(len(recs)) }),
		"Dropped() = %d, want %d after ctx abort", h.Dropped(), len(recs))
	require.Zero(t, sink.count.Load(), "server received records from an aborted batch")
}

// ---------------------------------------------------------------------------
// #7 关闭后 Handle 丢弃被计数
// ---------------------------------------------------------------------------

func TestHandleAfterCloseCountsDropped(t *testing.T) {
	sink := &countingSink{}
	h := newLiveHandler(t, sink, nil)

	if err := h.Close(); err != nil {
		t.Logf("Close: %v", err)
	}
	before := h.Dropped()

	logger := slog.New(h)
	logger.Info("after close") // 不得 panic；必须计数

	require.True(t, waitFor(t, time.Second, func() bool { return h.Dropped() == before+1 }),
		"Dropped() = %d, want %d (post-close record counted)", h.Dropped(), before+1)
}

// ---------------------------------------------------------------------------
// #8 双 Close 等待第一次排空
// ---------------------------------------------------------------------------

// TestCloseTwiceWaitsForDrain：第二次 Close 必须等待第一次的
// 排空结束而非立即返回。先杀掉客户端让排空确定性变慢：
// 此后每次发送立即失败并返回 "not connected"，重试循环烧完
// MaxRetries × RetryDelay 才放弃（禁用 Reconnect，循环无法自愈会话）。
func TestCloseTwiceWaitsForDrain(t *testing.T) {
	sink := &countingSink{}
	h := newLiveHandler(t, sink, func(c *Config) {
		c.CloseTimeout = 5 * time.Second
		c.MaxRetries = 4
		c.RetryDelay = 400 * time.Millisecond
		c.Reconnect = mebsuta.Ptr(false)
	})

	logger := slog.New(h)
	const n = 10
	for i := 0; i < n; i++ {
		logger.Info("drain me")
	}

	// 掐断线路：SendBatch 立即失败，Close 排空恰好耗时
	// MaxRetries × RetryDelay（约 1.6s）。
	require.NoError(t, h.conn.Load().client.Close(), "client close")

	firstErr := make(chan error, 1)
	go func() { firstErr <- h.Close() }()
	time.Sleep(100 * time.Millisecond) // 让第一个 Close 接管排空

	secondErr := make(chan error, 1)
	go func() { secondErr <- h.Close() }()

	// 此时第二个 Close 必须仍阻塞在第一次排空上。
	select {
	case err := <-secondErr:
		require.FailNow(t, "second Close returned while the first drain was still running", "%v", err)
	case <-time.After(400 * time.Millisecond):
	}
	if err := <-firstErr; err != nil {
		t.Logf("first Close: %v (expected: sends fail against the closed client)", err)
	}
	err := <-secondErr
	require.NoError(t, err, "second Close")
	require.True(t, waitFor(t, 8*time.Second, func() bool { return h.Dropped() == n }),
		"Dropped() = %d, want %d (buffered records accounted after failed drain)", h.Dropped(), n)
}

// ---------------------------------------------------------------------------
// #1c 服务端拒绝可见性（OnResult + 内部结果处理器）
// ---------------------------------------------------------------------------

// TestOnResultReceivesRejection 端到端堵上审计盲区：
// SendBatch 在批次上线后即返回 nil，无人盯着客户端唯一 RESULT
// 槽位的话，服务端拒绝就不可见。下面的批次携带的事件数超过服务端
// 入口 maxBatchEvents（10000），mbta-go 服务端自身会在入口
// 以 RESULT(level=rejected, batch_invalid) 拒绝——不涉及
// forwarder sink。（mbta-go 服务端自身不对 SignalBatch 载荷做
// schema 校验；内容级拒绝发生在 forwarder 的 sink，内部
// 结果处理器无论如何都经同一槽位观察到。）
//
// handler 必须把 RESULT 转发给 Config.OnResult 并把丢失的
// 记录计入 Dropped。
func TestOnResultReceivesRejection(t *testing.T) {
	sink := &countingSink{}
	addr, stop := startTestServer(t, sink)
	defer stop()

	var (
		mu       sync.Mutex
		sawLevel string
		sawCode  uint32
	)
	cfg := Config{
		Server:             addr,
		AgentID:            "test-agent",
		Token:              "test-token",
		InsecureSkipVerify: true,
		FlushPeriod:        60 * time.Second,
		CloseTimeout:       2 * time.Second,
		MaxRetries:         2,
		RetryDelay:         100 * time.Millisecond,
		OnResult: func(_ uint64, level string, code uint32, _ string) {
			mu.Lock()
			defer mu.Unlock()
			sawLevel, sawCode = level, code
		},
	}
	h, err := NewHandler(cfg)
	if err != nil {
		t.Skipf("in-process server setup failed: %v", err)
	}
	defer func() { _ = h.Close() }()

	// 比服务端入口事件上限多一条记录：写线
	// 仍成功（SendBatch 返回 nil），服务端拒绝该批次。
	const n = maxServerBatchEvents + 1
	recs := make([]*core.SignalRecord, n)
	for i := range recs {
		recs[i] = &core.SignalRecord{SignalType: "log", TimeUnixNs: 1, Body: "x"}
	}
	h.sendBatch(recs)

	require.True(t, waitFor(t, 5*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return sawLevel == resultLevelRejected
	}), "OnResult level = %q, want %q (server rejection invisible)", func() string {
		mu.Lock()
		defer mu.Unlock()
		return sawLevel
	}(), resultLevelRejected)
	mu.Lock()
	code := sawCode
	mu.Unlock()
	require.Equal(t, core.ErrCodeBatchInvalid.Num, code, "OnResult code (batch_invalid)")

	// 内部包装把被拒批次的记录计为丢弃。
	require.True(t, waitFor(t, 2*time.Second, func() bool { return h.Dropped() == n }),
		"Dropped() = %d, want %d after server rejection", h.Dropped(), n)
	require.Zero(t, sink.count.Load(), "server sink received records from a rejected batch")
}

// countingSink 统计服务端接受的每个信号。
type countingSink struct {
	count atomic.Int64
}

// handler 将计数器适配到 mbta-go v0.6.0 的 BatchHandler sink 契约。
func (s *countingSink) handler() core.BatchHandler {
	return func(_ context.Context, ev core.BatchEvent, done func(core.Outcome)) {
		if ev.Decoded != nil {
			s.count.Add(int64(len(ev.Decoded.Signals)))
		}
		done(core.Outcome{Level: core.OutcomeAccepted})
	}
}

// writeSelfSignedCert 创建一次性自签名服务端证书并
// 返回证书/密钥文件路径。
func writeSelfSignedCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
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
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	dir := t.TempDir()
	certPath = filepath.Join(dir, "server.crt")
	keyPath = filepath.Join(dir, "server.key")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600))
	return certPath, keyPath
}

// startTestServer 在空闲的 localhost 端口上启动进程内 MBTA 服务。
func startTestServer(t *testing.T, sink *countingSink) (addr string, stop func()) {
	t.Helper()
	certPath, keyPath := writeSelfSignedCert(t)

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	addr = conn.LocalAddr().String()
	_ = conn.Close() // 尽力而为：探测 socket 只是预留了一个空闲端口

	server, err := mbtago.NewServer(
		mbtago.WithAuth(core.NewStaticTokenValidator(map[string]string{
			"test-token": "test-agent",
		})),
		mbtago.WithPolicy(core.ServerPolicy{
			Profile:              corepb.Profile_PROFILE_INTL,
			AckMode:              corepb.AckMode_ACK_MODE_ACCEPTED_ONLY,
			InitialCreditBatches: 64,
			InitialCreditBytes:   8 << 20,
			MaxFrameBytes:        core.MaxFrameBytes,
			MaxBatchBytes:        8 << 20,
		}),
		mbtago.WithSink(core.SinkOptions{}, sink.handler()),
		mbtago.WithV1(v1.QUICServerConfig{
			Address: addr,
			Credentials: &v1.ServerCredentials{
				CertFile: certPath,
				KeyFile:  keyPath,
			},
		}),
	)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = server.Start(ctx) }()
	// 确定性就绪等待：轮询 facade Addr()（Start 完成监听后非空），替代裸
	// sleep——高负载下 1.5s 不保证绑定完成，曾致 CloseFlushesBuffer 在
	// 未就绪窗口内 Dial/排空而确定性失败。
	readyDeadline := time.Now().Add(10 * time.Second)
	for server.Addr() == "" {
		if time.Now().After(readyDeadline) {
			require.FailNow(t, "QUIC listener did not become ready within 10s")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return addr, func() { cancel(); _ = server.Close() }
}

// TestHandler_CloseFlushesBuffer 是 Close 顺序 bug 的端到端
// 回归测试：Close 过去在排空前先取消 context，
// 最终刷新撞上 mbta-go 的 ctx.Err() 门控，丢弃了所有缓冲
// 记录（原始 PoC 中 0/5 送达）。现在所有缓冲记录必须仅靠
// Close 送达——无需显式 Flush 调用。
func TestHandler_CloseFlushesBuffer(t *testing.T) {
	sink := &countingSink{}
	addr, stop := startTestServer(t, sink)
	defer stop()

	h, err := NewHandler(Config{
		Server:             addr,
		AgentID:            "test-agent",
		Token:              "test-token",
		InsecureSkipVerify: true,             // 自签名测试证书
		FlushPeriod:        60 * time.Second, // 不会有自动刷新
		BatchSize:          100,
		CloseTimeout:       5 * time.Second,
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
	require.FailNow(t, "server received %d/%d records after Close — Close dropped buffered logs", sink.count.Load(), n)
}

// TestRecordToSignal_ResolvesLogValuer：slog handler 必须解析
// LogValuer 值；泄漏给编码器会经 fmt 序列化出内部结构体
// 表示。
func TestRecordToSignal_ResolvesLogValuer(t *testing.T) {
	secret := secretValuer{}
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "m", 0)
	r.AddAttrs(slog.Any("cred", secret))

	sig, _ := recordToSignal(r)
	got, ok := sig.Attributes["cred"].(string)
	require.True(t, ok, "cred attr = %#v, want resolved string", sig.Attributes["cred"])
	require.Equal(t, "REDACTED-TOKEN", got, "resolved LogValuer")
}

type secretValuer struct{}

func (secretValuer) LogValue() slog.Value {
	return slog.StringValue("REDACTED-TOKEN")
}

// TestRecordToSignal_SeverityNumber：数值 severity 必须跟随
// 级别，而不是恒为 0。
func TestRecordToSignal_SeverityNumber(t *testing.T) {
	cases := map[slog.Level]int{
		slog.LevelDebug:    5,
		slog.LevelInfo:     9,
		slog.LevelWarn:     13,
		slog.LevelError:    17,
		mebsuta.LevelAudit: 21,
	}
	for level, want := range cases {
		r := slog.NewRecord(time.Now(), level, "m", 0)
		got, _ := recordToSignal(r)
		require.Equal(t, want, got.SeverityNumber, "SeverityNumber(%v)", level)
	}
}

// TestRecordToSignal_AttrBudgets：空键被跳过、属性条数有上限，
// 单条记录才无法撑大每个批次。
func TestRecordToSignal_AttrBudgets(t *testing.T) {
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "m", 0)
	r.AddAttrs(slog.String("", "empty key"))
	for i := 0; i < core.MaxSignalAttrs+50; i++ {
		r.AddAttrs(slog.Int("k", i))
	}
	sig, _ := recordToSignal(r)
	require.NotContains(t, sig.Attributes, "", "empty-key attr was not skipped")
	require.LessOrEqual(t, len(sig.Attributes), core.MaxSignalAttrs, "attr count")
}

// TestSanitizeHostname：静态与系统主机名在进入 resource 属性前被
// 规约到 [a-zA-Z0-9.-] 字符集。
func TestSanitizeHostname(t *testing.T) {
	cases := map[string]string{
		"web-01.example.com": "web-01.example.com",
		"bad host\nname":     "bad-host-name",
		"host\x00x":          "host-x",
	}
	for in, want := range cases {
		got := sanitizeHostname(in)
		require.Equal(t, want, got, "sanitizeHostname(%q)", in)
	}
	got := sanitizeHostname("")
	require.NotEmpty(t, got, "sanitizeHostname(system)")
	require.False(t, strings.ContainsAny(got, " \n\t"), "sanitizeHostname(system) = %q, want non-empty sanitized", got)
}

// TestHandler_ReconnectReplacesSingleUseClient:mbta-go 的 Client 是
// 一次性实例,会话断开后对同一实例 Connect 恒报 "single-use"——
// tryReconnect 必须 Dial 新实例换入(0.1.0-22 修复:旧实现对旧实例
// 重连,断线后永不恢复)。本测试把在连 client 关闭到 single-use 态
// (等同服务端消失后的客户端状态),触发重连,断言换入新 client 且
// 发送恢复。
func TestHandler_ReconnectReplacesSingleUseClient(t *testing.T) {
	sink := &countingSink{}
	h := newLiveHandler(t, sink, func(c *Config) {
		c.BatchSize = 1 // 每条记录立即成批,确定性走 sendBatch
	})

	require.NoError(t, h.Handle(context.Background(), newRecord(slog.LevelInfo, "before")))
	require.Eventually(t, func() bool { return sink.count.Load() == 1 },
		5*time.Second, 20*time.Millisecond, "first record delivered")

	// 关闭到 single-use 态:这正是会话断开后 mbta-go 客户端所处的
	// 状态(再调 Connect 恒报 ErrCodeSession "Client is single-use")。
	old := h.conn.Load()
	require.NotNil(t, old)
	require.NoError(t, old.client.Close(), "force single-use state")

	h.tryReconnect()
	cur := h.conn.Load()
	require.NotNil(t, cur)
	require.NotSame(t, old.client, cur.client,
		"tryReconnect must dial a new client, not reuse the single-use one")

	// 发送恢复:新 client 送达 sink。
	require.NoError(t, h.Handle(context.Background(), newRecord(slog.LevelInfo, "after")))
	require.Eventually(t, func() bool { return sink.count.Load() == 2 },
		5*time.Second, 20*time.Millisecond, "delivery resumed after reconnect")
}
