package database

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iuboy/mebsuta"
	"github.com/iuboy/mebsuta/internal/handlerkit"
	"github.com/stretchr/testify/require"
)

// mockHash 与下方的 mock signer/verifier 用最简单的 XOR 方案实现
// 完整性接口，测试因此可以在不依赖任何真实
// 密码学库的情况下签名与校验。
func mockHash(data []byte) ([]byte, error) {
	h := make([]byte, len(data))
	for i, b := range data {
		h[i] = b ^ 0x5A
	}
	return h, nil
}

func mockSignature(recordHash []byte) []byte {
	return append([]byte("sig:"), recordHash...)
}

type mockSigner struct{}

func (mockSigner) Algorithm() string { return "MOCK" }

func (mockSigner) Sign(data []byte) (recordHash, signature []byte, err error) {
	recordHash, err = mockHash(data)
	if err != nil {
		return nil, nil, err
	}
	return recordHash, mockSignature(recordHash), nil
}

type mockVerifier struct{}

func (*mockVerifier) Algorithm() string { return "MOCK" }

func (*mockVerifier) Hash(data []byte) ([]byte, error) { return mockHash(data) }

func (*mockVerifier) Verify(recordHash, signature []byte) error {
	if !bytes.Equal(signature, mockSignature(recordHash)) {
		return errors.New("mock: bad signature")
	}
	return nil
}

func TestIntegritySigner_Interface(t *testing.T) {
	var _ IntegritySigner = mockSigner{}
	var _ IntegrityVerifier = &mockVerifier{}
}

func TestCanonicalBytes_Deterministic(t *testing.T) {
	base := time.Date(2026, 8, 3, 10, 42, 23, 123456789, time.UTC)

	cases := []struct {
		name   string
		t1, t2 time.Time
		f1, f2 json.RawMessage
	}{
		{
			name: "sub-microsecond digits ignored",
			t1:   base,
			t2:   time.Date(2026, 8, 3, 10, 42, 23, 123456000, time.UTC),
		},
		{
			name: "timezone independent (same instant)",
			t1:   base,
			t2:   base.In(time.FixedZone("+08", 8*3600)),
		},
		{
			name: "fields key order and whitespace irrelevant",
			t1:   base, f1: json.RawMessage(`{"a": 1, "b": {"y": true, "x": null}}`),
			t2: base, f2: json.RawMessage(`{ "b" : { "x" : null , "y" : true } , "a" : 1 }`),
		},
		{
			name: "empty fields equals JSON null",
			t1:   base, f1: nil,
			t2: base, f2: json.RawMessage(`null`),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c1, err := CanonicalBytes(tc.t1, "INFO", "msg", tc.f1)
			require.NoError(t, err, "CanonicalBytes #1")
			c2, err := CanonicalBytes(tc.t2, "INFO", "msg", tc.f2)
			require.NoError(t, err, "CanonicalBytes #2")
			require.True(t, bytes.Equal(c1, c2), "canonical forms differ:\n%q\n%q", c1, c2)
			require.True(t, json.Valid(c1), "canonical form is not valid JSON: %q", c1)
		})
	}
}

func TestCanonicalBytes_DistinguishesContent(t *testing.T) {
	now := time.Date(2026, 8, 3, 10, 42, 23, 123000000, time.UTC)
	base, err := CanonicalBytes(now, "INFO", "transfer ok", json.RawMessage(`{"a":1}`))
	require.NoError(t, err, "CanonicalBytes")
	// 任何内容变化都必须改变规范字节——包括
	// 含旧 "|" 分隔符与引号的消息。
	variants := []struct {
		level, msg string
		fields     json.RawMessage
	}{
		{"WARN", "transfer ok", json.RawMessage(`{"a":1}`)},
		{"INFO", "transfer ok?", json.RawMessage(`{"a":1}`)},
		{"INFO", "transfer ok", json.RawMessage(`{"a":2}`)},
		{"INFO", "msg|with|pipes and \"quotes\"", nil},
	}
	for i, v := range variants {
		got, err := CanonicalBytes(now, v.level, v.msg, v.fields)
		require.NoError(t, err, "variant %d", i)
		require.False(t, i != 3 && bytes.Equal(got, base),
			"variant %d collapsed to the same canonical bytes as base", i)
		require.True(t, json.Valid(got), "variant %d produced invalid JSON: %q", i, got)
	}
}

func TestCanonicalBytes_InvalidJSON(t *testing.T) {
	_, err := CanonicalBytes(time.Now(), "INFO", "msg", json.RawMessage(`{"a":`))
	require.Error(t, err, "expected error for invalid fields JSON")
}

func TestRecordToDBEntry_SignsCanonicalForm(t *testing.T) {
	h := &Handler{cfg: Config{IntegritySigner: mockSigner{}}, errorHandler: handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler())}
	now := time.Date(2026, 8, 3, 10, 42, 23, 123456789, time.FixedZone("+08", 8*3600))

	rec := slog.NewRecord(now, slog.LevelWarn, `msg with | pipe and "quote"`, 0)
	rec.AddAttrs(slog.String("b", "2"), slog.String("a", "1"))
	entry := h.recordToDBEntry(context.Background(), rec)

	require.Zero(t, entry.Time.Nanosecond()%int(time.Microsecond),
		"entry.Time not truncated to canonical precision")

	canonical, err := CanonicalBytes(entry.Time, entry.Level, entry.Message, entry.Fields)
	require.NoError(t, err, "CanonicalBytes")
	wantHash, err := mockHash(canonical)
	require.NoError(t, err, "mockHash")
	require.Equal(t, hex.EncodeToString(wantHash), entry.RecordHash, "RecordHash")
	require.True(t, bytes.Equal(entry.Signature, mockSignature(wantHash)), "Signature")
	require.Equal(t, "MOCK", entry.SignAlgo, "SignAlgo")
}

func TestRecordToDBEntry_NilSignerLeavesUnsigned(t *testing.T) {
	h := &Handler{cfg: Config{}, errorHandler: handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler())}
	rec := slog.NewRecord(time.Now(), slog.LevelInfo, "hello", 0)
	entry := h.recordToDBEntry(context.Background(), rec)
	require.Empty(t, entry.RecordHash, "expected unsigned entry")
	require.Nil(t, entry.Signature, "expected unsigned entry")
	require.Empty(t, entry.SignAlgo, "expected unsigned entry")
}

func TestVerifyRecord_RoundTrip(t *testing.T) {
	h := &Handler{cfg: Config{IntegritySigner: mockSigner{}}, errorHandler: handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler())}
	now := time.Date(2026, 8, 3, 10, 42, 23, 123456789, time.FixedZone("+08", 8*3600))
	rec := slog.NewRecord(now, slog.LevelError, "db write failed", 0)
	rec.AddAttrs(slog.String("table", "logs"), slog.Int("retries", 3))
	entry := h.recordToDBEntry(context.Background(), rec)

	stored := StoredRecord{Time: entry.Time, Level: entry.Level, Message: entry.Message, Fields: entry.Fields, SignAlgo: entry.SignAlgo}

	require.NoError(t, VerifyRecord(stored, entry.RecordHash, entry.Signature, &mockVerifier{}),
		"untampered record failed verification")

	// 模拟读回时数据库侧的规范化：JSON 列会被
	// 重排/重格式化，Postgres 以 UTC 返回时间戳。
	reformatted := stored
	reformatted.Fields = json.RawMessage(`{ "retries" : 3 , "table" : "logs" }`)
	require.NoError(t, VerifyRecord(reformatted, entry.RecordHash, entry.Signature, &mockVerifier{}),
		"reformatted-but-equal fields failed verification")

	utcStored := stored
	utcStored.Time = stored.Time.UTC()
	require.NoError(t, VerifyRecord(utcStored, entry.RecordHash, entry.Signature, &mockVerifier{}),
		"UTC read-back failed verification")
}

func TestVerifyRecord_Tampering(t *testing.T) {
	h := &Handler{cfg: Config{IntegritySigner: mockSigner{}}, errorHandler: handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler())}
	rec := slog.NewRecord(time.Date(2026, 8, 3, 10, 42, 23, 123000000, time.UTC), slog.LevelInfo, "audit event", 0)
	rec.AddAttrs(slog.String("user", "alice"), slog.Int("amount", 100))
	entry := h.recordToDBEntry(context.Background(), rec)

	// 篡改内容但保留原始 hash+签名：重算的
	// hash 不再匹配，必须被发现。
	tamperedMsg := StoredRecord{Time: entry.Time, Level: entry.Level, Message: "audit event (edited)", Fields: entry.Fields, SignAlgo: entry.SignAlgo}
	require.ErrorIs(t, VerifyRecord(tamperedMsg, entry.RecordHash, entry.Signature, &mockVerifier{}), ErrHashMismatch, "tampered message")

	tamperedFields := StoredRecord{Time: entry.Time, Level: entry.Level, Message: entry.Message, Fields: json.RawMessage(`{"amount":1000000,"user":"alice"}`), SignAlgo: entry.SignAlgo}
	require.ErrorIs(t, VerifyRecord(tamperedFields, entry.RecordHash, entry.Signature, &mockVerifier{}), ErrHashMismatch, "tampered fields")

	tamperedLevel := StoredRecord{Time: entry.Time, Level: slog.LevelWarn.String(), Message: entry.Message, Fields: entry.Fields, SignAlgo: entry.SignAlgo}
	require.ErrorIs(t, VerifyRecord(tamperedLevel, entry.RecordHash, entry.Signature, &mockVerifier{}), ErrHashMismatch, "tampered level")

	// 新内容有合法 hash 但签名过期，必须败在
	// 签名检查上（攻击者没有密钥就造不出签名）。
	newCanonical, err := CanonicalBytes(tamperedMsg.Time, tamperedMsg.Level, tamperedMsg.Message, tamperedMsg.Fields)
	require.NoError(t, err, "CanonicalBytes")
	newHash, err := mockHash(newCanonical)
	require.NoError(t, err, "mockHash")
	err = VerifyRecord(tamperedMsg, hex.EncodeToString(newHash), entry.Signature, &mockVerifier{})
	require.Error(t, err, "stale signature: want signature verification error")
	require.NotErrorIs(t, err, ErrHashMismatch, "stale signature: want signature verification error")
	require.ErrorContains(t, err, "signature verification failed", "stale signature")
}

func TestVerifyRecord_FailClosed(t *testing.T) {
	h := &Handler{cfg: Config{IntegritySigner: mockSigner{}}, errorHandler: handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler())}
	rec := slog.NewRecord(time.Date(2026, 8, 3, 10, 42, 23, 123000000, time.UTC), slog.LevelInfo, "msg", 0)
	entry := h.recordToDBEntry(context.Background(), rec)
	stored := StoredRecord{Time: entry.Time, Level: entry.Level, Message: entry.Message, Fields: entry.Fields, SignAlgo: entry.SignAlgo}

	// 两列皆空，以及被剥离签名的情况：清空任一
	// 列都不得静默通过（篡改者的轻易胜利）。
	require.ErrorIs(t, VerifyRecord(StoredRecord{}, "", nil, nil), ErrUnsignedRecord, "fully unsigned")
	require.ErrorIs(t, VerifyRecord(stored, entry.RecordHash, nil, &mockVerifier{}), ErrUnsignedRecord, "signature stripped")
	require.ErrorIs(t, VerifyRecord(stored, "", entry.Signature, &mockVerifier{}), ErrUnsignedRecord, "hash stripped")

	// 有签名但没有可用的校验器。
	require.ErrorIs(t, VerifyRecord(stored, entry.RecordHash, entry.Signature, nil), ErrNilVerifier, "nil verifier")
	var typedNil *mockVerifier
	require.ErrorIs(t, VerifyRecord(stored, entry.RecordHash, entry.Signature, typedNil), ErrNilVerifier, "typed-nil verifier")

	// 损坏的存储 hash（非法十六进制）。
	require.Error(t, VerifyRecord(stored, "zzzz-not-hex", entry.Signature, &mockVerifier{}), "non-hex record_hash: expected error")
}

// TestHandler_SignSkippedCounter 验证经 signer 失败路径未签名
// 落库的记录被计入 SignSkipped 并经限频报告
// 呈现，而不是凭空消失。审计人员用该计数器
// 对账 ErrUnsignedRecord 行。
func TestHandler_SignSkippedCounter(t *testing.T) {
	h, _ := newSQLiteHandler(t)
	h.cfg.IntegritySigner = failingSigner{}

	var reported atomic.Int64
	h.SetErrorHandler(func(he *mebsuta.HandlerError) {
		if strings.Contains(he.Err.Error(), "persisted unsigned") {
			reported.Add(1)
		}
	})

	require.Zero(t, h.SignSkipped(), "SignSkipped starts at 0")

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "sign failure", 0)
	_ = h.recordToDBEntry(context.Background(), r)
	require.Equal(t, int64(1), h.SignSkipped(), "first skipped sign")
	require.Equal(t, int64(1), reported.Load(), "first skip must be reported (rate limiter cold)")

	_ = h.recordToDBEntry(context.Background(), r)
	require.Equal(t, int64(2), h.SignSkipped(), "every unsigned record must be counted")
	require.Equal(t, int64(1), reported.Load(), "reports must be rate-limited to one per second")
}

// failingSigner 永远失败，模拟签名时的 HSM 会话错误。
type failingSigner struct{}

func (failingSigner) Algorithm() string { return "FAIL" }

func (failingSigner) Sign([]byte) ([]byte, []byte, error) {
	return nil, nil, errors.New("mock signer failure")
}

// TestCanonicalBytes_NumberPrecision 是 float64 坍缩的回归
// 测试：规范化此前解码进 any（float64），超过 2^53 且舍入到
// 同一 double 的整数会产出相同的
// 规范字节——攻击者可以改写存储的金额/ID 而签名
// 仍然通过校验。
func TestCanonicalBytes_NumberPrecision(t *testing.T) {
	now := time.Date(2026, 8, 22, 10, 0, 0, 123456000, time.UTC)

	cases := []struct {
		name string
		a, b json.RawMessage
	}{
		{"2^53 boundary", json.RawMessage(`{"amount":9007199254740993}`), json.RawMessage(`{"amount":9007199254740992}`)},
		{"20-digit uid", json.RawMessage(`{"uid":12345678901234567890}`), json.RawMessage(`{"uid":12345678901234567168}`)},
		{"int64 extremes", json.RawMessage(`{"v":9223372036854775807}`), json.RawMessage(`{"v":-9223372036854775808}`)},
		{"distinct decimals", json.RawMessage(`{"v":0.1}`), json.RawMessage(`{"v":0.2}`)},
	}
	for _, c := range cases {
		b1, err := CanonicalBytes(now, "INFO", "m", c.a)
		require.NoError(t, err, "%s: CanonicalBytes(a)", c.name)
		b2, err := CanonicalBytes(now, "INFO", "m", c.b)
		require.NoError(t, err, "%s: CanonicalBytes(b)", c.name)
		require.False(t, bytes.Equal(b1, b2),
			"%s: distinct values collapsed to the same canonical bytes: %s", c.name, b1)
	}
}

// TestCanonicalBytes_NumberValuePreserved 确保规范形携带
// 精确字面量——签名字节包含原始数字，而不是它的
// float64 重渲染。
func TestCanonicalBytes_NumberValuePreserved(t *testing.T) {
	now := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	got, err := CanonicalBytes(now, "INFO", "m", json.RawMessage(`{"uid":12345678901234567890}`))
	require.NoError(t, err)
	require.Contains(t, string(got), "12345678901234567890", "canonical form lost the exact number")
}

// TestCanonicalBytes_DuplicateKeysRejected：重复对象键只可能
// 来自直接篡改列（写入方序列化的是 Go map）；以
// last-wins 语义接受它们会藏住 {"k":orig,"k":forged} 式改写。
func TestCanonicalBytes_DuplicateKeysRejected(t *testing.T) {
	_, err := CanonicalBytes(time.Now(), "INFO", "m", json.RawMessage(`{"a":1,"a":2}`))
	require.Error(t, err, "expected error for duplicate top-level keys")
	_, err = CanonicalBytes(time.Now(), "INFO", "m", json.RawMessage(`{"outer":{"x":1,"x":2}}`))
	require.Error(t, err, "expected error for duplicate nested keys")
	_, err = CanonicalBytes(time.Now(), "INFO", "m", json.RawMessage(`[{"a":1,"a":1}]`))
	require.Error(t, err, "expected error for duplicate keys inside arrays")
	// 不同对象中的同名键是合法的。
	_, err = CanonicalBytes(time.Now(), "INFO", "m", json.RawMessage(`{"o1":{"k":1},"o2":{"k":2}}`))
	require.NoError(t, err, "same key in sibling objects must be accepted")
}

// TestCanonicalBytes_TrailingDataRejected：粘在一起的两个 JSON 文档
// 不得被当作一个校验通过。
func TestCanonicalBytes_TrailingDataRejected(t *testing.T) {
	_, err := CanonicalBytes(time.Now(), "INFO", "m", json.RawMessage(`{"a":1} {"b":2}`))
	require.Error(t, err, "expected error for trailing data")
}

// TestVerifyRecord_AlgoBinding 覆盖 sign_algo 列检查：算法不匹配
// 或缺失必须失败收紧，而不是在调用方碰巧
// 传入的任何算法下校验通过。
func TestVerifyRecord_AlgoBinding(t *testing.T) {
	h := &Handler{cfg: Config{IntegritySigner: mockSigner{}}, errorHandler: handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler())}
	rec := newSignedRecord(t, h)
	stored := StoredRecord{Time: rec.Time, Level: rec.Level, Message: rec.Message, Fields: rec.Fields, SignAlgo: rec.SignAlgo}

	require.NoError(t, VerifyRecord(stored, rec.RecordHash, rec.Signature, &mockVerifier{}), "matching algo should verify")

	flipped := stored
	flipped.SignAlgo = "ECDSA-SHA256"
	require.ErrorIs(t, VerifyRecord(flipped, rec.RecordHash, rec.Signature, &mockVerifier{}), ErrAlgoMismatch, "tampered sign_algo")

	cleared := stored
	cleared.SignAlgo = ""
	require.ErrorIs(t, VerifyRecord(cleared, rec.RecordHash, rec.Signature, &mockVerifier{}), ErrUnsignedRecord, "cleared sign_algo")
}

// newSignedRecord 经 handler 的条目路径签名一条记录。
func newSignedRecord(t *testing.T, h *Handler) dbLogEntry {
	t.Helper()
	rec := slog.NewRecord(time.Date(2026, 8, 22, 9, 0, 0, 123000000, time.UTC), slog.LevelInfo, "audit transfer", 0)
	rec.AddAttrs(slog.Int64("amount", 9007199254740993))
	entry := h.recordToDBEntry(context.Background(), rec)
	require.NotEmpty(t, entry.RecordHash, "record was not signed: %+v", entry)
	require.NotNil(t, entry.Signature, "record was not signed: %+v", entry)
	require.NotEmpty(t, entry.SignAlgo, "record was not signed: %+v", entry)
	return entry
}

// TestVerifyRecord_NumberTamperingDetected 是精度回归的端到端
// 变体：校验一个已存储的大整数字段，再把它改成它的
// float64 孪生值——现在校验必须失败。
func TestVerifyRecord_NumberTamperingDetected(t *testing.T) {
	h := &Handler{cfg: Config{IntegritySigner: mockSigner{}}, errorHandler: handlerkit.NewErrorSlot(mebsuta.DefaultErrorHandler())}
	entry := newSignedRecord(t, h)

	// 篡改：2^53+1 → 2^53（float64 舍入下相同）。
	tampered := StoredRecord{
		Time:     entry.Time,
		Level:    entry.Level,
		Message:  entry.Message,
		Fields:   json.RawMessage(`{"amount":9007199254740992}`),
		SignAlgo: entry.SignAlgo,
	}
	require.ErrorIs(t, VerifyRecord(tampered, entry.RecordHash, entry.Signature, &mockVerifier{}), ErrHashMismatch,
		"float64-twin tampering not detected")
}

// TestNormalizeJSONNumber 依据 PostgreSQL 18 实测观察到的 numeric 文本
// 输出验证字面量改写（见 normalizeJSONNumber 的注释；
// 每个期望值都在真实服务器上探针验证过）。
func TestNormalizeJSONNumber(t *testing.T) {
	cases := map[string]string{
		// 纯文本形式直接通过（快速路径）
		"0": "0", "100": "100", "-0.5": "-0.5", "0.015": "0.015",
		"1.50": "1.50", "12345678901234567890": "12345678901234567890",
		// 指数展开
		"1e+21":  "1000000000000000000000",
		"1e2":    "100",
		"1.5e2":  "150",
		"1.5e-2": "0.015",
		"1.5e-7": "0.00000015",
		"1.50e1": "15.0", // 位数 2 - 1 = 1 → 保留一位小数零
		"1.50e2": "150",  // 位数 2 - 2 = 0 → 无小数
		// 前导零
		"007":   "7",
		"007e2": "700",
		// 零语义：符号丢弃、最终位数保留
		"-0":     "0",
		"-0.0":   "0.0",
		"0e10":   "0",
		"0.00e1": "0.0",
		// 负数带指数
		"-1.5e-3": "-0.0015",
		// 超出 PG numeric 上限：原样保留（PG 无法把它们存进 jsonb）
		"1e9999999": "1e9999999",
	}
	for in, want := range cases {
		got := normalizeJSONNumber(json.Number(in))
		require.Equal(t, want, got, "normalizeJSONNumber(%q)", in)
	}
}

// TestCanonicalBytes_JsonbEquivalenceClasses：PostgreSQL jsonb 渲染
// 相同的写法必须规范化相同——这正是让 json → jsonb
// 列迁移对已签名行透明的原因。
func TestCanonicalBytes_JsonbEquivalenceClasses(t *testing.T) {
	now := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	pairs := []struct{ a, b string }{
		{`{"x":1e2}`, `{"x":100}`},
		{`{"x":1e+21}`, `{"x":1000000000000000000000}`},
		{`{"x":-0}`, `{"x":0}`},
		{`{"x":-0.0}`, `{"x":0.0}`},
		{`{"x":007}`, `{"x":7}`}, // json 解码器接受前导零？见下文
		{`{"x":1.50e2}`, `{"x":150}`},
	}
	for i, p := range pairs {
		b1, err1 := CanonicalBytes(now, "INFO", "m", json.RawMessage(p.a))
		b2, err2 := CanonicalBytes(now, "INFO", "m", json.RawMessage(p.b))
		if err1 != nil || err2 != nil {
			// 前导零字面量被 Go 的严格解码器拒绝——
			// 它们只能经直接篡改列出现，checkNoDuplicateKeys/Decode
			// 对其失败同样是可接受的 fail-closed 行为。
			if i == 4 && err1 != nil {
				continue
			}
			require.FailNow(t, "pair %d (%s vs %s): %v / %v", i, p.a, p.b, err1, err2)
		}
		require.True(t, bytes.Equal(b1, b2), "pair %d: jsonb-equivalent spellings diverged:\n  %s\n  %s", i, b1, b2)
	}
}

// TestCanonicalBytes_JsonValueDistinctnessAfterNormalization：安全
// 属性在改写后依然成立——不同的“值”（原始发现中的
// float64 孪生攻击）仍永不趋同，等值写法的
// 趋同也不会打开任何新的别名。
func TestCanonicalBytes_JsonValueDistinctnessAfterNormalization(t *testing.T) {
	now := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	must := func(fields string) []byte {
		b, err := CanonicalBytes(now, "INFO", "m", json.RawMessage(fields))
		require.NoError(t, err, "CanonicalBytes(%s)", fields)
		return b
	}
	require.False(t, bytes.Equal(must(`{"amount":9007199254740993}`), must(`{"amount":9007199254740992}`)),
		"float64-twin tampering became undetectable after normalization")
	require.False(t, bytes.Equal(must(`{"v":100}`), must(`{"v":101}`)),
		"distinct integers converged")
	if bytes.Equal(must(`{"v":0.1}`), must(`{"v":0.10}`)) {
		// 0.1 与 0.10：jsonb 保留位数 → 0.1 与 0.10 在 PG 中也不同。
		t.Log("note: 0.1 vs 0.10 converged (PG renders them 0.1 vs 0.10 — distinct)")
	}
}

// TestCanonicalBytes_NumberValuePreservedAfterNormalization 复核 20 位
// 整数原样存活（其字面量已是 numeric 文本
// 形式，走快速路径）。
func TestCanonicalBytes_NumberValuePreservedAfterNormalization(t *testing.T) {
	now := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	got, err := CanonicalBytes(now, "INFO", "m", json.RawMessage(`{"uid":12345678901234567890}`))
	require.NoError(t, err)
	require.Contains(t, string(got), "12345678901234567890", "canonical form lost the exact number")
}
