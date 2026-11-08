package mbta

import (
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"

	"github.com/iuboy/mebsuta"
)

// maxServerBatchEvents mirrors mbta-go's unexported ingress cap
// (internal/protocol maxBatchEvents = 10000): batches with more events are
// rejected server-side with RESULT(level=rejected, batch_invalid).
const maxServerBatchEvents = 10000

// ---------------------------------------------------------------------------
// #1a record→signal wire-schema pre-filter
// ---------------------------------------------------------------------------

// TestRecordToSignal_ServerSchemaPrefilter verifies the pre-filter brings every
// record inside mbta-go's server-side budgets (core.MaxSignalAttrs /
// MaxSignalAttrKeyLen / strict control characters) and reports what it cut.
// Without it the server rejects the WHOLE batch atomically, so one oversized
// record used to silently lose every record in the batch.
func TestRecordToSignal_ServerSchemaPrefilter(t *testing.T) {
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "m", 0)
	// Special keys first so the entry-count budget cannot swallow them before
	// the key-level filters see them (attrs are converted in record order).
	r.AddAttrs(slog.String(strings.Repeat("x", 300), "v")) // over-long key
	r.AddAttrs(slog.String("bad\nkey\x00", "v"))           // control-char key
	// 130 flat entries: together the record carries 132 leaves, 4 beyond
	// core.MaxSignalAttrs.
	for i := 0; i < 130; i++ {
		r.AddAttrs(slog.Int(fmt.Sprintf("k%03d", i), i))
	}

	rec, stats := recordToSignal(r)

	if len(rec.Attributes) != core.MaxSignalAttrs {
		t.Fatalf("attr count = %d, want exactly %d (budget enforced)", len(rec.Attributes), core.MaxSignalAttrs)
	}
	if want := 132 - core.MaxSignalAttrs; stats.droppedAttrs != want {
		t.Errorf("droppedAttrs = %d, want %d", stats.droppedAttrs, want)
	}
	for k := range rec.Attributes {
		if len(k) > core.MaxSignalAttrKeyLen {
			t.Errorf("key length %d exceeds server budget %d", len(k), core.MaxSignalAttrKeyLen)
		}
		if strings.ContainsFunc(k, func(rn rune) bool { return rn < 0x20 || rn == 0x7f }) {
			t.Errorf("key %q still contains strict control characters", k)
		}
	}
	if got, ok := rec.Attributes[strings.Repeat("x", core.MaxSignalAttrKeyLen)]; !ok || got != "v" {
		t.Error("over-long key was not truncated to the server budget")
	}
	if got, ok := rec.Attributes["bad_key_"]; !ok || got != "v" {
		t.Errorf("control-char key not sanitized, got %q (ok=%v)", got, ok)
	}
	if stats.truncatedKeys != 1 || stats.sanitizedKeys != 1 {
		t.Errorf("stats = %+v, want 1 truncated + 1 sanitized", stats)
	}

	// The produced record must pass mbta-go's server-side validation probe —
	// that is the whole point of the pre-filter.
	probe := &core.SignalBatch{Signals: []*core.SignalRecord{rec}}
	if err := probe.Validate(); err != nil {
		t.Fatalf("prefiltered record still fails server validation: %v", err)
	}
}

// TestRecordToSignal_PrefilterKeepsUTF8Boundary: truncation must not split a
// multi-byte rune (invalid UTF-8 keys would be its own wire problem).
func TestRecordToSignal_PrefilterKeepsUTF8Boundary(t *testing.T) {
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "m", 0)
	r.AddAttrs(slog.String(strings.Repeat("ä", 200), "v")) // 400 bytes of 2-byte runes

	rec, stats := recordToSignal(r)
	if stats.truncatedKeys != 1 {
		t.Fatalf("truncatedKeys = %d, want 1", stats.truncatedKeys)
	}
	for k := range rec.Attributes {
		if len(k) > core.MaxSignalAttrKeyLen {
			t.Fatalf("key = %d bytes, exceeds budget", len(k))
		}
	}
}

// ---------------------------------------------------------------------------
// #2 nested-group flattening → deterministic serialization
// ---------------------------------------------------------------------------

// TestRecordToSignal_FlattensGroupsAndSerializesStably: nested groups become
// dot-joined scalar keys, and the same record serializes to identical bytes on
// every attempt (retries re-marshal the same batch; canonical CBOR sorts map
// keys, so any byte difference would come from non-scalar attribute values).
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
	if stats.any() {
		t.Fatalf("unexpected pre-filter intervention: %+v", stats)
	}
	for key, val := range rec.Attributes {
		if _, ok := val.(map[string]any); ok {
			t.Errorf("attribute %q is still a nested map: %T", key, val)
		}
	}
	if rec.Attributes["http.method"] != "GET" ||
		rec.Attributes["http.status"] != int64(200) ||
		rec.Attributes["http.retry.count"] != int64(2) ||
		rec.Attributes["region"] != "eu-1" {
		t.Fatalf("flattened keys wrong: %#v", rec.Attributes)
	}

	// Two conversions of the same logical record yield identical attribute
	// maps (event/time fields differ by design and are excluded here).
	rec2, _ := recordToSignal(r)
	if !reflect.DeepEqual(rec.Attributes, rec2.Attributes) {
		t.Fatalf("attribute maps differ between conversions:\n%#v\n%#v", rec.Attributes, rec2.Attributes)
	}

	batch := &core.SignalBatch{Signals: []*core.SignalRecord{rec}}
	marshal := func() string {
		data, err := core.MarshalSignalBatchCodec(corepb.Codec_CODEC_CBOR, batch)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return string(data)
	}
	first := marshal()
	for i := 0; i < 20; i++ {
		if next := marshal(); next != first {
			t.Fatalf("serialization of the same record is not stable at iteration %d", i)
		}
	}
}

// ---------------------------------------------------------------------------
// #3 BatchSize cap
// ---------------------------------------------------------------------------

func TestConfigValidate_BatchSizeCap(t *testing.T) {
	cfg, err := Config{Server: "localhost:7400", AgentID: "a", BatchSize: 50000}.Validate()
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if cfg.BatchSize != maxBatchSize {
		t.Errorf("BatchSize = %d, want clamped to %d", cfg.BatchSize, maxBatchSize)
	}
	cfg, err = Config{Server: "localhost:7400", AgentID: "a", BatchSize: 1}.Validate()
	if err != nil || cfg.BatchSize != 1 {
		t.Errorf("small BatchSize altered: %d (err=%v)", cfg.BatchSize, err)
	}
}

// ---------------------------------------------------------------------------
// #4 Config token masking
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
		if strings.Contains(repr, "super-secret-token") {
			t.Errorf("representation leaks the token: %s", repr)
		}
		if !strings.Contains(repr, maskedToken) {
			t.Errorf("representation lacks %q placeholder: %s", maskedToken, repr)
		}
		if !strings.Contains(repr, "localhost:7400") {
			t.Errorf("representation lost non-secret fields: %s", repr)
		}
	}

	s := cfg.Sanitize()
	if s.Token != maskedToken {
		t.Errorf("Sanitize().Token = %q, want %q", s.Token, maskedToken)
	}
	if cfg.Token != "super-secret-token" {
		t.Errorf("Sanitize mutated the receiver: Token = %q", cfg.Token)
	}
	if s.Server != cfg.Server || s.AgentID != cfg.AgentID {
		t.Errorf("Sanitize lost fields: %+v", s)
	}
}

// ---------------------------------------------------------------------------
// Error-report capture + live-handler helpers
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

// waitFor polls cond until it holds or the deadline expires.
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

// newLiveHandler builds a handler connected to an in-process server.
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
// #1b pre-send Validate gate
// ---------------------------------------------------------------------------

// TestSendBatch_ValidateGateDropsInvalidRecords: records that violate the
// server's wire schema must not enter the batch (the server rejects batches
// atomically, so one bad record would take the whole batch down), must be
// counted as dropped and reported.
func TestSendBatch_ValidateGateDropsInvalidRecords(t *testing.T) {
	sink := &countingSink{}
	capture := &errCapture{}
	h := newLiveHandler(t, sink, nil)
	h.SetErrorHandler(capture.handler())

	base := slog.NewRecord(time.Now(), slog.LevelInfo, "kept", 0)
	base.AddAttrs(slog.String("k", "v"))
	goodRec, _ := recordToSignal(base)

	// One record with attributes beyond the server entry budget: the server
	// would reject the whole batch over it.
	overAttrs := make(map[string]any, core.MaxSignalAttrs+1)
	for i := 0; i < core.MaxSignalAttrs+1; i++ {
		overAttrs[fmt.Sprintf("k%03d", i)] = i
	}
	badRec := &core.SignalRecord{SignalType: "log", TimeUnixNs: 1, Body: "bad", Attributes: overAttrs}

	records := []*core.SignalRecord{goodRec, nil, badRec}
	h.sendBatch(records)

	if !waitFor(t, 2*time.Second, func() bool { return sink.count.Load() == 1 }) {
		t.Fatalf("server received %d records, want exactly 1 (valid record only)", sink.count.Load())
	}
	if !waitFor(t, 2*time.Second, func() bool { return h.Dropped() == 2 }) {
		t.Errorf("Dropped() = %d, want 2 (nil record + over-budget record counted)", h.Dropped())
	}
	if capture.count() == 0 {
		t.Error("validation drops were not reported via the error handler")
	}
}

// ---------------------------------------------------------------------------
// #5 ctx-abort accounting
// ---------------------------------------------------------------------------

// TestSendBatch_CtxAbortCountsDropped: when the handler context is cancelled
// mid-batch, the in-flight records are lost — they must land in Dropped, not
// just in an error report.
func TestSendBatch_CtxAbortCountsDropped(t *testing.T) {
	sink := &countingSink{}
	h := newLiveHandler(t, sink, nil)

	recs := make([]*core.SignalRecord, 4)
	for i := range recs {
		recs[i] = &core.SignalRecord{SignalType: "log", TimeUnixNs: 1, Body: "x"}
	}

	h.cancel() // simulate the Close-timeout abort path
	h.sendBatch(recs)

	if !waitFor(t, 2*time.Second, func() bool { return h.Dropped() == int64(len(recs)) }) {
		t.Fatalf("Dropped() = %d, want %d after ctx abort", h.Dropped(), len(recs))
	}
	if sink.count.Load() != 0 {
		t.Errorf("server received %d records from an aborted batch", sink.count.Load())
	}
}

// ---------------------------------------------------------------------------
// #7 post-close Handle drops are counted
// ---------------------------------------------------------------------------

func TestHandleAfterCloseCountsDropped(t *testing.T) {
	sink := &countingSink{}
	h := newLiveHandler(t, sink, nil)

	if err := h.Close(); err != nil {
		t.Logf("Close: %v", err)
	}
	before := h.Dropped()

	logger := slog.New(h)
	logger.Info("after close") // must not panic; must be counted

	if !waitFor(t, time.Second, func() bool { return h.Dropped() == before+1 }) {
		t.Errorf("Dropped() = %d, want %d (post-close record counted)", h.Dropped(), before+1)
	}
}

// ---------------------------------------------------------------------------
// #8 double Close waits for the first drain
// ---------------------------------------------------------------------------

// TestCloseTwiceWaitsForDrain: the second Close must wait for the first one's
// drain instead of returning immediately. The drain is made deterministically
// slow by killing the client first: every send attempt then fails instantly
// with "not connected" and the retry loop burns MaxRetries × RetryDelay before
// giving up (Reconnect is disabled so the loop cannot heal the session).
func TestCloseTwiceWaitsForDrain(t *testing.T) {
	sink := &countingSink{}
	h := newLiveHandler(t, sink, func(c *Config) {
		c.CloseTimeout = 5 * time.Second
		c.MaxRetries = 4
		c.RetryDelay = 400 * time.Millisecond
		c.Reconnect = mebsuta.BoolPtr(false)
	})

	logger := slog.New(h)
	const n = 10
	for i := 0; i < n; i++ {
		logger.Info("drain me")
	}

	// Kill the wire: SendBatch now fails immediately, so the Close drain takes
	// exactly MaxRetries × RetryDelay (about 1.6s).
	if err := h.client.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}

	firstErr := make(chan error, 1)
	go func() { firstErr <- h.Close() }()
	time.Sleep(100 * time.Millisecond) // let the first Close own the drain

	secondErr := make(chan error, 1)
	go func() { secondErr <- h.Close() }()

	// The second Close must still be blocked on the first drain here.
	select {
	case err := <-secondErr:
		t.Fatalf("second Close returned while the first drain was still running: %v", err)
	case <-time.After(400 * time.Millisecond):
	}
	if err := <-firstErr; err != nil {
		t.Logf("first Close: %v (expected: sends fail against the closed client)", err)
	}
	if err := <-secondErr; err != nil {
		t.Errorf("second Close: %v", err)
	}
	if !waitFor(t, 8*time.Second, func() bool { return h.Dropped() == n }) {
		t.Errorf("Dropped() = %d, want %d (buffered records accounted after failed drain)", h.Dropped(), n)
	}
}

// ---------------------------------------------------------------------------
// #1c server rejection visibility (OnResult + internal result handler)
// ---------------------------------------------------------------------------

// TestOnResultReceivesRejection closes the audit blind spot end to end:
// SendBatch returns nil once the batch is on the wire, so a server-side
// rejection was invisible unless someone watched the client's single RESULT
// slot. The batch below carries more events than the server's ingress
// maxBatchEvents (10000), which makes the mbta-go server itself reject it at
// ingress with RESULT(level=rejected, batch_invalid) — no forwarder sink
// involved. (The mbta-go server does not schema-validate SignalBatch payloads
// itself; a content-level rejection happens in the forwarder's sink, which the
// internal result handler observes through the same single slot either way.)
//
// The handler must forward the RESULT to Config.OnResult and count the lost
// records into Dropped.
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

	// One record more than the server's ingress event cap: the wire write
	// still succeeds (SendBatch returns nil), the server rejects the batch.
	const n = maxServerBatchEvents + 1
	recs := make([]*core.SignalRecord, n)
	for i := range recs {
		recs[i] = &core.SignalRecord{SignalType: "log", TimeUnixNs: 1, Body: "x"}
	}
	h.sendBatch(recs)

	if !waitFor(t, 5*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return sawLevel == resultLevelRejected
	}) {
		mu.Lock()
		got := sawLevel
		mu.Unlock()
		t.Fatalf("OnResult level = %q, want %q (server rejection invisible)", got, resultLevelRejected)
	}
	mu.Lock()
	code := sawCode
	mu.Unlock()
	if code != core.ErrCodeBatchInvalid.Num {
		t.Errorf("OnResult code = %d, want %d (batch_invalid)", code, core.ErrCodeBatchInvalid.Num)
	}

	// The internal wrapper counts the rejected batch's records as dropped.
	if !waitFor(t, 2*time.Second, func() bool { return h.Dropped() == n }) {
		t.Errorf("Dropped() = %d, want %d after server rejection", h.Dropped(), n)
	}
	if sink.count.Load() != 0 {
		t.Errorf("server sink received %d records from a rejected batch", sink.count.Load())
	}
}
