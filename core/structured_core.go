package core

import (
	"fmt"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	serviceName = "default_service"
	requestID   = "unknown_request_id"
	hostname, _ = os.Hostname()
	pid         = os.Getpid()
)

// StructuredCore 实现 zapcore.Core
// 将日志同时分发给：
// 1. JSON/Console 编码器（用于文件/控制台）
// 2. 结构化事件处理器（用于 DB/Syslog/gRPC）
type StructuredCore struct {
	// 传统字节输出目标
	encoder   zapcore.Encoder
	levelEnab zapcore.LevelEnabler
	encSyncer zapcore.WriteSyncer

	// 结构化输出目标
	eventWriter EventWriteSyncer

	fields []zap.Field
}

func NewStructuredCore(
	encoder zapcore.Encoder,
	levelEnab zapcore.LevelEnabler,
	encSyncer zapcore.WriteSyncer,
	eventWriter EventWriteSyncer,
) zapcore.Core {
	return &StructuredCore{
		encoder:     encoder,
		levelEnab:   levelEnab,
		encSyncer:   encSyncer,
		eventWriter: eventWriter,
	}
}

func (c *StructuredCore) Enabled(level zapcore.Level) bool {
	return c.levelEnab.Enabled(level)
}

func (c *StructuredCore) With(fields []zapcore.Field) zapcore.Core {
	// 克隆自身
	clone := c.clone()

	// 缓存字段，供事件生成使用
	clone.fields = append(clone.fields, fields...)

	return clone
}

func (c *StructuredCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.levelEnab.Enabled(ent.Level) {
		return ce.AddCore(ent, c)
	}
	return ce
}

func (c *StructuredCore) Write(ent zapcore.Entry, fields []zapcore.Field) error {
	combinedFields := append(c.fields, fields...)
	var firstErr error
	// === 路径1: JSON/Console 字节输出 ===
	if c.encSyncer != nil {
		if err := c.writeBytes(ent, combinedFields); err != nil {
			firstErr = fmt.Errorf("byte_output_failed: %w", err)
		}
	}
	// === 路径2: 结构化事件输出 ===
	if c.eventWriter != nil {
		event := c.toLogEvent(ent, combinedFields)
		if err := c.eventWriter.WriteEvent(event); err != nil {
			// 记录，但不覆盖原始错误
			if firstErr == nil {
				firstErr = fmt.Errorf("event_output_failed: %w", err)
			} else {
				// 两者都失败，只报告第一个，但记录第二个
				fmt.Fprintf(os.Stderr, "secondary failure in WriteEvent: %v\n", err)
			}
		}
	}
	return firstErr
}
func (c *StructuredCore) Sync() error {
	var err error
	if c.encSyncer != nil {
		if e := c.encSyncer.Sync(); e != nil {
			err = e
		}
	}
	if c.eventWriter != nil {
		if e := c.eventWriter.Sync(); e != nil && err == nil {
			err = e
		}
	}
	return err
}

// writeBytes 独立函数：安全编码 JSON
func (c *StructuredCore) writeBytes(ent zapcore.Entry, fields []zapcore.Field) error {
	if c.encoder == nil || c.encSyncer == nil {
		return nil
	}

	// 使用克隆的 encoder 以避免并发问题
	clone := c.encoder.Clone()
	buf, err := clone.EncodeEntry(ent, fields)
	if err != nil {
		return fmt.Errorf("encode entry failed: %w", err)
	}

	// 写入字节流
	if _, werr := c.encSyncer.Write(buf.Bytes()); werr != nil {
		buf.Free()
		return fmt.Errorf("write to syncer failed: %w", werr)
	}

	// 释放 buffer 回池
	buf.Free()
	return nil
}

// toLogEvent 构建结构化事件
func (c *StructuredCore) toLogEvent(ent zapcore.Entry, fields []zapcore.Field) *LogEvent {
	event := &LogEvent{
		Timestamp:   ent.Time,
		Level:       ent.Level.String(),
		Message:     ent.Message,
		Caller:      ent.Caller.String(),
		Stack:       ent.Stack,
		ServiceName: serviceName,
		RequestID:   requestID,
		Host:        hostname,
		PID:         pid,
		Fields:      make(map[string]any),
	}
	// 解码字段到 map
	enc := newFieldEncoder(event.Fields)
	for _, f := range fields {
		f.AddTo(enc)
	}
	return event
}

// clone 实现 zapcore.Core 接口
func (c *StructuredCore) clone() *StructuredCore {
	return &StructuredCore{
		encoder:     c.encoder.Clone(),
		levelEnab:   c.levelEnab,
		encSyncer:   c.encSyncer,
		eventWriter: c.eventWriter,
		fields:      append([]zap.Field(nil), c.fields...),
	}
}

// newFieldEncoder 构建一个可以将 zap.Field 映射到 map 的 encoder
func newFieldEncoder(out map[string]any) zapcore.ObjectEncoder {
	return &fieldEncoder{out: out, ns: "", nsSep: "."}
}

type fieldEncoder struct {
	out   map[string]any
	ns    string
	nsSep string
}

func (fe *fieldEncoder) AddArray(key string, marshaler zapcore.ArrayMarshaler) error {
	if key != "" {
		fe.ns = fe.appendKey(fe.ns, key)
	}
	arr := &arrayEncoder{elems: make([]any, 0)}
	err := marshaler.MarshalLogArray(arr)
	if key != "" {
		fe.ns = fe.parentNS()
	}
	if err == nil {
		fe.out[fe.appendKey(fe.ns, key)] = arr.elems
	}
	return err
}

func (fe *fieldEncoder) AddObject(key string, marshaler zapcore.ObjectMarshaler) error {
	if key != "" {
		fe.ns = fe.appendKey(fe.ns, key)
	}
	obj := &objectEncoder{out: make(map[string]any)}
	err := marshaler.MarshalLogObject(obj)
	if key != "" {
		fe.ns = fe.parentNS()
	}
	if err == nil {
		fe.out[fe.appendKey(fe.ns, key)] = obj.out
	}
	return err
}

func (fe *fieldEncoder) AddBinary(key string, val []byte) { fe.out[fe.appendKey(fe.ns, key)] = val }
func (fe *fieldEncoder) AddByteString(key string, val []byte) {
	fe.out[fe.appendKey(fe.ns, key)] = string(val)
}
func (fe *fieldEncoder) AddBool(key string, val bool) { fe.out[fe.appendKey(fe.ns, key)] = val }
func (fe *fieldEncoder) AddComplex128(key string, val complex128) {
	fe.out[fe.appendKey(fe.ns, key)] = val
}
func (fe *fieldEncoder) AddComplex64(key string, val complex64) {
	fe.out[fe.appendKey(fe.ns, key)] = val
}
func (fe *fieldEncoder) AddDuration(key string, val time.Duration) {
	fe.out[fe.appendKey(fe.ns, key)] = val
}
func (fe *fieldEncoder) AddFloat64(key string, val float64) { fe.out[fe.appendKey(fe.ns, key)] = val }
func (fe *fieldEncoder) AddFloat32(key string, val float32) { fe.out[fe.appendKey(fe.ns, key)] = val }
func (fe *fieldEncoder) AddInt(key string, val int)         { fe.out[fe.appendKey(fe.ns, key)] = val }
func (fe *fieldEncoder) AddInt64(key string, val int64)     { fe.out[fe.appendKey(fe.ns, key)] = val }
func (fe *fieldEncoder) AddInt32(key string, val int32)     { fe.out[fe.appendKey(fe.ns, key)] = val }
func (fe *fieldEncoder) AddInt16(key string, val int16)     { fe.out[fe.appendKey(fe.ns, key)] = val }
func (fe *fieldEncoder) AddInt8(key string, val int8)       { fe.out[fe.appendKey(fe.ns, key)] = val }
func (fe *fieldEncoder) AddString(key string, val string)   { fe.out[fe.appendKey(fe.ns, key)] = val }
func (fe *fieldEncoder) AddTime(key string, val time.Time)  { fe.out[fe.appendKey(fe.ns, key)] = val }
func (fe *fieldEncoder) AddUint(key string, val uint)       { fe.out[fe.appendKey(fe.ns, key)] = val }
func (fe *fieldEncoder) AddUint64(key string, val uint64)   { fe.out[fe.appendKey(fe.ns, key)] = val }
func (fe *fieldEncoder) AddUint32(key string, val uint32)   { fe.out[fe.appendKey(fe.ns, key)] = val }
func (fe *fieldEncoder) AddUint16(key string, val uint16)   { fe.out[fe.appendKey(fe.ns, key)] = val }
func (fe *fieldEncoder) AddUint8(key string, val uint8)     { fe.out[fe.appendKey(fe.ns, key)] = val }
func (fe *fieldEncoder) AddUintptr(key string, val uintptr) { fe.out[fe.appendKey(fe.ns, key)] = val }
func (fe *fieldEncoder) AddReflected(key string, val interface{}) error {
	fe.out[fe.appendKey(fe.ns, key)] = val
	return nil
}
func (fe *fieldEncoder) OpenNamespace(key string) { fe.ns = fe.appendKey(fe.ns, key) }

func (fe *fieldEncoder) appendKey(ns, key string) string {
	if ns == "" {
		return key
	}
	return ns + fe.nsSep + key
}

func (fe *fieldEncoder) parentNS() string {
	idx := strings.LastIndex(fe.ns, fe.nsSep)
	if idx == -1 {
		return ""
	}
	return fe.ns[:idx]
}

type arrayEncoder struct{ elems []any }

func (a *arrayEncoder) AppendArray(marshaler zapcore.ArrayMarshaler) error {
	// 调用 marshaler 将数组内容追加到 elems 中
	if err := marshaler.MarshalLogArray(a); err != nil {
		return err // 返回错误
	}
	return nil // 无错误时返回 nil
}

func (a *arrayEncoder) AppendObject(marshaler zapcore.ObjectMarshaler) error {
	obj := &objectEncoder{out: make(map[string]any)}
	if err := marshaler.MarshalLogObject(obj); err != nil {
		return err
	}
	a.elems = append(a.elems, obj.out)
	return nil
}
func (a *arrayEncoder) AppendReflected(value interface{}) error {
	a.elems = append(a.elems, value)
	return nil
}
func (a *arrayEncoder) AppendBool(v bool)              { a.elems = append(a.elems, v) }
func (a *arrayEncoder) AppendByteString(v []byte)      { a.elems = append(a.elems, string(v)) }
func (a *arrayEncoder) AppendComplex128(v complex128)  { a.elems = append(a.elems, v) }
func (a *arrayEncoder) AppendComplex64(v complex64)    { a.elems = append(a.elems, v) }
func (a *arrayEncoder) AppendDuration(v time.Duration) { a.elems = append(a.elems, v) }
func (a *arrayEncoder) AppendFloat64(v float64)        { a.elems = append(a.elems, v) }
func (a *arrayEncoder) AppendFloat32(v float32)        { a.elems = append(a.elems, v) }
func (a *arrayEncoder) AppendInt(v int)                { a.elems = append(a.elems, v) }
func (a *arrayEncoder) AppendInt64(v int64)            { a.elems = append(a.elems, v) }
func (a *arrayEncoder) AppendInt32(v int32)            { a.elems = append(a.elems, v) }
func (a *arrayEncoder) AppendInt16(v int16)            { a.elems = append(a.elems, v) }
func (a *arrayEncoder) AppendInt8(v int8)              { a.elems = append(a.elems, v) }
func (a *arrayEncoder) AppendString(v string)          { a.elems = append(a.elems, v) }
func (a *arrayEncoder) AppendTime(v time.Time)         { a.elems = append(a.elems, v) }
func (a *arrayEncoder) AppendUint(v uint)              { a.elems = append(a.elems, v) }
func (a *arrayEncoder) AppendUint64(v uint64)          { a.elems = append(a.elems, v) }
func (a *arrayEncoder) AppendUint32(v uint32)          { a.elems = append(a.elems, v) }
func (a *arrayEncoder) AppendUint16(v uint16)          { a.elems = append(a.elems, v) }
func (a *arrayEncoder) AppendUint8(v uint8)            { a.elems = append(a.elems, v) }
func (a *arrayEncoder) AppendUintptr(v uintptr)        { a.elems = append(a.elems, v) }

type objectEncoder struct {
	out map[string]any
}

// AddArray 实现 zapcore.ObjectEncoder 接口
func (o *objectEncoder) AddArray(key string, marshaler zapcore.ArrayMarshaler) error {
	arr := &arrayEncoder{elems: make([]any, 0)}
	if err := marshaler.MarshalLogArray(arr); err != nil {
		return err
	}
	o.out[key] = arr.elems
	return nil
}

// AddObject 实现 zapcore.ObjectEncoder 接口
func (o *objectEncoder) AddObject(key string, marshaler zapcore.ObjectMarshaler) error {
	sub := &objectEncoder{out: make(map[string]any)}
	if err := marshaler.MarshalLogObject(sub); err != nil {
		return err
	}
	o.out[key] = sub.out
	return nil
}

// AddBinary 实现 zapcore.ObjectEncoder 接口
func (o *objectEncoder) AddBinary(key string, value []byte) {
	o.out[key] = value
}

// AddBool 实现 zapcore.ObjectEncoder 接口
func (o *objectEncoder) AddBool(key string, value bool) {
	o.out[key] = value
}

// AddByteString 补充实现 zapcore.ObjectEncoder 接口
func (o *objectEncoder) AddByteString(key string, value []byte) {
	o.out[key] = string(value)
}

// AddComplex128 实现 zapcore.ObjectEncoder 接口
func (o *objectEncoder) AddComplex128(key string, value complex128) {
	o.out[key] = value
}

// AddComplex64 实现 zapcore.ObjectEncoder 接口
func (o *objectEncoder) AddComplex64(key string, value complex64) {
	o.out[key] = value
}

// AddDuration 实现 zapcore.ObjectEncoder 接口
func (o *objectEncoder) AddDuration(key string, value time.Duration) {
	o.out[key] = value
}

// AddFloat64 实现 zapcore.ObjectEncoder 接口
func (o *objectEncoder) AddFloat64(key string, value float64) {
	o.out[key] = value
}

// AddFloat32 实现 zapcore.ObjectEncoder 接口
func (o *objectEncoder) AddFloat32(key string, value float32) {
	o.out[key] = value
}

// AddInt 实现 zapcore.ObjectEncoder 接口
func (o *objectEncoder) AddInt(key string, value int) {
	o.out[key] = value
}

// AddInt64 实现 zapcore.ObjectEncoder 接口
func (o *objectEncoder) AddInt64(key string, value int64) {
	o.out[key] = value
}

// AddInt32 实现 zapcore.ObjectEncoder 接口
func (o *objectEncoder) AddInt32(key string, value int32) {
	o.out[key] = value
}

// AddInt16 实现 zapcore.ObjectEncoder 接口
func (o *objectEncoder) AddInt16(key string, value int16) {
	o.out[key] = value
}

// AddInt8 实现 zapcore.ObjectEncoder 接口
func (o *objectEncoder) AddInt8(key string, value int8) {
	o.out[key] = value
}

// AddString 实现 zapcore.ObjectEncoder 接口
func (o *objectEncoder) AddString(key string, value string) {
	o.out[key] = value
}

// AddTime 实现 zapcore.ObjectEncoder 接口
func (o *objectEncoder) AddTime(key string, value time.Time) {
	o.out[key] = value
}

// AddUint 实现 zapcore.ObjectEncoder 接口
func (o *objectEncoder) AddUint(key string, value uint) {
	o.out[key] = value
}

// AddUint64 实现 zapcore.ObjectEncoder 接口
func (o *objectEncoder) AddUint64(key string, value uint64) {
	o.out[key] = value
}

// AddUint32 实现 zapcore.ObjectEncoder 接口
func (o *objectEncoder) AddUint32(key string, value uint32) {
	o.out[key] = value
}

// AddUint16 实现 zapcore.ObjectEncoder 接口
func (o *objectEncoder) AddUint16(key string, value uint16) {
	o.out[key] = value
}

// AddUint8 实现 zapcore.ObjectEncoder 接口
func (o *objectEncoder) AddUint8(key string, value uint8) {
	o.out[key] = value
}

// AddUintptr 实现 zapcore.ObjectEncoder 接口
func (o *objectEncoder) AddUintptr(key string, value uintptr) {
	o.out[key] = value
}

// AddReflected 实现 zapcore.ObjectEncoder 接口
func (o *objectEncoder) AddReflected(key string, value interface{}) error {
	o.out[key] = value
	return nil
}

// OpenNamespace 实现 zapcore.ObjectEncoder 接口
func (o *objectEncoder) OpenNamespace(key string) {
	// 忽略命名空间操作
}
