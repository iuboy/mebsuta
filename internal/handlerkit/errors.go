// Package handlerkit 是根包与各 handler 子包(database、syslog、mbta)
// 共享的实现缝:错误上报机制、错误槽位、上报限流闸、WithAttrs/WithGroup
// 子 handler 与 slog 级别工具。它经 internal 路径保持私有——不属于
// 对外消费面;公共 API 中的 mebsuta.HandlerError / mebsuta.ErrorHandler
// 是本包类型的别名。
package handlerkit

import (
	"fmt"
	"sync/atomic"
	"time"
)

// HandlerError 是 handler 通过 ErrorHandler 上报的结构化错误。
// 根包以类型别名 mebsuta.HandlerError 对外暴露同一类型。
type HandlerError struct {
	Component string // "file"、"syslog"、"database"、"async"、"multi"
	Operation string // "write"、"rotate"、"connect"、"batch"、"compress"、"cleanup"、"send"
	Err       error
	Dropped   int64     // 本次操作丢弃的记录数（异步缓冲满）
	Retryable bool      // 调用方可安全重试
	Records   int       // 受影响的记录数（批次级）
	Time      time.Time // 错误发生时间
}

func (e *HandlerError) Unwrap() error { return e.Err }

func (e *HandlerError) Error() string {
	return fmt.Sprintf("mebsuta/%s/%s: %v", e.Component, e.Operation, e.Err)
}

// ErrorHandler 处理 handler 的内部错误（如文件轮转失败、数据库写入失败）。
// 由于 slog.Logger 会静默忽略 Handle 返回的错误，handler 通过该机制上报错误。
type ErrorHandler func(*HandlerError)

// ReportError 在 ErrorHandler 非 nil 时调用它。
func ReportError(eh ErrorHandler, he *HandlerError) {
	if eh != nil {
		if he.Time.IsZero() {
			he.Time = time.Now()
		}
		eh(he)
	}
}

// ErrorSlot 是跨 WithAttrs/WithGroup 克隆共享的 ErrorHandler 原子槽位:
// 构造时以初始值填充,运行时可无锁热换,任意 goroutine 并发 Load/Store
// 均无竞争。此前每个 handler 各自重复 atomic.Pointer + Load/Store 样板。
type ErrorSlot struct {
	p atomic.Pointer[ErrorHandler]
}

// NewErrorSlot 返回以 initial 填充的槽位。
func NewErrorSlot(initial ErrorHandler) *ErrorSlot {
	s := new(ErrorSlot)
	s.p.Store(&initial)
	return s
}

// Store 热换槽位中的 ErrorHandler。nil 与普通值一视同仁地存储;
// 是否跳过 nil 传播由调用方(propagateErrorHandler)决定。
func (s *ErrorSlot) Store(fn ErrorHandler) { s.p.Store(&fn) }

// Load 返回槽位中当前的 ErrorHandler(未初始化时为 nil)。
func (s *ErrorSlot) Load() ErrorHandler {
	v := s.p.Load()
	if v == nil {
		return nil
	}
	return *v
}

// Report 经槽位当前的 ErrorHandler 上报 he(当前值为 nil 时丢弃)。
func (s *ErrorSlot) Report(he *HandlerError) { ReportError(s.Load(), he) }

// DefaultReportInterval 是 RateGate 零值使用的默认放行间隔:上报风暴
// 的限流粒度与既有各 handler 的"每秒至多一次"语义一致。
const DefaultReportInterval = int64(time.Second)

// gateEpoch 是 RateGate 的单调时钟基准:放行时间戳以 time.Since 计
// (Go 的 time.Now 携带单调钟,差值不受墙钟回拨影响——墙钟实现会在
// NTP 回拨时压制上报或连环放行)。
var gateEpoch = time.Now()

// RateGate 是"每 interval 至多放行一次"的原子限流闸,零值即可用(首次
// 调用即放行,间隔取 DefaultReportInterval)。供丢弃/错误上报共用:
// 缓冲溢出或内层失败的洪峰若 1:1 上报,每次都是一次带锁 stderr 写入,
// 限流闸把上报从洪峰中解耦。
type RateGate struct {
	last     atomic.Int64 // 最近一次放行的 unix 纳秒
	interval int64        // 放行间隔(纳秒);零值按 DefaultReportInterval
}

// Allow 报告现在是否放行;放行的调用会推进闸门。并发调用下每个间隔
// 至多一个 goroutine 收到 true(CAS 胜者),与既有各 handler 的
// shouldReportDrop 语义一致。
func (g *RateGate) Allow() bool {
	interval := g.interval
	if interval == 0 {
		interval = DefaultReportInterval
	}
	now := int64(time.Since(gateEpoch))
	last := g.last.Load()
	// last==0 表示从未放行(单调时钟下 now 从 0 起算,不能与 last=0
	// 相减判窗口——那会把进程启动后的第一个 interval 误判为"刚放行
	// 过")。零值 gate 首次调用放行,与墙钟实现语义一致。
	if last != 0 && now-last < interval {
		return false
	}
	return g.last.CompareAndSwap(last, now)
}
