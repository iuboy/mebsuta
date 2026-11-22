package database

import (
	"crypto/rand"
	"sync"

	"github.com/oklog/ulid/v2"
)

// idGen 生成 ULID 记录身份，用作表的自然
// 游标与幂等键。ULID 按创建顺序字典序排列
// （48 位毫秒时间戳 + 80 位单调随机数），
// 这正是让 "ORDER BY id" 成为有效增量消费游标
// 的原因，供 relay 扫描器与 mebsuta-forwarder 的 database source 使用。
//
// ulid.Monotonic 熵源本身不是 goroutine 安全的；互斥锁防止
// 并发的 Handle 调用方产出相同 ID，同时每条记录只增加一个
// 极短的临界区——相比该路径上已有的 JSON 编码与
// （可选）签名，开销可以忽略。
type idGen struct {
	mu      sync.Mutex
	entropy *ulid.MonotonicEntropy
}

var defaultIDGen = newIDGen()

func newIDGen() *idGen {
	return &idGen{mu: sync.Mutex{}, entropy: ulid.Monotonic(rand.Reader, 0)}
}

// Next 返回新的 ULID 字符串。实践中不会出错
// （Monotonic 只在其 reader 失败时失败；crypto/rand.Reader 不会），
// 因此失败时坍缩为零值 ULID，而不是在
// 日志路径上 panic。
func (g *idGen) Next() string {
	g.mu.Lock()
	id, err := ulid.New(ulid.Now(), g.entropy)
	g.mu.Unlock()
	if err != nil {
		return ulid.ULID{}.String()
	}
	return id.String()
}

// newRecordID 返回一条日志记录的身份。
func newRecordID() string { return defaultIDGen.Next() }
