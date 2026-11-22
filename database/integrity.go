// Package database 提供与 slog 兼容的 handler，将日志
// 记录批量持久化到 SQL 数据库。
//
// IntegritySigner 是可选的、与算法无关的防篡改钩子。
// database handler 不依赖任何特定密码学库；
// 调用方注入具体的 signer（SM2+SM3、ECDSA+SHA256 等）。

package database

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// VerifyRecord 返回的错误。VerifyRecord 失败即收紧：没有
// hash 或签名的记录会被报告为 ErrUnsignedRecord，而不是
// 静默通过，由审计人员显式决定如何处置未签名行。
var (
	// ErrUnsignedRecord 表示存储的记录没有 record_hash 或没有
	// signature。篡改者清空任一列也会产生此错误。
	ErrUnsignedRecord = errors.New("mebsuta/database: record is unsigned (missing record_hash or signature)")

	// ErrNilVerifier 表示存在签名但未提供校验器
	//（包括类型化 nil 实现）。
	ErrNilVerifier = errors.New("mebsuta/database: verifier is nil")

	// ErrHashMismatch 表示从存储记录内容重新计算的 hash
	// 与存储的 record_hash 不一致——内容很可能在签名后
	// 被篡改。
	ErrHashMismatch = errors.New("mebsuta/database: record content does not match stored hash (possible tampering)")

	// ErrAlgoMismatch 表示存储的 sign_algo 列指定的算法与
	// 所提供校验器实现的算法不同。否则校验器要么
	// 不透明地失败，更糟的是在篡改者选定的算法下
	// “验证”签名。
	ErrAlgoMismatch = errors.New("mebsuta/database: stored sign_algo does not match verifier algorithm")
)

const (
	// canonicalTimeLayout 以 UTC、固定微秒小数位渲染时间戳
	//（不去除尾零），因此相同的时刻总是
	// 产出相同的规范字节。
	canonicalTimeLayout = "2006-01-02T15:04:05.000000Z07:00"

	// canonicalPrecision 与存储时间戳的 timestamptz 列分辨率一致
	//（PostgreSQL 与 openGauss 都保留
	// 微秒）。启用签名时，亚微秒位会从规范形与
	// 存储值中同时丢弃，因此从存储行重新
	// 计算 hash 能精确复现签名的 hash。
	canonicalPrecision = time.Microsecond
)

// canonicalRecord 是 CanonicalBytes 编码的确定性形态。
// JSON 编码让表示无歧义（不会与消息内容发生
// 分隔符冲突）且跨 Go 版本稳定。
type canonicalRecord struct {
	Time   string          `json:"t"`
	Level  string          `json:"l"`
	Msg    string          `json:"m"`
	Fields json.RawMessage `json:"f"`
}

// canonicalFields 将原始 JSON 规范化为确定性形态：键排序、
// 无多余空白、Go 原生转义。签名侧与
// 校验侧都让 fields 列经过它，而不是
// 直接比较原始字节。
//
// 数字用 json.Number 解码——绝不用 float64——因此像
// 9007199254740992 与 9007199254740993（都会舍入到 2^53）这样的
// 不同值保持可区分；篡改者无法偷换存储的数字字段（金额、ID），
// 而重新计算的 hash——进而签名——仍然
// 通过校验。数字字面量还会被改写为 PostgreSQL 的 numeric 文本
// 形式（见 normalizeJSONNumber），使 json → jsonb 列迁移
// ——它会把 1e+21 等改写为纯小数——对已签名行
// 透明：jsonb 渲染相同的写法规范化结果相同，数值
// 不同的写法永不趋同。
//
// 含重复对象键的文档被直接拒绝。
// 写入方从不产生它们（它序列化的是 Go map），而 last-wins 解码
// 会静默掩盖 {"k":original,"k":forged} 式的改写。
func canonicalFields(fields json.RawMessage) (json.RawMessage, error) {
	if len(fields) == 0 {
		return nil, nil
	}
	if err := checkNoDuplicateKeys(fields); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(fields))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("mebsuta/database: fields are not valid JSON: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("mebsuta/database: fields contain trailing data after the JSON value")
	}
	normalizeNumbersIn(v)
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("mebsuta/database: canonicalize fields: %w", err)
	}
	return data, nil
}

// normalizeNumbersIn 将解码值树中的每个 json.Number（原地）
// 改写为 PostgreSQL 的 numeric 文本形式。json.Number 是字符串类型，
// Marshal 原样输出它，因此替换字面量文本即可改写
// 规范字节而不触碰任何其他值。
func normalizeNumbersIn(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if n, ok := val.(json.Number); ok {
				t[k] = json.Number(normalizeJSONNumber(n))
			} else {
				normalizeNumbersIn(val)
			}
		}
	case []any:
		for i, val := range t {
			if n, ok := val.(json.Number); ok {
				t[i] = json.Number(normalizeJSONNumber(n))
			} else {
				normalizeNumbersIn(val)
			}
		}
	}
}

// maxNumberExpandLen 限制展开后的十进制形式。PostgreSQL 拒绝
// numeric 形式超出位数上限的 jsonb 数字（“value overflows
// numeric format”），因此展开后超过该上限的字面量
// 本来就无法经 jsonb 列往返；它们原样通过，
// 并经保留文本的 json 列保持一致。
const maxNumberExpandLen = 8192

// normalizeJSONNumber 将 JSON 数字字面量改写为 PostgreSQL 的
// numeric 文本输出形式，已对照 PostgreSQL 18 实证验证：
//
//	"1e+21"  → "1000000000000000000000"（指数展开）
//	"1.50"   → "1.50"（小数位数保留）
//	"1.50e2" → "150"、"1.50e1" → "15.0"（位数被指数缩减）
//	"1.5e-2" → "0.015"（补小数零）
//	"007"    → "7"（整数前导零剥离）
//	"-0" → "0"、"-0.0" → "0.0"、"0e10" → "0"（零：符号丢弃、位数保留）
//
// 因此两种写法规范化的结果相同，当且仅当 jsonb 渲染
// 相同——json → jsonb 迁移对已签名行
// 透明——且绝不使不同的数值趋同。
func normalizeJSONNumber(lit json.Number) string {
	s := string(lit)
	if isNumericTextForm(s) {
		return s
	}
	neg := false
	if s[0] == '-' {
		neg, s = true, s[1:]
	}
	mant, exp := s, 0
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		mant = s[:i]
		e, err := strconv.Atoi(s[i+1:])
		if err != nil {
			return s // 不可达：解码器已校验过该字面量
		}
		exp = e
	}
	intPart, fracPart := mant, ""
	if i := strings.IndexByte(mant, '.'); i >= 0 {
		intPart, fracPart = mant[:i], mant[i+1:]
	}
	digits := intPart + fracPart
	point := len(intPart) + exp // decimal point position within digits

	if strings.Trim(digits, "0") == "" {
		// 零值：符号丢弃；只保留最终位数
		// 隐含的小数零（PostgreSQL numeric 语义）。
		scale := len(fracPart) - exp
		if scale <= 0 {
			return "0"
		}
		if scale > maxNumberExpandLen {
			return s
		}
		return "0." + strings.Repeat("0", scale)
	}

	switch {
	case point <= 0:
		if -point+1+len(digits) > maxNumberExpandLen {
			return s
		}
		out := "0." + strings.Repeat("0", -point) + digits
		if neg {
			return "-" + out
		}
		return out
	case point >= len(digits):
		if point > maxNumberExpandLen {
			return s
		}
		// "007e2" → "00700”——整数前导零无意义。
		out := strings.TrimLeft(digits+strings.Repeat("0", point-len(digits)), "0")
		if out == "" {
			out = "0"
		}
		if neg {
			return "-" + out
		}
		return out
	default:
		intOut := strings.TrimLeft(digits[:point], "0")
		if intOut == "" {
			intOut = "0"
		}
		if len(intOut)+1+len(digits[point:]) > maxNumberExpandLen {
			return s
		}
		out := intOut + "." + digits[point:]
		if neg {
			return "-" + out
		}
		return out
	}
}

// isNumericTextForm 判断 lit 是否已等于其 PostgreSQL numeric
// 文本形式：无指数、无整数前导零、且不是负零。
// Go 的 float/int 编码器对 1e21 以下的一切都输出该形式，因此
// 该快速路径覆盖绝大多数字面量。
func isNumericTextForm(s string) bool {
	i := 0
	if s[0] == '-' {
		i = 1
	}
	d := i
	for d < len(s) && s[d] >= '0' && s[d] <= '9' {
		d++
	}
	intPart := s[i:d]
	if len(intPart) == 0 || (len(intPart) > 1 && s[i] == '0') {
		return false // “.5”不会来自解码器；前导零
	}
	rest := s[d:]
	for _, c := range rest {
		if c == 'e' || c == 'E' {
			return false // 指数形式需要展开
		}
	}
	if i == 1 && intPart == "0" {
		// 可能是负零（"-0"、"-0.0"）：符号必须丢弃
		for _, c := range rest {
			if c >= '1' && c <= '9' {
				return true // 负的非零小数：原样即可
			}
		}
		return false
	}
	return true
}

// maxDupCheckDepth 限制 checkNoDuplicateKeys 的递归深度，恶意构造的
// 超深文档才不会在校验期间溢出栈。
const maxDupCheckDepth = 64

// checkNoDuplicateKeys 遍历 JSON token 流，任何对象
// 重复键即报错。encoding/json 的解码器静默保留
// 最后一个重复项，那会让 {"a":1,"a":2} 与 {"a":2} 校验
// 结果相同，把被篡改的列藏在未变的规范形
// 之后。
func checkNoDuplicateKeys(data []byte) error {
	// UseNumber：没有它，token 遍历会把数字解析为 float64，像
	// 1e999 这样的巨大字面量（写入方可经
	// json.Number 合法产生）会在这里失败，而下方严格的
	// UseNumber 解码却接受它——该不一致曾把这类记录
	// 静默降级为未签名。
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := checkValueDupKeys(dec, 0); err != nil {
		return fmt.Errorf("mebsuta/database: fields JSON is not acceptable: %w", err)
	}
	return nil
}

func checkValueDupKeys(dec *json.Decoder, depth int) error {
	if depth >= maxDupCheckDepth {
		return fmt.Errorf("nesting deeper than %d levels", maxDupCheckDepth-1)
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // 标量值
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyTok.(string)
			if !ok {
				return fmt.Errorf("unexpected non-string object key %v", keyTok)
			}
			if _, dup := seen[key]; dup {
				return fmt.Errorf("duplicate object key %q", key)
			}
			seen[key] = struct{}{}
			if err := checkValueDupKeys(dec, depth+1); err != nil {
				return err
			}
		}
		_, err = dec.Token() // 消费 '}'
		return err
	case '[':
		for dec.More() {
			if err := checkValueDupKeys(dec, depth+1); err != nil {
				return err
			}
		}
		_, err = dec.Token() // 消费 ']'
		return err
	default:
		return nil // 独立分隔符不会作为值出现
	}
}

// CanonicalBytes 返回记录的规范字节表示：
// 写入时由 IntegritySigner 签名、审计时由
// VerifyRecord 重新计算的确切字节。它确定且与
// 存储往返无关：
//
//   - Time 转为 UTC 并截断到微秒精度
//     （canonicalPrecision），与 PostgreSQL
//     timestamptz 列的分辨率一致。
//   - Fields 经 canonicalFields 规范化，容忍数据库
//     对 JSON 列施加的键重排与空白变化。
//     数字保留精确值与字面量写法（json.Number）；
//     含重复对象键的文档被拒绝。
//
// 审计工具重算存储记录 hash 时应使用本函数
// （而非自造的序列化）。
func CanonicalBytes(t time.Time, level, message string, fields json.RawMessage) ([]byte, error) {
	f, err := canonicalFields(fields)
	if err != nil {
		return nil, err
	}
	return json.Marshal(canonicalRecord{
		Time:   t.UTC().Truncate(canonicalPrecision).Format(canonicalTimeLayout),
		Level:  level,
		Msg:    message,
		Fields: f,
	})
}

// IntegritySigner 为数据库日志条目提供逐记录的完整性保护
// （hash + 签名）。
//
// handler 对每条记录的 CanonicalBytes 输出签名。
// 返回的 recordHash 与 signature 随条目一起持久化，之后的
// 任何篡改都可通过用 CanonicalBytes 重新计算 hash 并经
// IntegrityVerifier 校验来发现（见 VerifyRecord）。
//
// 实现可以使用任意算法对（如国密合规的 SM2+SM3，
// 国际通用的 ECDSA+SHA256）。handler 与算法无关，
// 自身不引入任何密码学依赖。
type IntegritySigner interface {
	// Sign 计算 data 的 hash（通常是 CanonicalBytes 的输出）
	// 并签名，返回原始 hash 与签名字节。hash 以十六进制
	// 存入 record_hash 列；签名以原始
	// 字节存入 signature 列。
	//
	// Sign 必须并发安全：slog handler 可能从多个
	// goroutine 处理记录，因此 handler 会并发调用 Sign。
	// 持有可变状态的实现（HSM 会话、复用的 hash
	// 对象、缓冲区）必须自行同步访问。
	Sign(data []byte) (recordHash, signature []byte, err error)

	// Algorithm 返回算法对的简短稳定标识，
	// 如 "SM2-SM3" 或 "ECDSA-SHA256"。存入 sign_algo 列，
	// 校验器据此知道使用哪种算法。
	Algorithm() string
}

// IntegrityVerifier 是 IntegritySigner 在校验侧的镜像。写入
// 时不需要；需要审计存储记录的调用方
// 实现它并传给 VerifyRecord。
//
// 与 IntegritySigner 一样，实现必须并发安全。
type IntegrityVerifier interface {
	// Hash 用与对应 signer 相同的摘要算法计算规范数据
	//（CanonicalBytes 的输出）的记录 hash。
	// VerifyRecord 用它重算存储记录的 hash，把
	// 存储 hash 与记录内容绑定。
	Hash(data []byte) ([]byte, error)

	// Verify 检查 signature 对 recordHash 是否有效。成功
	// 返回 nil。
	Verify(recordHash, signature []byte) error

	// Algorithm 返回算法标识（必须与 signer 的一致）。
	Algorithm() string
}

// StoredRecord 承载从数据库读回的一条日志条目的
// 持久化列，供 VerifyRecord 校验。
type StoredRecord struct {
	Time     time.Time       // time 列内容。
	Level    string          // level 列内容。
	Message  string          // msg 列内容。
	Fields   json.RawMessage // fields 列内容；任意键序或空白。
	SignAlgo string          // sign_algo 列内容；为空表示该行未签名。
}

// VerifyRecord 端到端校验一条存储日志条目的完整性：
//
//  1. 行必须带全部三个完整性列（record_hash、signature、
//     sign_algo）；任一缺失即报 ErrUnsignedRecord。
//  2. 存储的 sign_algo 必须等于 verifier.Algorithm()，校验器
//     才不会被诱导去按篡改者选定的算法校验
//     签名（否则为 ErrAlgoMismatch）。
//  3. 从记录内容重算的 hash（经 CanonicalBytes 与
//     verifier.Hash）必须等于存储的 record_hash——这把 hash 与
//     内容绑定，因此即使存储 hash 与签名原封不动，事后
//     篡改消息或 fields 也会被发现。
//  4. 存储的签名必须对该 hash 校验通过。
//
// 它失败即收紧：缺少任一完整性列的记录返回
// ErrUnsignedRecord 而非静默通过——清空
// signature 列的篡改者不能蒙混过关。确实允许
// 未签名记录的调用方可用 errors.Is 匹配该错误。
//
// 范围限制：签名逐记录且彼此独立。整行
// 删除、插入与重排无法被 VerifyRecord 发现——
// 若这些威胁重要，请配合外部锚点（行数清单、周期性头/尾
// hash 检查点，或数据库级审计日志）。
func VerifyRecord(rec StoredRecord, recordHashHex string, signature []byte, verifier IntegrityVerifier) error {
	if len(recordHashHex) == 0 || len(signature) == 0 || rec.SignAlgo == "" {
		return ErrUnsignedRecord
	}
	if isNilVerifier(verifier) {
		return ErrNilVerifier
	}
	if rec.SignAlgo != verifier.Algorithm() {
		return fmt.Errorf("%w: stored %q, verifier %q", ErrAlgoMismatch, rec.SignAlgo, verifier.Algorithm())
	}

	canonical, err := CanonicalBytes(rec.Time, rec.Level, rec.Message, rec.Fields)
	if err != nil {
		return err
	}
	expected, err := verifier.Hash(canonical)
	if err != nil {
		return fmt.Errorf("mebsuta/database: recompute record hash: %w", err)
	}

	stored, err := hex.DecodeString(recordHashHex)
	if err != nil {
		return fmt.Errorf("mebsuta/database: record_hash column is not valid hex: %w", err)
	}
	if !bytes.Equal(expected, stored) {
		return ErrHashMismatch
	}

	if err := verifier.Verify(stored, signature); err != nil {
		return fmt.Errorf("mebsuta/database: signature verification failed: %w", err)
	}
	return nil
}

// isNilVerifier 判断 verifier 是无类型 nil，还是类型化 nil 的
// 指针/map/slice/func/chan 值，防止调用方
// 没能构造出校验器（如 nil *MyVerifier）时
// VerifyRecord panic。
func isNilVerifier(verifier IntegrityVerifier) bool {
	if verifier == nil {
		return true
	}
	switch v := reflect.ValueOf(verifier); v.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return v.IsNil()
	default:
		return false
	}
}
