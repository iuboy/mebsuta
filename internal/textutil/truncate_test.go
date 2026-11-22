package textutil

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
)

func TestTruncateUTF8(t *testing.T) {
	cases := []struct {
		in       string
		maxBytes int
		want     string
	}{
		{"short", 100, "short"},        // 不截断
		{"hello world", 8, "hello..."}, // 截断并带标记
		{"héllo wörld", 5, "h..."},     // limit=2 从 é（2 字节）回退到 1
		{"héllo wörld", 6, "hé..."},    // limit=3 落在 é 中间 → 回退到 2 = "hé"
		{"abc", 2, "ab"},               // 低于标记空间：硬切
		{"abc", 0, ""},                 // 零预算
		{"abc", -1, ""},                // 负预算
		{"界界界", 7, "界..."},             // limit=4 回退到 3 = 一个界
	}
	for _, tc := range cases {
		require.Equal(t, tc.want, TruncateUTF8(tc.in, tc.maxBytes),
			"TruncateUTF8(%q, %d)", tc.in, tc.maxBytes)
	}
	// 每个输出都必须是合法 UTF-8（边界回退的全部意义所在）。
	for _, in := range []string{"héllo wörld", "界界界界", "🙂🙃🙂"} {
		for max := 0; max < len(in)+2; max++ {
			require.True(t, utf8.ValidString(TruncateUTF8(in, max)),
				"TruncateUTF8(%q, %d) 产生了非法 UTF-8", in, max)
		}
	}
}

func TestCutToRuneBoundary(t *testing.T) {
	require.Equal(t, "hé", CutToRuneBoundary("héllo", 3))
	require.Equal(t, "abc", CutToRuneBoundary("abc", 99), "短字符串应原样通过")
	// 永不追加标记。
	require.Equal(t, "界", CutToRuneBoundary(strings.Repeat("界", 10), 5),
		"硬切风格不得追加标记")
}
