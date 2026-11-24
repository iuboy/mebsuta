// SetMaxAgeDays 单元测试：值生效、负值拒绝、并发安全冒烟。
package filerotate

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetMaxAgeDays(t *testing.T) {
	w, err := New(Config{Path: filepath.Join(t.TempDir(), "a.log")})
	require.NoError(t, err)
	defer func() { _ = w.Close() }()
	require.NoError(t, w.SetMaxAgeDays(30))
	w.mu.Lock()
	got := w.cfg.MaxAgeDays
	w.mu.Unlock()
	require.Equal(t, 30, got)
	// UnlimitedAge(-1) 合法 = 不按时间删除;0 与其他负值拒绝(0.1.0-24 收紧)。
	require.NoError(t, w.SetMaxAgeDays(UnlimitedAge))
	require.Equal(t, UnlimitedAge, w.MaxAgeDays())
	require.Error(t, w.SetMaxAgeDays(0), "0 应拒绝(构造期 0 是默认 30 天)")
	require.Error(t, w.SetMaxAgeDays(-2), "其他负值应拒绝")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = w.SetMaxAgeDays(i)
		}(i)
	}
	wg.Wait()
}
