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
	require.Error(t, w.SetMaxAgeDays(-1), "负值应拒绝")
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
