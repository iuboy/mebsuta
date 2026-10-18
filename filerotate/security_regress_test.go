package filerotate

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestOpenAppend_RefusesSymlink is the regression test for the symlink
// TOCTOU write-hijack: opening the log path when it is a symlink (the exact
// state an attacker plants during the rotation rename window) must fail.
func TestOpenAppend_RefusesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("O_NOFOLLOW is Unix-only; inode check remains on Windows")
	}
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.txt")
	if err := os.WriteFile(victim, []byte("do not touch\n"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "app.log")
	if err := os.Symlink(victim, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	if f, _, err := openAppend(link, 0600); err == nil {
		f.Close()
		t.Fatal("openAppend accepted a symlink — writes would land on the victim file")
	}
	// The victim must be untouched.
	data, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "do not touch\n" {
		t.Fatalf("victim file was modified: %q", data)
	}
}

// TestNew_RefusesSymlinkedPath covers the construction-time check.
func TestNew_RefusesSymlinkedPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.txt")
	if err := os.WriteFile(victim, nil, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "app.log")
	if err := os.Symlink(victim, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := New(Config{Path: link}); err == nil {
		t.Fatal("New accepted a symlinked log path")
	}
}

// TestClose_OnErrorReentrancy is the regression test for the M4 deadlock:
// Close used to report pending rotation errors while still holding w.mu, so
// an OnError callback that re-entered the Writer deadlocked permanently.
func TestClose_OnErrorReentrancy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	w, err := New(Config{Path: path, MaxSizeMB: 1, Compress: boolPtr(false)})
	if err != nil {
		t.Fatal(err)
	}

	reentered := make(chan struct{})
	w.SetOnError(func(err error) {
		select {
		case <-reentered:
		default:
			close(reentered)
		}
		// Re-enter the Writer from inside the error callback — deadlock
		// before the fix, must complete now.
		_, _ = w.Write([]byte("reentry probe"))
	})

	w.addRotateErrors(&Error{Op: "rotate", Err: errTest})
	done := make(chan error, 1)
	go func() { done <- w.Close() }()

	select {
	case <-reentered:
		// callback ran and re-entered successfully
	case <-time.After(5 * time.Second):
		t.Fatal("OnError was never invoked from Close")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close deadlocked: OnError re-entry blocked on w.mu")
	}
}

var errTest = &Error{Op: "test", Err: os.ErrDeadlineExceeded}

// TestCompressFile_TmpIsExclusive: the .gz.tmp must be created with O_EXCL so
// a pre-planted symlink at that name cannot be truncated through.
func TestCompressFile_TmpIsExclusive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "src.log")
	if err := os.WriteFile(src, []byte("data\n"), 0600); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(dir, "victim.txt")
	if err := os.WriteFile(victim, []byte("precious\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// Pre-plant the temp name as a symlink to the victim.
	if err := os.Symlink(victim, src+".gz.tmp"); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	compressFile(src, func(error) {})

	data, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "precious\n" {
		t.Fatalf("victim truncated through tmp symlink: %q", data)
	}
	// The planted symlink must not have been replaced by a successful
	// compression either — the source should still exist.
	if _, err := os.Stat(src); err != nil {
		t.Errorf("source removed despite tmp conflict: %v", err)
	}
	// Clean up the planted link so TempDir removal works.
	_ = os.Remove(src + ".gz.tmp")
}

// TestIsBackupName_NanoFallbackTightness: the unix-nano fallback branch
// requires 15+ digits so unrelated <base>.<digits> files (app.log.12345) are
// not treated as rotation artifacts — compressResidual would gzip and DELETE
// them on every startup with Compress enabled by default.
func TestIsBackupName_NanoFallbackTightness(t *testing.T) {
	base := "app.log"
	yes := []string{
		"app.log.1760000000000000000",          // nano fallback
		"app.log.1760000000000000000.3",        // nano + seq
		"app.log.1760000000000000000.gz",       // nano + gz
		"app.log.2026-04-01T00-00-00.000",      // timestamp
		"app.log.2026-04-01T00-00-00.000.2.gz", // timestamp + seq + gz
	}
	no := []string{
		"app.log.12345", // short digit run — NOT a rotation artifact
		"app.log.12345.gz",
		"app.log.notes",
		"app.log.2020-manual",
	}
	for _, n := range yes {
		if !isBackupName(base, n) {
			t.Errorf("isBackupName(%q) = false, want true", n)
		}
	}
	for _, n := range no {
		if isBackupName(base, n) {
			t.Errorf("isBackupName(%q) = true, want false", n)
		}
	}
}
