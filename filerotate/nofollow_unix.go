//go:build !windows

package filerotate

import "syscall"

// openNoFollow prevents the final path component from being a symlink on
// platforms that support O_NOFOLLOW. With O_CREATE and without O_EXCL, a
// dangling symlink would otherwise be followed and the target file created —
// an attacker with write access to the log directory could redirect log
// output (and rotation re-opens) to an arbitrary file.
const openNoFollow = syscall.O_NOFOLLOW
