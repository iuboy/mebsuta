//go:build windows

package filerotate

// Windows has no O_NOFOLLOW; openAppend's pre/post-open inode comparison
// remains the symlink defense there.
const openNoFollow = 0
