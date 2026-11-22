//go:build windows

package filerotate

// Windows 没有 O_NOFOLLOW；openAppend 打开前后的 inode 比较
// 在该平台上仍是符号链接防线。
const openNoFollow = 0
