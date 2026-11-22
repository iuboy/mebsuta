//go:build !windows

package filerotate

import "syscall"

// openNoFollow 在支持 O_NOFOLLOW 的平台上阻止最终路径组件
// 成为符号链接。若只有 O_CREATE 而没有 O_EXCL，悬空
// 符号链接会被跟随并创建目标文件——能写日志目录的
// 攻击者可借此将日志输出（以及轮转重开）
// 重定向到任意文件。
const openNoFollow = syscall.O_NOFOLLOW
