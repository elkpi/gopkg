//go:build linux

package underlay

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// Control 返回使用真实 SO_MARK 的控制回调。
func Control(mark uint32) func(string, string, syscall.RawConn) error {
	return ControlWithSetter(mark, func(fd uintptr, value uint32) error {
		return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(value))
	})
}
