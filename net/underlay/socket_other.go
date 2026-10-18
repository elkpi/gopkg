//go:build !linux

package underlay

import (
	"errors"
	"syscall"
)

// errSOMarkUnsupported 标记当前平台不支持 SO_MARK 路由标记。
var errSOMarkUnsupported = errors.New("underlay: SO_MARK is not supported on this platform")

// Control 返回当前平台的 SO_MARK 控制回调。
// 非 Linux 平台 mark 为零时放行（不设置任何选项），非零时创建即失败，
// 避免出现未标记的 socket 静默建连。
func Control(mark uint32) func(string, string, syscall.RawConn) error {
	return ControlWithSetter(mark, func(uintptr, uint32) error {
		return errSOMarkUnsupported
	})
}
