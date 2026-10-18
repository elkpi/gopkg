package underlay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

var ErrSocketType = errors.New("listener is not a UDP connection")

// ControlSetter 是可注入的 SO_MARK 设置器，便于测试。
type ControlSetter func(fd uintptr, value uint32) error

// ControlWithSetter 返回 net.ListenConfig.Control 形状的回调；
// setter 失败时套接字创建失败，保证“先标记、后发包”的顺序约束。
func ControlWithSetter(mark uint32, setter ControlSetter) func(string, string, syscall.RawConn) error {
	return func(network, address string, conn syscall.RawConn) error {
		if mark == 0 {
			return nil
		}
		var controlErr error
		err := conn.Control(func(fd uintptr) {
			controlErr = setter(fd, mark)
		})
		if err != nil {
			return fmt.Errorf("socket control callback failed: %w", err)
		}
		if controlErr != nil {
			return fmt.Errorf("failed to set SO_MARK: %w", controlErr)
		}
		return nil
	}
}

// Control 返回使用真实 SO_MARK 的控制回调。
func Control(mark uint32) func(string, string, syscall.RawConn) error {
	return ControlWithSetter(mark, func(fd uintptr, value uint32) error {
		return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(value))
	})
}

// ListenUDP 用带标记的控制回调创建 UDP 套接字。
func ListenUDP(ctx context.Context, mark uint32, network, address string) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: Control(mark)}
	packetConn, err := lc.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("failed to create marked UDP socket: %w", err)
	}
	udp, ok := packetConn.(*net.UDPConn)
	if !ok {
		packetConn.Close()
		return nil, ErrSocketType
	}
	return udp, nil
}
