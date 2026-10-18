package underlay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
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

// Factory 的 mark 为零时不设置 SO_MARK；非零时在首次发包前设置。
// 每个实例的目的前缀约束同样覆盖 DNS 解析产生的连接。
type Factory struct {
	mark      uint32
	setter    ControlSetter
	protected []netip.Prefix
}

// NewFactory 创建带 mark 的 socket 工厂。setter 为 nil 时使用真实 SO_MARK。
func NewFactory(mark uint32, setter ControlSetter) *Factory {
	return &Factory{mark: mark, setter: setter}
}

func (f *Factory) control() func(string, string, syscall.RawConn) error {
	if f.setter != nil {
		return ControlWithSetter(f.mark, f.setter)
	}
	return Control(f.mark)
}

// ListenUDP 创建带标记的 UDP socket；mark 设置失败时不出 socket、错误上抛。
func (f *Factory) ListenUDP(ctx context.Context, network, address string) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: f.control()}
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

// DialContext 创建带标记的出站连接；控制回调失败时连接建立失败。
// 解析域名时同样经由带标记的 Resolver，避免 DNS 查询绕过路由标记。
func (f *Factory) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := net.Dialer{Control: f.control(), Resolver: f.Resolver()}
	if len(f.protected) != 0 {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if ip, err := netip.ParseAddr(host); err == nil {
			if err := f.CheckDestination(ip); err != nil {
				return nil, err
			}
		} else {
			ips, err := f.Resolver().LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, addr := range ips {
				ip, ok := netip.AddrFromSlice(addr.IP)
				if !ok {
					return nil, fmt.Errorf("invalid resolved address for %s", host)
				}
				if err := f.CheckDestination(ip); err != nil {
					return nil, err
				}
			}
			var lastErr error
			for _, addr := range ips {
				target := addr.IP.String()
				if addr.Zone != "" {
					target += "%" + addr.Zone
				}
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(target, port))
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			if lastErr == nil {
				lastErr = fmt.Errorf("no resolved addresses for %s", host)
			}
			return nil, lastErr
		}
	}
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("underlay dial failed: %w", err)
	}
	return conn, nil
}

// Resolver 返回强制使用带标记拨号的解析器；PreferGo 保证自定义 Dial 生效，
// 不会经由 cgo 解析路径创建未标记 socket。
func (f *Factory) Resolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return f.DialContext(ctx, network, address)
		},
	}
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
