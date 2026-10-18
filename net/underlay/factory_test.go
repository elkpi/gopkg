package underlay

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
)

func TestFactoryMarkFailurePreventsPackets(t *testing.T) {
	sentinel := errors.New("synthetic mark failure")
	f := NewFactory(1, func(uintptr, uint32) error { return sentinel })
	conn, err := f.ListenUDP(context.Background(), "udp4", "127.0.0.1:0")
	if conn != nil {
		conn.Close()
		t.Fatal("失败后仍创建了 socket")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("错误未传播: %v", err)
	}
	dialConn, err := f.DialContext(context.Background(), "tcp4", "127.0.0.1:1")
	if dialConn != nil {
		dialConn.Close()
		t.Fatal("失败后仍创建了拨号连接")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("拨号错误未传播: %v", err)
	}
}

func TestFactoryDNSUsesMarkedDial(t *testing.T) {
	var calls atomic.Int32
	f := NewFactory(7, func(uintptr, uint32) error { calls.Add(1); return nil })
	resolver := f.Resolver()
	if resolver == nil {
		t.Fatal("Resolver 返回 nil")
	}
	// 直接调用 resolver 的 Dial：控制回调在 socket 创建时执行，
	// 即使目标端口拒绝连接，也能证明标记回调参与了解析器拨号路径。
	_, _ = resolver.Dial(context.Background(), "udp4", "127.0.0.1:1")
	if calls.Load() == 0 {
		t.Fatal("解析器拨号未经过标记控制回调")
	}
}

func TestFactoryNilSetterUsesRealControl(t *testing.T) {
	f := NewFactory(0, nil)
	conn, err := f.ListenUDP(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mark=0 时应允许创建 socket: %v", err)
	}
	conn.Close()
}

func TestDualStackFixedPortAndConflict(t *testing.T) {
	reserve, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(reserve.LocalAddr().(*net.UDPAddr).Port)
	reserve.Close()
	v4Addr := net.JoinHostPort("127.0.0.1", port)
	v6Addr := net.JoinHostPort("::1", port)

	f := NewFactory(0, nil)
	v4, err := f.ListenUDP(context.Background(), "udp4", v4Addr)
	if err != nil {
		t.Fatalf("ipv4 固定端口绑定失败: %v", err)
	}
	defer v4.Close()
	v6, err := f.ListenUDP(context.Background(), "udp6", v6Addr)
	if err != nil {
		t.Fatalf("ipv6 同端口独立绑定失败: %v", err)
	}
	defer v6.Close()

	conflict, err := f.ListenUDP(context.Background(), "udp4", v4Addr)
	if err == nil {
		conflict.Close()
		t.Fatal("端口占用被静默接受")
	}
}
