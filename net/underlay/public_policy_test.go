package underlay_test

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/elkpi/gopkg/net/underlay"
	"golang.org/x/sys/unix"
)

func TestZeroMarkSkipsSetter(t *testing.T) {
	var calls atomic.Int32
	factory := underlay.NewFactory(0, func(uintptr, uint32) error { calls.Add(1); return errors.New("不应调用 SO_MARK setter") })
	if factory.Mark() != 0 {
		t.Fatal("公网工厂 mark 非零")
	}
	socket, err := factory.ListenUDP(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	raw, err := socket.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var actual int
	var getErr error
	if err := raw.Control(func(fd uintptr) { actual, getErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK) }); err != nil {
		t.Fatal(err)
	}
	if getErr != nil {
		t.Fatal(getErr)
	}
	if calls.Load() != 0 || actual != 0 {
		t.Fatalf("calls=%d actual mark=%d", calls.Load(), actual)
	}
}

func TestPublicTargetOverlapsOverlayRejected(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("10.254.0.2/32")}
	factory := underlay.NewFactory(0, nil).WithProtectedNetworks(prefixes)
	prefixes[0] = netip.MustParsePrefix("192.0.2.0/24")
	for _, text := range []string{"198.51.100.1", "10.254.0.2"} {
		if err := factory.CheckDestination(netip.MustParseAddr(text)); !errors.Is(err, underlay.ErrProtectedDestination) {
			t.Fatalf("未拒绝受保护目标 %s: %v", text, err)
		}
	}
	if err := factory.CheckDestination(netip.MustParseAddr("203.0.113.1")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if c, err := factory.DialContext(ctx, "tcp", "198.51.100.1:7000"); !errors.Is(err, underlay.ErrProtectedDestination) {
		if c != nil {
			c.Close()
		}
		t.Fatalf("拨号前未拒绝受保护目标: %v", err)
	}
}
