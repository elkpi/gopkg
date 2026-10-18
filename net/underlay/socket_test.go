package underlay_test

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/elkpi/gopkg/net/underlay"
)

type fakeRawConn struct {
	ControlErr error
	controlled bool
}

func (f *fakeRawConn) Control(fn func(fd uintptr)) error {
	f.controlled = true
	if f.ControlErr != nil {
		return f.ControlErr
	}
	fn(0)
	return nil
}

func (f *fakeRawConn) Read(fn func(uintptr) bool) error  { return os.ErrClosed }
func (f *fakeRawConn) Write(fn func(uintptr) bool) error { return os.ErrClosed }

func TestControlErrorAbortsSocket(t *testing.T) {
	fake := &fakeRawConn{ControlErr: syscall.EPERM}
	control := underlay.ControlWithSetter(7, func(uintptr, uint32) error {
		return syscall.EPERM
	})
	err := control("udp4", "127.0.0.1:0", fake)
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf("隐藏了标记失败：%v", err)
	}
	if !fake.controlled {
		t.Fatal("Control 回调未执行")
	}
}

func TestControlSuccessAppliesMark(t *testing.T) {
	fake := &fakeRawConn{}
	var gotFD uintptr
	var gotValue uint32
	control := underlay.ControlWithSetter(7, func(fd uintptr, value uint32) error {
		gotFD = fd
		gotValue = value
		return nil
	})
	if err := control("udp4", "127.0.0.1:0", fake); err != nil {
		t.Fatal(err)
	}
	if !fake.controlled || gotValue != 7 {
		t.Fatalf("标记参数错误：fd=%d value=%d", gotFD, gotValue)
	}
}

func TestListenUDPBindsWithoutMarkOnLoopback(t *testing.T) {
	conn, err := underlay.ListenUDP(context.Background(), 0, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mark=0 不应请求特权SO_MARK: %v", err)
	}
	conn.Close()
}

func TestListenUDPRejectsBadAddress(t *testing.T) {
	if _, err := underlay.ListenUDP(context.Background(), 0, "udp4", "not-an-address"); err == nil {
		t.Fatal("非法地址被接受")
	}
}

// 保持对 os/syscall 的引用，避免测试文件裁剪时误删依赖。
var (
	_ = os.Getenv
	_ = syscall.EPERM
	_ net.Conn
)
