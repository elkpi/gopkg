package underlay_test

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/elkpi/gopkg/net/underlay"
	"golang.org/x/sys/unix"
)

func TestSendUDPWithTTL(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	serverAddr := server.LocalAddr().(*net.UDPAddr)

	payload := []byte("TTL_PACKET_TEST")
	if err := underlay.SendUDPWithTTL(client, payload, serverAddr, 7); err != nil {
		t.Fatalf("SendUDPWithTTL(7) failed: %v", err)
	}

	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1024)
	n, _, err := server.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("ReadFromUDP failed: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("payload mismatch: %s", string(buf[:n]))
	}

	// 零 TTL 使用默认发送
	if err := underlay.SendUDPWithTTL(client, payload, serverAddr, 0); err != nil {
		t.Fatalf("SendUDPWithTTL(0) failed: %v", err)
	}
	n, _, err = server.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("ReadFromUDP with default TTL failed: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("default TTL payload mismatch: %s", string(buf[:n]))
	}
}

func TestSendUDPWithTTLIPv6HopLimit(t *testing.T) {
	server, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("ipv6 loopback unavailable: %v", err)
	}
	defer server.Close()

	raw, err := server.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var optErr error
	if err := raw.Control(func(fd uintptr) {
		optErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVHOPLIMIT, 1)
	}); err != nil || optErr != nil {
		t.Fatalf("enable IPV6_RECVHOPLIMIT: %v %v", err, optErr)
	}

	client, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	payload := []byte("TTL6_PACKET_TEST")
	if err := underlay.SendUDPWithTTL(client, payload, server.LocalAddr().(*net.UDPAddr), 7); err != nil {
		t.Fatalf("SendUDPWithTTL(7) over ipv6 failed: %v", err)
	}

	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 64)
	oob := make([]byte, 128)
	_, oobn, _, _, err := server.ReadMsgUDP(buf, oob)
	if err != nil {
		t.Fatalf("ReadMsgUDP failed: %v", err)
	}
	cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range cmsgs {
		if m.Header.Level == unix.IPPROTO_IPV6 && m.Header.Type == unix.IPV6_HOPLIMIT {
			if got := binary.NativeEndian.Uint32(m.Data); got != 7 {
				t.Fatalf("received hop limit %d, want 7", got)
			}
			return
		}
	}
	t.Fatal("no IPV6_HOPLIMIT control message received")
}
