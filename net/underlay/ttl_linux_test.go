package underlay_test

import (
	"net"
	"testing"
	"time"

	"github.com/elkpi/gopkg/net/underlay"
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
