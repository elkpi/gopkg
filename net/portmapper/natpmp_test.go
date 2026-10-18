package portmapper

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

func startMockNATPMPGateway(t *testing.T) (*net.UDPConn, net.IP, int) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen mock nat-pmp: %v", err)
	}

	addr := conn.LocalAddr().(*net.UDPAddr)

	go func() {
		buf := make([]byte, 128)
		for {
			n, remoteAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 2 {
				continue
			}
			op := buf[1]
			switch op {
			case natpmpOpExternalIP:
				resp := make([]byte, 12)
				resp[0] = 0
				resp[1] = natpmpRespOpExternalIP
				binary.BigEndian.PutUint16(resp[2:4], 0)    // success
				binary.BigEndian.PutUint32(resp[4:8], 1000) // epoch
				copy(resp[8:12], net.ParseIP("203.0.113.1").To4())
				_, _ = conn.WriteToUDP(resp, remoteAddr)

			case natpmpOpMapTCP, natpmpOpMapUDP:
				if n < 12 {
					continue
				}
				internalPort := binary.BigEndian.Uint16(buf[4:6])
				prefExtPort := binary.BigEndian.Uint16(buf[6:8])
				lifetime := binary.BigEndian.Uint32(buf[8:12])

				resp := make([]byte, 16)
				resp[0] = 0
				resp[1] = op + 128
				binary.BigEndian.PutUint16(resp[2:4], 0) // success
				binary.BigEndian.PutUint32(resp[4:8], 1000)
				binary.BigEndian.PutUint16(resp[8:10], internalPort)
				if prefExtPort == 0 {
					binary.BigEndian.PutUint16(resp[10:12], internalPort)
				} else {
					binary.BigEndian.PutUint16(resp[10:12], prefExtPort)
				}
				binary.BigEndian.PutUint32(resp[12:16], lifetime)
				_, _ = conn.WriteToUDP(resp, remoteAddr)
			}
		}
	}()

	return conn, addr.IP, addr.Port
}

func TestNATPMP_Unit(t *testing.T) {
	conn, ip, port := startMockNATPMPGateway(t)
	defer conn.Close()

	client, err := NewNATPMPClientWithPort(ip, port)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	if client.Provider() != ProviderNATPMP {
		t.Errorf("expected provider %v, got %v", ProviderNATPMP, client.Provider())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// 1. 获取公网 IP 测试
	extIP, err := client.GetExternalIP(ctx)
	if err != nil {
		t.Fatalf("GetExternalIP failed: %v", err)
	}
	if expected := "203.0.113.1"; extIP.String() != expected {
		t.Errorf("expected external IP %s, got %s", expected, extIP)
	}

	// 2. TCP 端口映射测试
	tcpMap, err := client.AddPortMapping(ctx, ProtocolTCP, 8080, 8080, 1*time.Hour)
	if err != nil {
		t.Fatalf("AddPortMapping TCP failed: %v", err)
	}
	if tcpMap.ExternalPort != 8080 {
		t.Errorf("expected external port 8080, got %d", tcpMap.ExternalPort)
	}
	if tcpMap.InternalPort != 8080 {
		t.Errorf("expected internal port 8080, got %d", tcpMap.InternalPort)
	}
	if tcpMap.Lifetime != 1*time.Hour {
		t.Errorf("expected lifetime 1h, got %v", tcpMap.Lifetime)
	}

	// 3. UDP 端口映射测试
	udpMap, err := client.AddPortMapping(ctx, ProtocolUDP, 9000, 9000, 30*time.Minute)
	if err != nil {
		t.Fatalf("AddPortMapping UDP failed: %v", err)
	}
	if udpMap.ExternalPort != 9000 {
		t.Errorf("expected external port 9000, got %d", udpMap.ExternalPort)
	}

	// 4. 删除映射测试
	if err := client.DeletePortMapping(ctx, tcpMap); err != nil {
		t.Fatalf("DeletePortMapping failed: %v", err)
	}

	// 5. 不支持的协议
	_, err = client.AddPortMapping(ctx, Protocol("SCTP"), 8080, 8080, time.Hour)
	if !errors.Is(err, ErrUnsupportedProtocol) {
		t.Errorf("expected ErrUnsupportedProtocol, got %v", err)
	}
}

func TestNATPMP_Errors(t *testing.T) {
	// 测试状态码解析
	tests := []struct {
		code uint16
		err  error
	}{
		{0, nil},
		{1, ErrUnsupportedVersion},
		{2, ErrNotAuthorized},
		{3, ErrGatewayNetworkFailure},
		{4, ErrNoResources},
		{5, ErrUnsupportedProtocol},
	}

	for _, tt := range tests {
		err := parseNATPMPResultCode(tt.code)
		if tt.err == nil {
			if err != nil {
				t.Errorf("code %d: expected nil error, got %v", tt.code, err)
			}
		} else {
			if !errors.Is(err, tt.err) {
				t.Errorf("code %d: expected %v, got %v", tt.code, tt.err, err)
			}
		}
	}
}
