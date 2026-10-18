package portmapper

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func startMockPCPGateway(t *testing.T) (*net.UDPConn, net.IP, int) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen mock pcp: %v", err)
	}

	addr := conn.LocalAddr().(*net.UDPAddr)

	go func() {
		buf := make([]byte, 256)
		for {
			n, remoteAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 60 {
				continue
			}

			version := buf[0]
			opcode := buf[1]
			if version != 2 || opcode != 1 { // MAP
				// ANNOUNCE 探测：零副作用返回外部 IP
				if version == 2 && opcode == 0 && n >= 60 {
					resp := make([]byte, 60)
					resp[0] = 2
					resp[1] = 0x80
					copy(resp[44:60], net.ParseIP("198.51.100.1").To16())
					_, _ = conn.WriteToUDP(resp, remoteAddr)
				}
				continue
			}

			lifetime := binary.BigEndian.Uint32(buf[4:8])
			var nonce [12]byte
			copy(nonce[:], buf[24:36])
			proto := buf[36]
			internalPort := binary.BigEndian.Uint16(buf[40:42])
			suggestedExtPort := binary.BigEndian.Uint16(buf[42:44])

			// 组装 60 字节的 PCP MAP 响应
			resp := make([]byte, 60)
			resp[0] = 2
			resp[1] = 1 | 0x80 // 0x81
			resp[2] = 0        // Reserved
			resp[3] = 0        // Result Code: SUCCESS
			binary.BigEndian.PutUint32(resp[4:8], lifetime)
			binary.BigEndian.PutUint32(resp[8:12], 2000) // Epoch Time
			// resp[12:24] Reserved 12 bytes

			// MAP Payload
			copy(resp[24:36], nonce[:])
			resp[36] = proto
			// resp[37:40] Reserved
			binary.BigEndian.PutUint16(resp[40:42], internalPort)
			if suggestedExtPort == 0 {
				binary.BigEndian.PutUint16(resp[42:44], internalPort)
			} else {
				binary.BigEndian.PutUint16(resp[42:44], suggestedExtPort)
			}

			// Assigned External IP: 198.51.100.1
			extIP := net.ParseIP("198.51.100.1")
			copy(resp[44:60], extIP.To16())

			_, _ = conn.WriteToUDP(resp, remoteAddr)
		}
	}()

	return conn, addr.IP, addr.Port
}

func TestPCP_Unit(t *testing.T) {
	conn, ip, port := startMockPCPGateway(t)
	defer conn.Close()

	clientIP := net.ParseIP("127.0.0.1")
	client, err := NewPCPClientWithPort(ip, clientIP, port)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	if client.Provider() != ProviderPCP {
		t.Errorf("expected provider %v, got %v", ProviderPCP, client.Provider())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// 1. 获取公网 IP
	extIP, err := client.GetExternalIP(ctx)
	if err != nil {
		t.Fatalf("GetExternalIP failed: %v", err)
	}
	if expected := "198.51.100.1"; extIP.String() != expected {
		t.Errorf("expected external IP %s, got %s", expected, extIP)
	}

	// 2. TCP 端口映射
	tcpMap, err := client.AddPortMapping(ctx, ProtocolTCP, 8080, 8080, 1*time.Hour)
	if err != nil {
		t.Fatalf("AddPortMapping TCP failed: %v", err)
	}
	if tcpMap.ExternalPort != 8080 {
		t.Errorf("expected external port 8080, got %d", tcpMap.ExternalPort)
	}
	if tcpMap.Lifetime != 1*time.Hour {
		t.Errorf("expected lifetime 1h, got %v", tcpMap.Lifetime)
	}
	if tcpMap.Provider != ProviderPCP {
		t.Errorf("expected provider PCP, got %v", tcpMap.Provider)
	}

	// 3. UDP 端口映射
	udpMap, err := client.AddPortMapping(ctx, ProtocolUDP, 9000, 9000, 30*time.Minute)
	if err != nil {
		t.Fatalf("AddPortMapping UDP failed: %v", err)
	}
	if udpMap.ExternalPort != 9000 {
		t.Errorf("expected external port 9000, got %d", udpMap.ExternalPort)
	}

	// 4. 删除端口映射
	if err := client.DeletePortMapping(ctx, tcpMap); err != nil {
		t.Fatalf("DeletePortMapping failed: %v", err)
	}
}

func TestPCP_AddressConversion(t *testing.T) {
	ip4 := net.ParseIP("192.168.1.100")
	addr := toPCPAddress(ip4)
	back := fromPCPAddress(addr[:])
	if !back.Equal(ip4) {
		t.Errorf("address roundtrip failed: got %v, expected %v", back, ip4)
	}

	ip6 := net.ParseIP("2001:db8::1")
	addr6 := toPCPAddress(ip6)
	back6 := fromPCPAddress(addr6[:])
	if !back6.Equal(ip6) {
		t.Errorf("IPv6 roundtrip failed: got %v, expected %v", back6, ip6)
	}
}

func TestPCP_Errors(t *testing.T) {
	tests := []struct {
		code uint8
		err  error
	}{
		{0, nil},
		{1, ErrUnsupportedVersion},
		{2, ErrNotAuthorized},
		{3, ErrMalformedResponse},
		{4, ErrUnsupportedProtocol},
		{7, ErrGatewayNetworkFailure},
		{8, ErrNoResources},
		{9, ErrUnsupportedProtocol},
		{11, ErrMappingFailed},
	}

	for _, tt := range tests {
		err := parsePCPResultCode(tt.code)
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

// startStrictPCPGateway 模拟按 RFC 6887 §11.3/§11.4 严格校验 nonce 的网关：
// 对已存在的映射，续租请求必须携带创建时的 nonce，否则返回 NOT_AUTHORIZED。
func startStrictPCPGateway(t *testing.T) (net.IP, int) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	var mu sync.Mutex
	byInternal := map[uint16][12]byte{}

	go func() {
		buf := make([]byte, 256)
		for {
			n, remote, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 60 || buf[0] != pcpVersion || buf[1] != pcpOpcodeMap {
				continue
			}
			internal := binary.BigEndian.Uint16(buf[40:42])
			var nonce [12]byte
			copy(nonce[:], buf[24:36])

			resp := make([]byte, 60)
			resp[0] = pcpVersion
			resp[1] = pcpOpcodeMap | pcpRespMask
			copy(resp[24:44], buf[24:44])
			copy(resp[44:60], net.IPv4(203, 0, 113, 7).To16())

			mu.Lock()
			known, exists := byInternal[internal]
			mu.Unlock()
			if exists && known != nonce {
				resp[3] = 2 // NOT_AUTHORIZED
			} else {
				binary.BigEndian.PutUint32(resp[4:8], binary.BigEndian.Uint32(buf[4:8]))
				if binary.BigEndian.Uint32(buf[4:8]) > 0 {
					mu.Lock()
					byInternal[internal] = nonce
					mu.Unlock()
				} else {
					mu.Lock()
					delete(byInternal, internal)
					mu.Unlock()
				}
			}
			_, _ = conn.WriteToUDP(resp, remote)
		}
	}()

	return net.IPv4(127, 0, 0, 1), conn.LocalAddr().(*net.UDPAddr).Port
}

func TestPCPRenewReusesOriginalNonce(t *testing.T) {
	ip, port := startStrictPCPGateway(t)
	client, err := NewPCPClientWithPort(ip, ip, port)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	m, err := client.AddPortMapping(ctx, ProtocolTCP, 12345, 12345, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Renew(ctx, 2*time.Hour); err != nil {
		t.Fatalf("严格网关应接受复用原 nonce 的续租：%v", err)
	}
	if err := client.DeletePortMapping(ctx, m); err != nil {
		t.Fatalf("续租后应仍能以原 nonce 释放：%v", err)
	}
}

func TestPCPRejectsMismatchedResponseNonce(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	port := conn.LocalAddr().(*net.UDPAddr).Port

	go func() {
		buf := make([]byte, 256)
		for {
			n, remote, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 60 || buf[0] != pcpVersion || buf[1] != pcpOpcodeMap {
				continue
			}
			resp := make([]byte, 60)
			copy(resp, buf[:n])
			resp[1] |= pcpRespMask
			resp[3] = 0
			resp[24] ^= 0xff // 篡改响应 nonce
			copy(resp[44:60], net.IPv4(203, 0, 113, 7).To16())
			_, _ = conn.WriteToUDP(resp, remote)
		}
	}()

	client, _ := NewPCPClientWithPort(net.IPv4(127, 0, 0, 1), net.IPv4(127, 0, 0, 1), port)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	m, err := client.AddPortMapping(ctx, ProtocolTCP, 12345, 12345, time.Hour)
	if err == nil {
		t.Fatalf("接受了 nonce 与请求不符的响应：%+v", m)
	}
}

func TestPCPProbeUsesAnnounce(t *testing.T) {
	var zeroLifetimeMaps atomic.Int32
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	port := conn.LocalAddr().(*net.UDPAddr).Port

	go func() {
		buf := make([]byte, 256)
		for {
			n, remote, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 12 || buf[0] != pcpVersion {
				continue
			}
			var resp []byte
			switch buf[1] {
			case pcpOpcodeAnnounce: // ANNOUNCE 探测：零副作用返回外部 IP
				resp = make([]byte, 60)
				resp[1] = pcpOpcodeAnnounce | pcpRespMask
				copy(resp[44:60], net.IPv4(203, 0, 113, 7).To16())
			case pcpOpcodeMap:
				if binary.BigEndian.Uint32(buf[4:8]) == 0 {
					zeroLifetimeMaps.Add(1) // 不应出现：探测不允许携带删除语义
					continue
				}
				resp = make([]byte, 60)
				resp[1] = pcpOpcodeMap | pcpRespMask
				copy(resp[24:44], buf[24:44])
				binary.BigEndian.PutUint32(resp[4:8], 3600)
				copy(resp[44:60], net.IPv4(203, 0, 113, 7).To16())
			default:
				continue
			}
			resp[0] = pcpVersion
			_, _ = conn.WriteToUDP(resp, remote)
		}
	}()

	cfg := DefaultConfig()
	cfg.GatewayIP = net.IPv4(127, 0, 0, 1)
	cfg.LocalIP = cfg.GatewayIP
	cfg.PCPPort = port
	cfg.ProbeTimeout = 300 * time.Millisecond
	cfg.PreferredProviders = []Provider{ProviderPCP}
	pm, _ := New(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	m, err := pm.Discover(ctx, 12345, 12345)
	if err != nil {
		t.Fatalf("支持正常 MAP 的网关应被探测接受：%v", err)
	}
	if got := zeroLifetimeMaps.Load(); got != 0 {
		t.Fatalf("探测阶段发出了 %d 个零租期 MAP（删除语义）请求", got)
	}
	if m.Provider != ProviderPCP || m.ExternalPort != 12345 {
		t.Fatalf("映射结果异常：%+v", m)
	}
}
