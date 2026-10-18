package portmapper

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	// PCPPort 为 PCP 标准网关 UDP 监听端口。
	PCPPort = 5351

	pcpVersion = 2

	pcpOpcodeAnnounce = 0
	pcpOpcodeMap      = 1
	pcpOpcodePeer     = 2

	pcpRespMask = 0x80

	pcpProtocolTCP = 6
	pcpProtocolUDP = 17
)

// PCPClient 实现了 RFC 6887 PCP 协议客户端。
type PCPClient struct {
	gatewayIP net.IP
	clientIP  net.IP
	port      int
	mu        sync.Mutex
	conn      *net.UDPConn
}

// NewPCPClient 创建针对指定网关的 PCP 客户端。
func NewPCPClient(gatewayIP net.IP) (*PCPClient, error) {
	return NewPCPClientWithPort(gatewayIP, nil, PCPPort)
}

// NewPCPClientWithPort 创建针对指定网关与端口的 PCP 客户端。
func NewPCPClientWithPort(gatewayIP net.IP, clientIP net.IP, port int) (*PCPClient, error) {
	if gatewayIP == nil {
		return nil, ErrNoGatewayFound
	}
	if port <= 0 {
		port = PCPPort
	}
	return &PCPClient{
		gatewayIP: gatewayIP,
		clientIP:  clientIP,
		port:      port,
	}, nil
}

// Provider 返回提供者类型。
func (c *PCPClient) Provider() Provider {
	return ProviderPCP
}

// Close 释放客户端资源。
func (c *PCPClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		return err
	}
	return nil
}

func parsePCPResultCode(code uint8) error {
	switch code {
	case 0:
		return nil
	case 1:
		return fmt.Errorf("%w: unsupported PCP version (code 1)", ErrUnsupportedVersion)
	case 2:
		return fmt.Errorf("%w: not authorized by PCP gateway (code 2)", ErrNotAuthorized)
	case 3:
		return fmt.Errorf("%w: malformed PCP request (code 3)", ErrMalformedResponse)
	case 4:
		return fmt.Errorf("%w: unsupported PCP opcode (code 4)", ErrUnsupportedProtocol)
	case 5, 6:
		return fmt.Errorf("%w: PCP option error (code %d)", ErrMalformedResponse, code)
	case 7:
		return fmt.Errorf("%w: PCP gateway network failure (code 7)", ErrGatewayNetworkFailure)
	case 8:
		return fmt.Errorf("%w: PCP gateway out of resources (code 8)", ErrNoResources)
	case 9:
		return fmt.Errorf("%w: unsupported protocol in PCP (code 9)", ErrUnsupportedProtocol)
	case 10:
		return fmt.Errorf("%w: user quota exceeded (code 10)", ErrNoResources)
	case 11:
		return fmt.Errorf("%w: cannot provide external port/IP (code 11)", ErrMappingFailed)
	case 12:
		return fmt.Errorf("%w: address mismatch (code 12)", ErrNotAuthorized)
	default:
		return fmt.Errorf("%w: unknown PCP result code %d", ErrMappingFailed, code)
	}
}

func toPCPAddress(ip net.IP) [16]byte {
	var res [16]byte
	if ip == nil {
		return res
	}
	ip16 := ip.To16()
	if ip16 != nil {
		copy(res[:], ip16)
	}
	return res
}

func fromPCPAddress(b []byte) net.IP {
	if len(b) < 16 {
		return nil
	}
	ip := net.IP(b)
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	return ip
}

func (c *PCPClient) getClientIP() (net.IP, error) {
	if c.clientIP != nil && !c.clientIP.IsUnspecified() {
		return c.clientIP, nil
	}
	ip, err := FindOutboundIP(c.gatewayIP)
	if err != nil {
		return nil, err
	}
	c.clientIP = ip
	return ip, nil
}

func (c *PCPClient) sendAndRecv(ctx context.Context, req []byte, expectedOpcode byte, minRespLen int) ([]byte, error) {
	gwAddr := &net.UDPAddr{
		IP:   c.gatewayIP,
		Port: c.port,
	}

	conn, err := net.DialUDP("udp", nil, gwAddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	retryInterval := 250 * time.Millisecond
	maxRetries := 3

	respBuf := make([]byte, 128)

	for attempt := 0; attempt <= maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if _, err := conn.Write(req); err != nil {
			return nil, err
		}

		deadline := time.Now().Add(retryInterval)
		if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		_ = conn.SetReadDeadline(deadline)

		n, err := conn.Read(respBuf)
		if err == nil {
			if n < minRespLen {
				return nil, fmt.Errorf("%w: response length %d less than expected %d", ErrMalformedResponse, n, minRespLen)
			}
			if respBuf[0] != pcpVersion {
				return nil, fmt.Errorf("%w: PCP version %d mismatch", ErrUnsupportedVersion, respBuf[0])
			}
			expectedRespOp := expectedOpcode | pcpRespMask
			if respBuf[1] != expectedRespOp {
				return nil, fmt.Errorf("%w: opcode %d mismatch, expected %d", ErrMalformedResponse, respBuf[1], expectedRespOp)
			}
			resultCode := respBuf[3]
			if err := parsePCPResultCode(resultCode); err != nil {
				return nil, err
			}
			res := make([]byte, n)
			copy(res, respBuf[:n])
			return res, nil
		}

		retryInterval *= 2
		if retryInterval > 1000*time.Millisecond {
			retryInterval = 1000 * time.Millisecond
		}
	}

	return nil, fmt.Errorf("%w: PCP gateway %s timeout", ErrMappingFailed, c.gatewayIP)
}

// AddPortMapping 请求 PCP 端口映射（MAP OpCode）。
func (c *PCPClient) AddPortMapping(ctx context.Context, proto Protocol, internalPort int, preferredExternal int, lifetime time.Duration) (*Mapping, error) {
	var ianaProto byte
	switch proto {
	case ProtocolTCP:
		ianaProto = pcpProtocolTCP
	case ProtocolUDP:
		ianaProto = pcpProtocolUDP
	default:
		return nil, ErrUnsupportedProtocol
	}

	clientIP, err := c.getClientIP()
	if err != nil {
		return nil, err
	}

	// 报文结构：24 字节 Header + 36 字节 MAP Payload = 60 字节
	req := make([]byte, 60)
	req[0] = pcpVersion
	req[1] = pcpOpcodeMap
	// req[2:4] Reserved
	binary.BigEndian.PutUint32(req[4:8], uint32(lifetime.Seconds()))
	clientIPBytes := toPCPAddress(clientIP)
	copy(req[8:24], clientIPBytes[:])

	// MAP Payload
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	copy(req[24:36], nonce[:])
	req[36] = ianaProto
	// req[37:40] Reserved
	binary.BigEndian.PutUint16(req[40:42], uint16(internalPort))
	binary.BigEndian.PutUint16(req[42:44], uint16(preferredExternal))
	// req[44:60] Suggested External IP (默认全 0)

	resp, err := c.sendAndRecv(ctx, req, pcpOpcodeMap, 60)
	if err != nil {
		return nil, err
	}

	grantedLifetime := time.Duration(binary.BigEndian.Uint32(resp[4:8])) * time.Second
	assignedExternalPort := int(binary.BigEndian.Uint16(resp[42:44]))
	assignedExternalIP := fromPCPAddress(resp[44:60])

	return &Mapping{
		client:       c,
		Protocol:     proto,
		InternalPort: internalPort,
		ExternalPort: assignedExternalPort,
		ExternalIP:   assignedExternalIP,
		Lifetime:     grantedLifetime,
		CreatedAt:    time.Now(),
		Provider:     ProviderPCP,
		nonce:        nonce,
	}, nil
}

// DeletePortMapping 删除 PCP 端口映射（Lifetime = 0，复用相同 Nonce）。
func (c *PCPClient) DeletePortMapping(ctx context.Context, m *Mapping) error {
	var ianaProto byte
	switch m.Protocol {
	case ProtocolTCP:
		ianaProto = pcpProtocolTCP
	case ProtocolUDP:
		ianaProto = pcpProtocolUDP
	default:
		return ErrUnsupportedProtocol
	}

	clientIP, err := c.getClientIP()
	if err != nil {
		return err
	}

	req := make([]byte, 60)
	req[0] = pcpVersion
	req[1] = pcpOpcodeMap
	binary.BigEndian.PutUint32(req[4:8], 0) // Lifetime = 0
	clientIPBytes := toPCPAddress(clientIP)
	copy(req[8:24], clientIPBytes[:])

	// 必须使用相同的 Nonce
	copy(req[24:36], m.nonce[:])
	req[36] = ianaProto
	binary.BigEndian.PutUint16(req[40:42], uint16(m.InternalPort))
	binary.BigEndian.PutUint16(req[42:44], uint16(m.ExternalPort))

	_, err = c.sendAndRecv(ctx, req, pcpOpcodeMap, 60)
	return err
}

// GetExternalIP 通过 ANNOUNCE 探测网关并获取其外部 IP。
// ANNOUNCE 无任何映射副作用；不可使用零租期 MAP 代替，
// 那是对既有映射的删除语义（RFC 6887 §10、§11.2）。
func (c *PCPClient) GetExternalIP(ctx context.Context) (net.IP, error) {
	req := make([]byte, 60)
	req[0] = pcpVersion
	req[1] = pcpOpcodeAnnounce

	resp, err := c.sendAndRecv(ctx, req, pcpOpcodeAnnounce, 60)
	if err != nil {
		return nil, err
	}

	extIP := fromPCPAddress(resp[44:60])
	if extIP == nil || extIP.IsUnspecified() {
		return nil, fmt.Errorf("%w: unspecified external IP in PCP response", ErrMalformedResponse)
	}
	return extIP, nil
}
