package portmapper

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	// NATPMPPort 为 NAT-PMP 标准网关 UDP 监听端口。
	NATPMPPort = 5351

	natpmpVersion = 0

	natpmpOpExternalIP = 0
	natpmpOpMapUDP     = 1
	natpmpOpMapTCP     = 2

	natpmpRespOpExternalIP = 128
	natpmpRespOpMapUDP     = 129
	natpmpRespOpMapTCP     = 130
)

// NATPMPClient 实现了 RFC 6886 NAT-PMP 协议客户端。
type NATPMPClient struct {
	gatewayIP net.IP
	port      int
	mu        sync.Mutex
	conn      *net.UDPConn
}

// NewNATPMPClient 创建针对指定网关的 NAT-PMP 客户端（默认使用 5351 端口）。
func NewNATPMPClient(gatewayIP net.IP) (*NATPMPClient, error) {
	return NewNATPMPClientWithPort(gatewayIP, NATPMPPort)
}

// NewNATPMPClientWithPort 创建针对指定网关与端口的 NAT-PMP 客户端。
func NewNATPMPClientWithPort(gatewayIP net.IP, port int) (*NATPMPClient, error) {
	if gatewayIP == nil {
		return nil, ErrNoGatewayFound
	}
	if port <= 0 {
		port = NATPMPPort
	}
	return &NATPMPClient{
		gatewayIP: gatewayIP,
		port:      port,
	}, nil
}

// Provider 返回提供者类型。
func (c *NATPMPClient) Provider() Provider {
	return ProviderNATPMP
}

// Close 释放客户端资源。
func (c *NATPMPClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		return err
	}
	return nil
}

func parseNATPMPResultCode(code uint16) error {
	switch code {
	case 0:
		return nil
	case 1:
		return fmt.Errorf("%w: unsupported NAT-PMP version (code 1)", ErrUnsupportedVersion)
	case 2:
		return fmt.Errorf("%w: not authorized/refused (code 2)", ErrNotAuthorized)
	case 3:
		return fmt.Errorf("%w: network failure (code 3)", ErrGatewayNetworkFailure)
	case 4:
		return fmt.Errorf("%w: out of resources (code 4)", ErrNoResources)
	case 5:
		return fmt.Errorf("%w: unsupported opcode (code 5)", ErrUnsupportedProtocol)
	default:
		return fmt.Errorf("%w: unknown NAT-PMP error code %d", ErrMappingFailed, code)
	}
}

func (c *NATPMPClient) sendAndRecv(ctx context.Context, req []byte, expectedRespOp byte, minRespLen int) ([]byte, error) {
	gwAddr := &net.UDPAddr{
		IP:   c.gatewayIP,
		Port: c.port,
	}

	conn, err := net.DialUDP("udp", nil, gwAddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 重传控制：初始间隔 250ms，指数递增至 1s
	retryInterval := 250 * time.Millisecond
	maxRetries := 3

	respBuf := make([]byte, 64)

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
			if respBuf[0] != natpmpVersion {
				return nil, fmt.Errorf("%w: version %d mismatch", ErrUnsupportedVersion, respBuf[0])
			}
			if respBuf[1] != expectedRespOp {
				return nil, fmt.Errorf("%w: opcode %d mismatch, expected %d", ErrMalformedResponse, respBuf[1], expectedRespOp)
			}
			resultCode := binary.BigEndian.Uint16(respBuf[2:4])
			if err := parseNATPMPResultCode(resultCode); err != nil {
				return nil, err
			}
			res := make([]byte, n)
			copy(res, respBuf[:n])
			return res, nil
		}

		// 若已超时且上下文未取消，则指数退避后重试
		retryInterval *= 2
		if retryInterval > 1000*time.Millisecond {
			retryInterval = 1000 * time.Millisecond
		}
	}

	return nil, fmt.Errorf("%w: gateway %s timeout", ErrMappingFailed, c.gatewayIP)
}

// GetExternalIP 获取网关的外部公网 IPv4 地址。
func (c *NATPMPClient) GetExternalIP(ctx context.Context) (net.IP, error) {
	req := []byte{natpmpVersion, natpmpOpExternalIP}
	resp, err := c.sendAndRecv(ctx, req, natpmpRespOpExternalIP, 12)
	if err != nil {
		return nil, err
	}

	ip := net.IPv4(resp[8], resp[9], resp[10], resp[11])
	if ip == nil || ip.IsUnspecified() {
		return nil, fmt.Errorf("%w: empty external IP in response", ErrMalformedResponse)
	}
	return ip, nil
}

// AddPortMapping 请求端口映射（支持 TCP/UDP）。
func (c *NATPMPClient) AddPortMapping(ctx context.Context, proto Protocol, internalPort int, preferredExternal int, lifetime time.Duration) (*Mapping, error) {
	var op byte
	var expectedRespOp byte
	switch proto {
	case ProtocolTCP:
		op = natpmpOpMapTCP
		expectedRespOp = natpmpRespOpMapTCP
	case ProtocolUDP:
		op = natpmpOpMapUDP
		expectedRespOp = natpmpRespOpMapUDP
	default:
		return nil, ErrUnsupportedProtocol
	}

	req := make([]byte, 12)
	req[0] = natpmpVersion
	req[1] = op
	// req[2:4] reserved = 0
	binary.BigEndian.PutUint16(req[4:6], uint16(internalPort))
	binary.BigEndian.PutUint16(req[6:8], uint16(preferredExternal))
	binary.BigEndian.PutUint32(req[8:12], uint32(lifetime.Seconds()))

	resp, err := c.sendAndRecv(ctx, req, expectedRespOp, 16)
	if err != nil {
		return nil, err
	}

	mappedExternal := int(binary.BigEndian.Uint16(resp[10:12]))
	grantedLifetime := time.Duration(binary.BigEndian.Uint32(resp[12:16])) * time.Second

	// 异步尝试获取外部公网 IP（非致命）
	extIP, _ := c.GetExternalIP(ctx)

	return &Mapping{
		client:       c,
		Protocol:     proto,
		InternalPort: internalPort,
		ExternalPort: mappedExternal,
		ExternalIP:   extIP,
		Lifetime:     grantedLifetime,
		CreatedAt:    time.Now(),
		Provider:     ProviderNATPMP,
	}, nil
}

// RenewMapping 以原内外端口重新请求映射（NAT-PMP 无 nonce 概念）。
func (c *NATPMPClient) RenewMapping(ctx context.Context, m *Mapping, lifetime time.Duration) (*Mapping, error) {
	return c.AddPortMapping(ctx, m.Protocol, m.InternalPort, m.ExternalPort, lifetime)
}

// DeletePortMapping 删除指定的端口映射（Lifetime 置 0）。
func (c *NATPMPClient) DeletePortMapping(ctx context.Context, m *Mapping) error {
	var op byte
	var expectedRespOp byte
	switch m.Protocol {
	case ProtocolTCP:
		op = natpmpOpMapTCP
		expectedRespOp = natpmpRespOpMapTCP
	case ProtocolUDP:
		op = natpmpOpMapUDP
		expectedRespOp = natpmpRespOpMapUDP
	default:
		return ErrUnsupportedProtocol
	}

	req := make([]byte, 12)
	req[0] = natpmpVersion
	req[1] = op
	// req[2:4] reserved = 0
	binary.BigEndian.PutUint16(req[4:6], uint16(m.InternalPort))
	binary.BigEndian.PutUint16(req[6:8], 0)
	binary.BigEndian.PutUint32(req[8:12], 0)

	_, err := c.sendAndRecv(ctx, req, expectedRespOp, 16)
	return err
}
