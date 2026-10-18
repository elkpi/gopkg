package portmapper

import (
	"context"
	"errors"
	"net"
	"time"
)

// DiscoverDefaultGateway 尝试自动探测系统的缺省网关 IP。
func DiscoverDefaultGateway() (net.IP, error) {
	gw, err := discoverGateway()
	if err == nil && gw != nil && !gw.IsUnspecified() {
		return gw, nil
	}
	return nil, ErrNoGatewayFound
}

// FindOutboundIP 返回本机路由到指定目标 IP 时所使用的本地内网 IP。
func FindOutboundIP(target net.IP) (net.IP, error) {
	if target == nil {
		return nil, errors.New("target IP cannot be nil")
	}

	targetAddr := &net.UDPAddr{
		IP:   target,
		Port: 53,
	}

	conn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || localAddr.IP == nil {
		return nil, errors.New("unable to determine local UDP IP")
	}

	return localAddr.IP, nil
}

// FindLocalIP 返回本机的局域网主要 IPv4 地址。
func FindLocalIP() (net.IP, error) {
	// 尝试向外部公共 DNS 建立虚拟连接以获取出口接口 IP
	for _, targetStr := range []string{"223.5.5.5:53", "8.8.8.8:53", "1.1.1.1:53"} {
		var d net.Dialer
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		conn, err := d.DialContext(ctx, "udp", targetStr)
		cancel()
		if err == nil {
			defer conn.Close()
			if uaddr, ok := conn.LocalAddr().(*net.UDPAddr); ok && uaddr.IP != nil {
				return uaddr.IP, nil
			}
		}
	}

	// 回退：遍历本机所有有效网络接口
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.To4() != nil && !ip.IsLoopback() {
				return ip, nil
			}
		}
	}

	return nil, errors.New("no valid local IP found")
}
