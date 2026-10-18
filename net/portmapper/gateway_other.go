//go:build !linux

package portmapper

import (
	"errors"
	"net"
)

func discoverGateway() (net.IP, error) {
	// 在非 Linux 平台下，尝试通过本机主 IP 推测典型网关（如 x.x.x.1）
	localIP, err := FindLocalIP()
	if err != nil {
		return nil, err
	}

	ip4 := localIP.To4()
	if ip4 == nil {
		return nil, errors.New("cannot determine IPv4 default gateway")
	}

	// 局域网常见网关为第一段地址（如 192.168.1.1）
	gw := net.IPv4(ip4[0], ip4[1], ip4[2], 1)
	return gw, nil
}
