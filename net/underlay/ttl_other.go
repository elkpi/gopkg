//go:build !linux

package underlay

import (
	"errors"
	"net"
)

// errTTLOnUnsupported 标记当前平台不支持单包 TTL OOB 注入。
var errTTLOnUnsupported = errors.New("underlay: per-packet TTL injection is not supported on this platform")

// MarshalIPTTL 在不支持的平台不产生控制数据。
func MarshalIPTTL(ttl uint8) []byte {
	return nil
}

// SendUDPWithTTL 在不支持的平台退化为普通发送；显式 TTL 请求直接报错，
// 避免低 TTL 探测静默使用系统默认 TTL。
func SendUDPWithTTL(conn *net.UDPConn, payload []byte, addr *net.UDPAddr, ttl uint8) error {
	if ttl != 0 {
		return errTTLOnUnsupported
	}
	if conn == nil {
		return errors.New("udp connection is nil")
	}
	if addr == nil {
		return errors.New("destination address is nil")
	}
	_, err := conn.WriteToUDP(payload, addr)
	return err
}
