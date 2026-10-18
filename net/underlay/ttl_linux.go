//go:build linux

package underlay

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// MarshalIPTTL 构造设置单包 IP_TTL 的 ancillary (OOB) 控制数据。
// 若 ttl == 0，返回 nil（使用系统默认 TTL）。
func MarshalIPTTL(ttl uint8) []byte {
	return marshalCmsgTTL(unix.IPPROTO_IP, unix.IP_TTL, ttl)
}

// marshalIPv6HopLimit 构造设置单包 IPV6_HOPLIMIT 的控制数据。
func marshalIPv6HopLimit(ttl uint8) []byte {
	return marshalCmsgTTL(unix.IPPROTO_IPV6, unix.IPV6_HOPLIMIT, ttl)
}

func marshalCmsgTTL(level, cmsgType int32, ttl uint8) []byte {
	if ttl == 0 {
		return nil
	}
	oob := make([]byte, unix.CmsgSpace(4))
	cmsg := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	cmsg.Level = level
	cmsg.Type = cmsgType
	cmsg.SetLen(unix.CmsgLen(4))
	*(*int32)(unsafe.Pointer(&oob[unix.CmsgLen(0)])) = int32(ttl)
	return oob
}

// SendUDPWithTTL 在 UDP socket 上发送附带单包 TTL 的报文；ttl 为 0 时使用默认 TTL。
// 按目的地址族选择 IP_TTL 或 IPV6_HOPLIMIT；双栈 socket 上发送 IPv4 时仍需 IP_TTL。
func SendUDPWithTTL(conn *net.UDPConn, payload []byte, addr *net.UDPAddr, ttl uint8) error {
	if conn == nil {
		return fmt.Errorf("udp connection is nil")
	}
	if addr == nil {
		return fmt.Errorf("destination address is nil")
	}
	var oob []byte
	if ttl != 0 {
		if addr.IP != nil && addr.IP.To4() == nil {
			oob = marshalIPv6HopLimit(ttl)
		} else {
			oob = MarshalIPTTL(ttl)
		}
	}
	if len(oob) == 0 {
		_, err := conn.WriteToUDP(payload, addr)
		return err
	}
	n, oobn, err := conn.WriteMsgUDP(payload, oob, addr)
	if err != nil {
		return fmt.Errorf("write with TTL %d: %w", ttl, err)
	}
	if n != len(payload) || oobn != len(oob) {
		return fmt.Errorf("short write: data=%d/%d, oob=%d/%d", n, len(payload), oobn, len(oob))
	}
	return nil
}
