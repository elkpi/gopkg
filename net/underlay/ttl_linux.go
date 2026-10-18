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
	if ttl == 0 {
		return nil
	}
	oob := make([]byte, unix.CmsgSpace(4))
	cmsg := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	cmsg.Level = unix.IPPROTO_IP
	cmsg.Type = unix.IP_TTL
	cmsg.SetLen(unix.CmsgLen(4))
	*(*int32)(unsafe.Pointer(&oob[unix.CmsgLen(0)])) = int32(ttl)
	return oob
}

// SendUDPWithTTL 在 UDP socket 上发送附带单包 TTL 的报文；ttl 为 0 时使用默认 TTL。
func SendUDPWithTTL(conn *net.UDPConn, payload []byte, addr *net.UDPAddr, ttl uint8) error {
	if conn == nil {
		return fmt.Errorf("udp connection is nil")
	}
	if addr == nil {
		return fmt.Errorf("destination address is nil")
	}
	oob := MarshalIPTTL(ttl)
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
