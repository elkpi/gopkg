//go:build linux

package portmapper

import (
	"bufio"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

const procRoutePath = "/proc/net/route"

func discoverGateway() (net.IP, error) {
	file, err := os.Open(procRoutePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return parseLinuxRoute(file)
}

// parseLinuxRoute 从类似 /proc/net/route 的流中解析默认网关 IPv4。
func parseLinuxRoute(r io.Reader) (net.IP, error) {
	scanner := bufio.NewScanner(r)

	// 跳过第一行表头
	if !scanner.Scan() {
		return nil, errors.New("empty route file")
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// 格式：Iface Destination Gateway Flags ...
		destination := fields[1]
		gatewayHex := fields[2]
		flagsHex := fields[3]

		// 默认路由 Destination 为 00000000
		if destination != "00000000" {
			continue
		}

		flags, err := strconv.ParseUint(flagsHex, 16, 32)
		if err != nil {
			continue
		}

		// RTF_GATEWAY 标志位为 0x0002
		const rtfGateway = 0x0002
		if flags&rtfGateway == 0 {
			continue
		}

		gwVal, err := strconv.ParseUint(gatewayHex, 16, 32)
		if err != nil {
			continue
		}

		// Linux 内核在小端系统上以 16 进制打印无符号 32 位整数
		ip := net.IPv4(
			byte(gwVal),
			byte(gwVal>>8),
			byte(gwVal>>16),
			byte(gwVal>>24),
		)

		if ip != nil && !ip.IsUnspecified() {
			return ip, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return nil, errors.New("no default route in route table")
}
