package qos

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"
)

// PayloadSize 固定为 16 字节，严格向前兼容 frame.Ping 与 frame.Pong 报文约束。
const PayloadSize = 16

var (
	ErrPayloadTooShort = errors.New("qos payload must be exactly 16 bytes")
	ErrInvalidMagic    = errors.New("qos payload magic mismatch")
)

// Magic 占用 Salt 的最高字节，用于区分普通随机探针与高精度 QoS 探针。
const Magic uint8 = 0x51 // 'Q'

// ProbePayload 封装 16 字节 QoS 探针内联负载。
type ProbePayload struct {
	Timestamp uint64 // 发送端纳秒时间戳（8字节）
	Seq       uint32 // 递增探针序列号（4字节）
	Salt      uint32 // 随机盐与魔数（4字节，高8位为 Magic 0x51）
}

// EncodePayload 编码 QoS 探针载荷到 16 字节定长数组。
func EncodePayload(timestamp int64, seq uint32) [PayloadSize]byte {
	var buf [PayloadSize]byte
	if timestamp <= 0 {
		timestamp = time.Now().UnixNano()
	}
	binary.BigEndian.PutUint64(buf[0:8], uint64(timestamp))
	binary.BigEndian.PutUint32(buf[8:12], seq)

	var salt [4]byte
	_, _ = rand.Read(salt[:])
	salt[0] = Magic
	copy(buf[12:16], salt[:])
	return buf
}

// DecodePayload 解码 16 字节定长载荷。
func DecodePayload(p []byte) (ProbePayload, error) {
	if len(p) != PayloadSize {
		return ProbePayload{}, ErrPayloadTooShort
	}
	salt := binary.BigEndian.Uint32(p[12:16])
	if byte(salt>>24) != Magic {
		return ProbePayload{}, ErrInvalidMagic
	}
	return ProbePayload{
		Timestamp: binary.BigEndian.Uint64(p[0:8]),
		Seq:       binary.BigEndian.Uint32(p[8:12]),
		Salt:      salt,
	}, nil
}
