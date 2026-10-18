package qos

import (
	"testing"
	"time"
)

func TestPayloadEncodeDecode(t *testing.T) {
	nowNanos := time.Now().UnixNano()
	seq := uint32(1001)

	buf := EncodePayload(nowNanos, seq)
	if len(buf) != PayloadSize {
		t.Fatalf("expected payload size %d, got %d", PayloadSize, len(buf))
	}

	decoded, err := DecodePayload(buf[:])
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if decoded.Timestamp != uint64(nowNanos) {
		t.Errorf("timestamp mismatch: got %d, want %d", decoded.Timestamp, nowNanos)
	}
	if decoded.Seq != seq {
		t.Errorf("seq mismatch: got %d, want %d", decoded.Seq, seq)
	}
	if byte(decoded.Salt>>24) != Magic {
		t.Errorf("magic byte mismatch in salt: got 0x%x, want 0x%x", byte(decoded.Salt>>24), Magic)
	}
}

func TestPayloadDecodeRejectsInvalid(t *testing.T) {
	// 长度不足
	if _, err := DecodePayload([]byte{1, 2, 3}); err != ErrPayloadTooShort {
		t.Errorf("expected ErrPayloadTooShort, got %v", err)
	}

	// Magic 不匹配
	var raw [16]byte
	raw[12] = 0x11 // wrong magic
	if _, err := DecodePayload(raw[:]); err != ErrInvalidMagic {
		t.Errorf("expected ErrInvalidMagic, got %v", err)
	}
}

func TestAccumulatorRTTAndJitter(t *testing.T) {
	acc := NewAccumulator(20, 2*time.Second)
	baseTime := time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC)

	// 探针 1: RTT = 20ms
	seq1 := acc.NextSeq()
	t1 := baseTime
	acc.RecordProbeSent(seq1, t1)
	rtt, ok := acc.RecordPongReceived(seq1, t1.Add(20*time.Millisecond), t1.UnixNano())
	if !ok || rtt != 20*time.Millisecond {
		t.Fatalf("unexpected pong record: rtt=%v ok=%v", rtt, ok)
	}

	snap1 := acc.Snapshot(t1.Add(50 * time.Millisecond))
	if snap1.SmoothedRTT != 20*time.Millisecond {
		t.Errorf("snap1 SmoothedRTT mismatch: got %v, want 20ms", snap1.SmoothedRTT)
	}
	if snap1.Jitter != 0 {
		t.Errorf("first sample jitter should be 0, got %v", snap1.Jitter)
	}

	// 探针 2: RTT = 30ms -> diff = 10ms, jitter = (10ms - 0) / 16 = 625us
	seq2 := acc.NextSeq()
	t2 := baseTime.Add(1 * time.Second)
	acc.RecordProbeSent(seq2, t2)
	acc.RecordPongReceived(seq2, t2.Add(30*time.Millisecond), t2.UnixNano())

	snap2 := acc.Snapshot(t2.Add(50 * time.Millisecond))
	// EWMA: 20ms * 0.8 + 30ms * 0.2 = 22ms
	if snap2.SmoothedRTT != 22*time.Millisecond {
		t.Errorf("snap2 SmoothedRTT mismatch: got %v, want 22ms", snap2.SmoothedRTT)
	}
	expectedJitter := (10 * time.Millisecond) / 16
	if snap2.Jitter != expectedJitter {
		t.Errorf("snap2 Jitter mismatch: got %v, want %v", snap2.Jitter, expectedJitter)
	}
}

func TestAccumulatorLossRateSlidingWindow(t *testing.T) {
	windowSize := 10
	timeout := 1 * time.Second
	acc := NewAccumulator(windowSize, timeout)
	baseTime := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

	// 发送 10 个探针：其中前 8 个成功，后 2 个超时丢失
	for i := 1; i <= 8; i++ {
		seq := acc.NextSeq()
		st := baseTime.Add(time.Duration(i) * 100 * time.Millisecond)
		acc.RecordProbeSent(seq, st)
		acc.RecordPongReceived(seq, st.Add(10*time.Millisecond), st.UnixNano())
	}

	for i := 9; i <= 10; i++ {
		seq := acc.NextSeq()
		st := baseTime.Add(time.Duration(i) * 100 * time.Millisecond)
		acc.RecordProbeSent(seq, st)
		// 不记录 Pong
	}

	// 在未超时时检查快照：丢失率应为 0（因后两个尚处于 Pending）
	snapBefore := acc.Snapshot(baseTime.Add(1100 * time.Millisecond))
	if snapBefore.LossRate != 0.0 {
		t.Errorf("loss rate before timeout should be 0.0, got %f", snapBefore.LossRate)
	}

	// 推进时间到超时之后（如 baseTime + 3s）：后两个探针判定为 Lost
	snapAfter := acc.Snapshot(baseTime.Add(3 * time.Second))
	// 总计 10 个完成，2 个丢失 -> LossRate = 2/10 = 0.2 (20%)
	if snapAfter.LossRate != 0.2 {
		t.Errorf("expected loss rate 0.2, got %f", snapAfter.LossRate)
	}
}

func TestAccumulatorOverwritingSlidingWindow(t *testing.T) {
	windowSize := 5
	timeout := 1 * time.Second
	acc := NewAccumulator(windowSize, timeout)
	now := time.Now()

	// 发送 5 个探针全部成功
	for i := 0; i < 5; i++ {
		seq := acc.NextSeq()
		acc.RecordProbeSent(seq, now)
		acc.RecordPongReceived(seq, now.Add(10*time.Millisecond), now.UnixNano())
	}
	snap := acc.Snapshot(now.Add(100 * time.Millisecond))
	if snap.LossRate != 0.0 {
		t.Errorf("expected 0.0, got %f", snap.LossRate)
	}

	// 发送第 6 个探针（覆盖第 1 个），且未收到回复并超时
	seq6 := acc.NextSeq()
	t6 := now.Add(2 * time.Second)
	acc.RecordProbeSent(seq6, t6)

	snap2 := acc.Snapshot(t6.Add(2 * time.Second))
	// 窗口 5 个槽位：4 个 success，1 个 lost -> 1/5 = 0.2
	if snap2.LossRate != 0.2 {
		t.Errorf("expected loss rate 0.2 after wrap, got %f", snap2.LossRate)
	}
}

func TestAccumulatorRejectsStaleOrUnmatchedPong(t *testing.T) {
	acc := NewAccumulator(5, time.Second)
	now := time.Now()

	// 1. 未发出任何探针时收到 Pong，必须拒绝
	if rtt, ok := acc.RecordPongReceived(999, now, now.UnixNano()); ok || rtt != 0 {
		t.Fatalf("expected rejected pong for unsent probe, got ok=%v rtt=%v", ok, rtt)
	}

	// 2. 发送探针 1，并成功接收 Pong
	seq1 := acc.NextSeq()
	acc.RecordProbeSent(seq1, now)
	if _, ok := acc.RecordPongReceived(seq1, now.Add(20*time.Millisecond), now.UnixNano()); !ok {
		t.Fatal("expected first pong to succeed")
	}

	// 3. 重复接收针对探针 1 的 Pong（Duplicate Pong），必须被拒绝且不计入统计
	snapBefore := acc.Snapshot(now.Add(50 * time.Millisecond))
	if _, ok := acc.RecordPongReceived(seq1, now.Add(10*time.Second), now.UnixNano()); ok {
		t.Fatal("expected duplicate pong to be rejected")
	}
	snapAfter := acc.Snapshot(now.Add(50 * time.Millisecond))
	if snapAfter.PongsRecv != snapBefore.PongsRecv {
		t.Fatalf("duplicate pong should not increment pongsRecv: before=%d, after=%d", snapBefore.PongsRecv, snapAfter.PongsRecv)
	}
	if snapAfter.SmoothedRTT != snapBefore.SmoothedRTT {
		t.Fatalf("duplicate pong contaminated smoothedRTT: before=%v, after=%v", snapBefore.SmoothedRTT, snapAfter.SmoothedRTT)
	}

	// 4. 发送探针（导致旧槽位被覆盖），延迟到达的过期 Pong 必须被拒绝
	for i := 0; i < 6; i++ {
		s := acc.NextSeq()
		acc.RecordProbeSent(s, now.Add(time.Duration(i)*100*time.Millisecond))
	}
	// 尝试给已被覆盖的 seq1 补发迟到 Pong
	if _, ok := acc.RecordPongReceived(seq1, now.Add(5*time.Second), now.UnixNano()); ok {
		t.Fatal("expected overwritten probe pong to be rejected")
	}
}

func TestAccumulatorSequenceWraparound(t *testing.T) {
	acc := NewAccumulator(10, time.Second)
	// 强制测试接近 uint32 最大值时的自然翻转
	acc.nextSeq = ^uint32(0) // 0xFFFFFFFF
	seqMax := acc.NextSeq()
	if seqMax != ^uint32(0) {
		t.Fatalf("got %d, want %d", seqMax, ^uint32(0))
	}
	seqZero := acc.NextSeq()
	if seqZero != 0 {
		t.Fatalf("got %d, want 0 on natural wraparound", seqZero)
	}

	// 验证 seq 0 可以正常记录探针与匹配接收
	now := time.Now()
	acc.RecordProbeSent(seqZero, now)
	rtt, ok := acc.RecordPongReceived(seqZero, now.Add(15*time.Millisecond), now.UnixNano())
	if !ok || rtt != 15*time.Millisecond {
		t.Fatalf("failed to record probe with seq 0: ok=%v, rtt=%v", ok, rtt)
	}
}

func TestAccumulatorLatePongIsDeterministic(t *testing.T) {
	sent := time.Unix(1700000000, 0)
	pongTime := sent.Add(2 * time.Second) // 超过 1 秒探针超时

	direct := NewAccumulator(10, time.Second)
	swept := NewAccumulator(10, time.Second)
	direct.RecordProbeSent(1, sent)
	swept.RecordProbeSent(1, sent)
	// swept 在 Pong 到达前曾生成过快照（触发超时扫描）
	swept.Snapshot(sent.Add(1500 * time.Millisecond))

	_, okDirect := direct.RecordPongReceived(1, pongTime, sent.UnixNano())
	_, okSwept := swept.RecordPongReceived(1, pongTime, sent.UnixNano())
	if okDirect != okSwept {
		t.Fatalf("迟到 Pong 的接受与否取决于是否调用过 Snapshot：未扫描=%v，已扫描=%v", okDirect, okSwept)
	}
}
