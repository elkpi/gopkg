package qos

import (
	"sync"
	"time"
)

const (
	DefaultWindowSize   = 20
	DefaultProbeTimeout = 2 * time.Second
	Alpha               = 0.2 // EWMA 平滑权重
)

type slotStatus uint8

const (
	statusEmpty slotStatus = iota
	statusPending
	statusSuccess
	statusLost
)

type probeSlot struct {
	seq      uint32
	sendTime time.Time
	status   slotStatus
}

// Metrics 保存当前计算出的 QoS 质量快照。
type Metrics struct {
	SmoothedRTT time.Duration `json:"smoothed_rtt"`
	LatestRTT   time.Duration `json:"latest_rtt"`
	Jitter      time.Duration `json:"jitter"`
	LossRate    float64       `json:"loss_rate"` // 0.0 ~ 1.0
	ProbesSent  uint64        `json:"probes_sent"`
	PongsRecv   uint64        `json:"pongs_recv"`
}

// Accumulator 是线程安全的高精度网络质量聚合计算器。
type Accumulator struct {
	mu           sync.RWMutex
	windowSize   int
	probeTimeout time.Duration

	slots       []probeSlot
	nextSeq     uint32
	probesSent  uint64
	pongsRecv   uint64
	smoothedRTT time.Duration
	latestRTT   time.Duration
	jitter      time.Duration
}

// NewAccumulator 创建指定窗口大小与超时时间的 QoS 聚合器。
func NewAccumulator(windowSize int, probeTimeout time.Duration) *Accumulator {
	if windowSize <= 0 {
		windowSize = DefaultWindowSize
	}
	if probeTimeout <= 0 {
		probeTimeout = DefaultProbeTimeout
	}
	return &Accumulator{
		windowSize:   windowSize,
		probeTimeout: probeTimeout,
		slots:        make([]probeSlot, windowSize),
		nextSeq:      1,
	}
}

// NextSeq 生成下一个递增探针序列号。
func (a *Accumulator) NextSeq() uint32 {
	a.mu.Lock()
	defer a.mu.Unlock()
	seq := a.nextSeq
	a.nextSeq++
	return seq
}

// RecordProbeSent 记录一次发出的探针。
func (a *Accumulator) RecordProbeSent(seq uint32, sendTime time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()

	idx := int(seq % uint32(a.windowSize))
	// 若该槽位上一轮的探针仍处于 pending 状态，则判定其丢失
	if a.slots[idx].status == statusPending {
		a.slots[idx].status = statusLost
	}

	a.slots[idx] = probeSlot{
		seq:      seq,
		sendTime: sendTime,
		status:   statusPending,
	}
	a.probesSent++
}

// RecordPongReceived 记录接收到的 Pong 并更新 RTT 与 RFC 3550 抖动。
func (a *Accumulator) RecordPongReceived(seq uint32, recvTime time.Time, sendNanos int64) (time.Duration, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	idx := int(seq % uint32(a.windowSize))
	slot := &a.slots[idx]

	if slot.seq != seq || slot.status != statusPending {
		return 0, false
	}

	slot.status = statusSuccess
	var rtt time.Duration
	if !slot.sendTime.IsZero() {
		rtt = recvTime.Sub(slot.sendTime)
	}
	if rtt <= 0 && sendNanos > 0 {
		sentTime := time.Unix(0, sendNanos)
		rtt = recvTime.Sub(sentTime)
	}
	if rtt < 0 {
		rtt = 0
	}

	a.pongsRecv++
	// 1. EWMA RTT 计算
	if a.smoothedRTT == 0 {
		a.smoothedRTT = rtt
	} else {
		a.smoothedRTT = time.Duration(float64(a.smoothedRTT)*(1.0-Alpha) + float64(rtt)*Alpha)
	}

	// 2. RFC 3550 Jitter 计算: J = J + (|D| - J) / 16
	if a.latestRTT != 0 {
		diff := rtt - a.latestRTT
		if diff < 0 {
			diff = -diff
		}
		a.jitter += (diff - a.jitter) / 16
	}
	a.latestRTT = rtt
	return rtt, true
}

// SweepTimeouts 扫描超过超时时间未返回的探针，标记为丢失。
func (a *Accumulator) SweepTimeouts(now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sweepTimeoutsLocked(now)
}

func (a *Accumulator) sweepTimeoutsLocked(now time.Time) {
	for i := range a.slots {
		slot := &a.slots[i]
		if slot.status == statusPending && !slot.sendTime.IsZero() {
			if now.Sub(slot.sendTime) >= a.probeTimeout {
				slot.status = statusLost
			}
		}
	}
}

// Snapshot 抓取当前 QoS 统计快照。
func (a *Accumulator) Snapshot(now time.Time) Metrics {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.sweepTimeoutsLocked(now)

	var successCount, lostCount int
	for _, slot := range a.slots {
		switch slot.status {
		case statusSuccess:
			successCount++
		case statusLost:
			lostCount++
		}
	}

	var lossRate float64
	totalCompleted := successCount + lostCount
	if totalCompleted > 0 {
		lossRate = float64(lostCount) / float64(totalCompleted)
	}

	return Metrics{
		SmoothedRTT: a.smoothedRTT,
		LatestRTT:   a.latestRTT,
		Jitter:      a.jitter,
		LossRate:    lossRate,
		ProbesSent:  a.probesSent,
		PongsRecv:   a.pongsRecv,
	}
}

// Reset 清空历史数据。
func (a *Accumulator) Reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.slots {
		a.slots[i] = probeSlot{}
	}
	a.smoothedRTT = 0
	a.latestRTT = 0
	a.jitter = 0
	a.probesSent = 0
	a.pongsRecv = 0
}
