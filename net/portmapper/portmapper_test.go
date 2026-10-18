package portmapper

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMappingReleaseRetryAfterFailure(t *testing.T) {
	var deletes atomic.Int32
	var failFirst = int32(1)
	client := &stubClient{
		deleteFn: func() error {
			if deletes.Add(1) == 1 && atomic.LoadInt32(&failFirst) == 1 {
				return errors.New("临时删除失败")
			}
			return nil
		},
	}
	m := &Mapping{client: client}

	if err := m.Release(context.Background()); err == nil {
		t.Fatal("首次删除失败应上抛错误")
	}
	if m.IsReleased() {
		t.Fatal("删除失败时不应标记为已释放，否则无法重试")
	}
	if err := m.Release(context.Background()); err != nil {
		t.Fatalf("第二次 Release 应重试删除：%v", err)
	}
	if got := deletes.Load(); got != 2 {
		t.Fatalf("期望 Delete 被调用 2 次，实际 %d 次", got)
	}
}

// stubClient 实现仅用于生命周期测试的 Client。
type stubClient struct {
	deleteFn func() error
}

func (*stubClient) Provider() Provider { return ProviderNATPMP }
func (*stubClient) GetExternalIP(context.Context) (net.IP, error) {
	return net.IPv4(203, 0, 113, 7), nil
}
func (s *stubClient) DeletePortMapping(context.Context, *Mapping) error { return s.deleteFn() }
func (*stubClient) RenewMapping(context.Context, *Mapping, time.Duration) (*Mapping, error) {
	return nil, errors.New("not implemented")
}
func (*stubClient) Close() error { return nil }

func (s *stubClient) AddPortMapping(_ context.Context, proto Protocol, internal, external int, lifetime time.Duration) (*Mapping, error) {
	return &Mapping{
		Protocol:     proto,
		InternalPort: internal,
		ExternalPort: external,
		Lifetime:     lifetime,
		Provider:     ProviderNATPMP,
	}, nil
}

func TestPortMapperConcurrentDiscoverTracksAll(t *testing.T) {
	pm, _ := New(DefaultConfig())
	pm.mu.Lock()
	pm.cachedClient = &stubClient{deleteFn: func() error { return nil }}
	pm.mu.Unlock()

	const n = 1024
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, _ = pm.Discover(context.Background(), 10000+i, 10000+i)
		}(i)
	}
	close(start)
	wg.Wait()

	pm.mu.Lock()
	tracked := len(pm.activeMaps)
	pm.mu.Unlock()
	if tracked != n {
		t.Fatalf("成功创建 %d 个映射，只跟踪到 %d 个，ReleaseAll 将遗漏", n, tracked)
	}

	if err := pm.ReleaseAll(context.Background()); err != nil {
		t.Fatalf("ReleaseAll: %v", err)
	}
	pm.mu.Lock()
	tracked = len(pm.activeMaps)
	pm.mu.Unlock()
	if tracked != 0 {
		t.Fatalf("释放后仍跟踪 %d 个映射", tracked)
	}
}

func TestPortMapper_PCP_Priority(t *testing.T) {
	opts := DefaultMockOptions()
	opts.EnablePCP = true
	opts.EnableNATPMP = true
	opts.EnableUPnP = false

	gw, err := StartMockGateway(opts)
	if err != nil {
		t.Fatalf("failed to start mock gateway: %v", err)
	}
	defer gw.Close()

	cfg := Config{
		GatewayIP:          net.ParseIP("127.0.0.1"),
		LocalIP:            net.ParseIP("127.0.0.1"),
		PCPPort:            gw.UDPPort,
		NATPMPPort:         gw.UDPPort,
		PreferredProviders: []Provider{ProviderPCP, ProviderNATPMP},
		DefaultLifetime:    1 * time.Hour,
		ProbeTimeout:       500 * time.Millisecond,
	}

	pm, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create PortMapper: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	m, err := pm.Discover(ctx, 8080, 8080)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
	defer func() { _ = m.Release(ctx) }()

	if m.Provider != ProviderPCP {
		t.Errorf("expected ProviderPCP due to priority, got %v", m.Provider)
	}
	if m.InternalPort != 8080 || m.ExternalPort != 8080 {
		t.Errorf("unexpected ports: in=%d, ext=%d", m.InternalPort, m.ExternalPort)
	}
	if expected := "203.0.113.199:8080"; m.ExternalAddr() != expected {
		t.Errorf("expected external addr %s, got %s", expected, m.ExternalAddr())
	}
}

func TestPortMapper_NATPMP_Fallback(t *testing.T) {
	opts := DefaultMockOptions()
	opts.EnablePCP = false // PCP 禁用
	opts.EnableNATPMP = true
	opts.EnableUPnP = false

	gw, err := StartMockGateway(opts)
	if err != nil {
		t.Fatalf("failed to start mock gateway: %v", err)
	}
	defer gw.Close()

	cfg := Config{
		GatewayIP:          net.ParseIP("127.0.0.1"),
		LocalIP:            net.ParseIP("127.0.0.1"),
		PCPPort:            gw.UDPPort,
		NATPMPPort:         gw.UDPPort,
		PreferredProviders: []Provider{ProviderPCP, ProviderNATPMP},
		DefaultLifetime:    1 * time.Hour,
		ProbeTimeout:       200 * time.Millisecond, // 快速超时 PCP
	}

	pm, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create PortMapper: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	m, err := pm.DiscoverProtocol(ctx, ProtocolUDP, 9999, 9999)
	if err != nil {
		t.Fatalf("DiscoverProtocol failed: %v", err)
	}
	defer func() { _ = m.Release(ctx) }()

	if m.Provider != ProviderNATPMP {
		t.Errorf("expected fallback to ProviderNATPMP, got %v", m.Provider)
	}
	if m.Protocol != ProtocolUDP {
		t.Errorf("expected UDP protocol, got %v", m.Protocol)
	}
}

func TestPortMapper_UPnP_Fallback(t *testing.T) {
	opts := DefaultMockOptions()
	opts.EnablePCP = false
	opts.EnableNATPMP = false
	opts.EnableUPnP = true

	gw, err := StartMockGateway(opts)
	if err != nil {
		t.Fatalf("failed to start mock gateway: %v", err)
	}
	defer gw.Close()

	// 直接从 Mock UPnP 初始化客户端
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	upnpClient, err := NewUPnPClientFromLocation(ctx, gw.RootXMLURL, nil)
	if err != nil {
		t.Fatalf("failed to init upnp client: %v", err)
	}

	m, err := upnpClient.AddPortMapping(ctx, ProtocolTCP, 7777, 7777, 1*time.Hour)
	if err != nil {
		t.Fatalf("AddPortMapping via UPnP failed: %v", err)
	}
	defer func() { _ = m.Release(ctx) }()

	if m.Provider != ProviderUPnP {
		t.Errorf("expected UPnP provider, got %v", m.Provider)
	}
	if m.ExternalPort != 7777 {
		t.Errorf("expected external port 7777, got %d", m.ExternalPort)
	}
}

func TestPortMapper_Renew_And_Release(t *testing.T) {
	opts := DefaultMockOptions()
	opts.EnablePCP = true

	gw, err := StartMockGateway(opts)
	if err != nil {
		t.Fatalf("failed to start mock gateway: %v", err)
	}
	defer gw.Close()

	cfg := Config{
		GatewayIP:          net.ParseIP("127.0.0.1"),
		LocalIP:            net.ParseIP("127.0.0.1"),
		PCPPort:            gw.UDPPort,
		PreferredProviders: []Provider{ProviderPCP},
		DefaultLifetime:    30 * time.Minute,
		ProbeTimeout:       200 * time.Millisecond,
	}

	pm, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create PortMapper: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	m, err := pm.Discover(ctx, 8081, 8081)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	// 1. 验证续期
	if err := m.Renew(ctx, 1*time.Hour); err != nil {
		t.Fatalf("Renew failed: %v", err)
	}
	if m.Lifetime != 1*time.Hour {
		t.Errorf("expected lifetime 1h after renew, got %v", m.Lifetime)
	}

	// 2. 验证释放
	if m.IsReleased() {
		t.Error("expected not released initially")
	}
	if err := m.Release(ctx); err != nil {
		t.Fatalf("Release failed: %v", err)
	}
	if !m.IsReleased() {
		t.Error("expected isReleased true after Release")
	}

	// 再次调用 Release 应幂等返回 nil
	if err := m.Release(ctx); err != nil {
		t.Errorf("expected idempotent Release, got %v", err)
	}

	// 已释放状态下调用 Renew 应返回错误
	if err := m.Renew(ctx, time.Hour); !errors.Is(err, ErrMappingAlreadyReleased) {
		t.Errorf("expected ErrMappingAlreadyReleased, got %v", err)
	}
}

func TestPortMapper_AutoRenew(t *testing.T) {
	opts := DefaultMockOptions()
	opts.EnablePCP = true

	gw, err := StartMockGateway(opts)
	if err != nil {
		t.Fatalf("failed to start mock gateway: %v", err)
	}
	defer gw.Close()

	cfg := Config{
		GatewayIP:          net.ParseIP("127.0.0.1"),
		LocalIP:            net.ParseIP("127.0.0.1"),
		PCPPort:            gw.UDPPort,
		PreferredProviders: []Provider{ProviderPCP},
		DefaultLifetime:    10 * time.Minute,
		ProbeTimeout:       200 * time.Millisecond,
	}

	pm, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create PortMapper: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	m, err := pm.Discover(ctx, 8082, 8082)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	// 启动每 20ms 续期一次的自动任务
	stop := m.AutoRenew(ctx, 20*time.Millisecond)
	time.Sleep(70 * time.Millisecond)
	stop()

	// 验证释放
	_ = m.Release(ctx)
}

func TestPortMapper_ReleaseAll(t *testing.T) {
	opts := DefaultMockOptions()
	opts.EnablePCP = true

	gw, err := StartMockGateway(opts)
	if err != nil {
		t.Fatalf("failed to start mock gateway: %v", err)
	}
	defer gw.Close()

	cfg := Config{
		GatewayIP:          net.ParseIP("127.0.0.1"),
		LocalIP:            net.ParseIP("127.0.0.1"),
		PCPPort:            gw.UDPPort,
		PreferredProviders: []Provider{ProviderPCP},
		DefaultLifetime:    30 * time.Minute,
		ProbeTimeout:       200 * time.Millisecond,
	}

	pm, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create PortMapper: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	m1, err := pm.Discover(ctx, 8083, 8083)
	if err != nil {
		t.Fatalf("m1 failed: %v", err)
	}
	m2, err := pm.DiscoverProtocol(ctx, ProtocolUDP, 9083, 9083)
	if err != nil {
		t.Fatalf("m2 failed: %v", err)
	}

	if err := pm.ReleaseAll(ctx); err != nil {
		t.Fatalf("ReleaseAll failed: %v", err)
	}

	if !m1.IsReleased() || !m2.IsReleased() {
		t.Error("expected both mappings to be released after ReleaseAll")
	}
}

func TestPortMapper_FallsBackWhenMappingFails(t *testing.T) {
	var pmpMaps atomic.Int32
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	port := conn.LocalAddr().(*net.UDPAddr).Port

	go func() {
		buf := make([]byte, 256)
		for {
			n, remote, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 2 {
				continue
			}
			var resp []byte
			switch buf[0] {
			case 2: // PCP
				if n < 60 {
					continue
				}
				resp = make([]byte, 60)
				resp[0] = 2
				if buf[1] == pcpOpcodeAnnounce {
					resp[1] = pcpOpcodeAnnounce | pcpRespMask
					copy(resp[44:60], net.IPv4(203, 0, 113, 7).To16())
				} else if buf[1] == pcpOpcodeMap {
					resp[1] = pcpOpcodeMap | pcpRespMask
					copy(resp[24:44], buf[24:44])
					copy(resp[44:60], net.IPv4(203, 0, 113, 7).To16())
					if binary.BigEndian.Uint32(buf[4:8]) > 0 {
						resp[3] = 8 // NO_RESOURCES：探测可通过，但映射创建失败
					}
				} else {
					continue
				}
			case 0: // NAT-PMP
				if buf[1] == natpmpOpExternalIP {
					resp = make([]byte, 12)
					resp[1] = natpmpRespOpExternalIP
					copy(resp[8:12], net.IPv4(203, 0, 113, 7).To4())
				} else if n >= 12 {
					pmpMaps.Add(1)
					resp = make([]byte, 16)
					resp[1] = buf[1] + 128
					copy(resp[8:12], buf[4:8])
					copy(resp[12:16], buf[8:12])
				} else {
					continue
				}
			default:
				continue
			}
			_, _ = conn.WriteToUDP(resp, remote)
		}
	}()

	cfg := DefaultConfig()
	cfg.GatewayIP = net.IPv4(127, 0, 0, 1)
	cfg.LocalIP = cfg.GatewayIP
	cfg.PCPPort = port
	cfg.NATPMPPort = port
	cfg.ProbeTimeout = 300 * time.Millisecond
	cfg.PreferredProviders = []Provider{ProviderPCP, ProviderNATPMP}
	pm, _ := New(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	m, err := pm.Discover(ctx, 12345, 12345)
	if err != nil {
		t.Fatalf("PCP 映射失败后应回退到 NAT-PMP：%v", err)
	}
	if m.Provider != ProviderNATPMP {
		t.Fatalf("期望回退到 NAT-PMP，实际 %v", m.Provider)
	}
	if got := pmpMaps.Load(); got == 0 {
		t.Fatal("NAT-PMP 从未收到映射请求")
	}
}

func TestPortMapper_InvalidInputs(t *testing.T) {
	pm := NewDefault()
	ctx := context.Background()

	// 无效端口
	_, err := pm.Discover(ctx, 0, 8080)
	if err == nil {
		t.Error("expected error for port 0, got nil")
	}

	_, err = pm.Discover(ctx, 70000, 8080)
	if err == nil {
		t.Error("expected error for port 70000, got nil")
	}

	// 无效协议
	_, err = pm.DiscoverProtocol(ctx, Protocol("QUIC"), 8080, 8080)
	if !errors.Is(err, ErrUnsupportedProtocol) {
		t.Errorf("expected ErrUnsupportedProtocol, got %v", err)
	}
}
