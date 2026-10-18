package portmapper

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

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
