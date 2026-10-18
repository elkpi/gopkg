package portmapper

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// PortMapper 是网关端口映射的核心协调器。
type PortMapper struct {
	cfg Config
	mu  sync.Mutex

	cachedClient Client
	activeMaps   []*Mapping
}

// New 创建一个新的 PortMapper 实例。
func New(cfg Config) (*PortMapper, error) {
	if len(cfg.PreferredProviders) == 0 {
		cfg.PreferredProviders = []Provider{ProviderPCP, ProviderNATPMP, ProviderUPnP}
	}
	if cfg.DefaultLifetime <= 0 {
		cfg.DefaultLifetime = 2 * time.Hour
	}
	if cfg.ProbeTimeout <= 0 {
		cfg.ProbeTimeout = 1500 * time.Millisecond
	}
	if cfg.Description == "" {
		cfg.Description = "gopkg-portmapper"
	}

	return &PortMapper{
		cfg: cfg,
	}, nil
}

// NewDefault 使用默认配置创建 PortMapper。
func NewDefault() *PortMapper {
	pm, _ := New(DefaultConfig())
	return pm
}

// 全局默认实例
var defaultMapper = NewDefault()

// Discover 使用默认协调器映射 TCP 端口。
func Discover(ctx context.Context, internalPort int, preferredExternal int) (*Mapping, error) {
	return defaultMapper.Discover(ctx, internalPort, preferredExternal)
}

// DiscoverProtocol 使用默认协调器映射指定协议（TCP/UDP）的端口。
func DiscoverProtocol(ctx context.Context, proto Protocol, internalPort int, preferredExternal int) (*Mapping, error) {
	return defaultMapper.DiscoverProtocol(ctx, proto, internalPort, preferredExternal)
}

// Discover 映射 TCP 端口。
func (pm *PortMapper) Discover(ctx context.Context, internalPort int, preferredExternal int) (*Mapping, error) {
	return pm.DiscoverProtocol(ctx, ProtocolTCP, internalPort, preferredExternal)
}

// DiscoverProtocol 针对指定传输协议执行网关探测与端口映射。
func (pm *PortMapper) DiscoverProtocol(ctx context.Context, proto Protocol, internalPort int, preferredExternal int) (*Mapping, error) {
	if proto != ProtocolTCP && proto != ProtocolUDP {
		return nil, ErrUnsupportedProtocol
	}
	if internalPort <= 0 || internalPort > 65535 {
		return nil, errors.New("portmapper: internal port out of valid range (1-65535)")
	}
	if preferredExternal <= 0 || preferredExternal > 65535 {
		preferredExternal = internalPort
	}

	pm.mu.Lock()
	cached := pm.cachedClient
	pm.mu.Unlock()

	// 1. 若有已缓存且可用的客户端，优先使用
	if cached != nil {
		m, err := cached.AddPortMapping(ctx, proto, internalPort, preferredExternal, pm.cfg.DefaultLifetime)
		if err == nil {
			pm.trackMapping(m)
			return m, nil
		}
		// 缓存客户端失败，失效并重新探测
		pm.mu.Lock()
		pm.cachedClient = nil
		pm.mu.Unlock()
	}

	// 2. 执行梯次并发探测
	client, err := pm.probeProviders(ctx)
	if err != nil {
		return nil, err
	}

	// 3. 执行映射请求
	m, err := client.AddPortMapping(ctx, proto, internalPort, preferredExternal, pm.cfg.DefaultLifetime)
	if err != nil {
		return nil, err
	}

	pm.mu.Lock()
	pm.cachedClient = client
	pm.trackMapping(m)
	pm.mu.Unlock()

	return m, nil
}

func (pm *PortMapper) trackMapping(m *Mapping) {
	pm.activeMaps = append(pm.activeMaps, m)
}

// probeProviders 实现 PCP / NAT-PMP 单播优先、UPnP 兜底的并发梯次探测机制。
func (pm *PortMapper) probeProviders(ctx context.Context) (Client, error) {
	gatewayIP := pm.cfg.GatewayIP
	if gatewayIP == nil {
		var gwErr error
		gatewayIP, gwErr = DiscoverDefaultGateway()
		if gwErr != nil {
			// 若未发现网关 IP，但支持 UPnP，则直接尝试 UPnP 组播发现
			if pm.supportsProvider(ProviderUPnP) {
				upnpClient, err := DiscoverUPnPGateway(ctx, pm.cfg.HTTPClient)
				if err == nil {
					return upnpClient, nil
				}
			}
			return nil, fmt.Errorf("%w: %v", ErrNoGatewayFound, gwErr)
		}
	}

	type probeResult struct {
		provider Provider
		client   Client
		err      error
	}

	resCh := make(chan probeResult, len(pm.cfg.PreferredProviders))
	var wg sync.WaitGroup

	// 单播探测超时控制
	unicastCtx, cancelUnicast := context.WithTimeout(ctx, pm.cfg.ProbeTimeout)
	defer cancelUnicast()

	// 1. 启动单播探测（PCP / NAT-PMP）
	if pm.supportsProvider(ProviderPCP) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pcpClient, err := NewPCPClientWithPort(gatewayIP, pm.cfg.LocalIP, pm.cfg.PCPPort)
			if err != nil {
				resCh <- probeResult{provider: ProviderPCP, err: err}
				return
			}
			// 探测连通性与外部 IP
			_, err = pcpClient.GetExternalIP(unicastCtx)
			if err != nil {
				_ = pcpClient.Close()
				resCh <- probeResult{provider: ProviderPCP, err: err}
				return
			}
			resCh <- probeResult{provider: ProviderPCP, client: pcpClient}
		}()
	}

	if pm.supportsProvider(ProviderNATPMP) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pmpClient, err := NewNATPMPClientWithPort(gatewayIP, pm.cfg.NATPMPPort)
			if err != nil {
				resCh <- probeResult{provider: ProviderNATPMP, err: err}
				return
			}
			// 探测连通性与外部 IP
			_, err = pmpClient.GetExternalIP(unicastCtx)
			if err != nil {
				_ = pmpClient.Close()
				resCh <- probeResult{provider: ProviderNATPMP, err: err}
				return
			}
			resCh <- probeResult{provider: ProviderNATPMP, client: pmpClient}
		}()
	}

	// 2. 梯次启动 UPnP 探测（若单播优先，稍作等待或并发兜底）
	if pm.supportsProvider(ProviderUPnP) {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// UPnP 兜底：先等待 80ms 让单播快速通道响应，避免不必要的组播开销
			select {
			case <-time.After(80 * time.Millisecond):
			case <-ctx.Done():
				return
			}

			upnpClient, err := DiscoverUPnPGateway(ctx, pm.cfg.HTTPClient)
			if err != nil {
				resCh <- probeResult{provider: ProviderUPnP, err: err}
				return
			}
			resCh <- probeResult{provider: ProviderUPnP, client: upnpClient}
		}()
	}

	// 异步关闭 channel
	go func() {
		wg.Wait()
		close(resCh)
	}()

	var selected Client
	results := make(map[Provider]Client)
	finishedProviders := make(map[Provider]bool)

	defer func() {
		// 清理未被选中的其他客户端
		for _, c := range results {
			if c != selected && c != nil {
				_ = c.Close()
			}
		}
	}()

	for res := range resCh {
		finishedProviders[res.provider] = true
		if res.err == nil && res.client != nil {
			results[res.provider] = res.client
		}

		// 按首选顺序检查当前可决策的最高优先级结果
		for _, p := range pm.cfg.PreferredProviders {
			if c, ok := results[p]; ok {
				// 高优先级协议已成功完成，立即选定并返回
				selected = c
				return selected, nil
			}
			if !finishedProviders[p] {
				// 更高优先级的协议仍在探测中，暂不降级返回次级结果
				break
			}
		}
	}

	// 所有探测已完成，按优先级选取成功者
	for _, p := range pm.cfg.PreferredProviders {
		if c, exists := results[p]; exists {
			selected = c
			return selected, nil
		}
	}

	return nil, ErrNoProviderAvailable
}

func (pm *PortMapper) supportsProvider(p Provider) bool {
	for _, prov := range pm.cfg.PreferredProviders {
		if prov == p {
			return true
		}
	}
	return false
}

// ReleaseAll 释放当前 PortMapper 实例已创建并跟踪的所有活跃端口映射。
func (pm *PortMapper) ReleaseAll(ctx context.Context) error {
	pm.mu.Lock()
	maps := make([]*Mapping, len(pm.activeMaps))
	copy(maps, pm.activeMaps)
	pm.activeMaps = nil
	pm.mu.Unlock()

	var errs []error
	for _, m := range maps {
		if err := m.Release(ctx); err != nil && !errors.Is(err, ErrMappingAlreadyReleased) {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("portmapper: errors releasing mappings: %v", errs)
	}
	return nil
}
