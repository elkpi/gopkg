package portmapper

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Protocol 表示端口映射所用的传输层协议。
type Protocol string

const (
	ProtocolTCP Protocol = "TCP"
	ProtocolUDP Protocol = "UDP"
)

// Provider 表示端口映射的服务协议类型。
type Provider string

const (
	ProviderPCP    Provider = "PCP"
	ProviderNATPMP Provider = "NAT-PMP"
	ProviderUPnP   Provider = "UPnP-IGD"
)

// 常见错误定义
var (
	ErrNoGatewayFound         = errors.New("portmapper: default gateway IP not found")
	ErrNoProviderAvailable    = errors.New("portmapper: no compatible port mapping provider responded")
	ErrMappingFailed          = errors.New("portmapper: port mapping request failed")
	ErrUnsupportedProtocol    = errors.New("portmapper: unsupported protocol")
	ErrUnsupportedVersion     = errors.New("portmapper: unsupported protocol version")
	ErrNotAuthorized          = errors.New("portmapper: not authorized by gateway")
	ErrNoResources            = errors.New("portmapper: gateway out of resources")
	ErrMappingNotFound        = errors.New("portmapper: mapping not found or already deleted")
	ErrGatewayNetworkFailure  = errors.New("portmapper: gateway reported network failure")
	ErrMalformedResponse      = errors.New("portmapper: malformed response from gateway")
	ErrMappingAlreadyReleased = errors.New("portmapper: mapping has already been released")
)

// Client 是各底层端口映射协议（NAT-PMP、PCP、UPnP）的统一接口。
type Client interface {
	Provider() Provider
	GetExternalIP(ctx context.Context) (net.IP, error)
	AddPortMapping(ctx context.Context, proto Protocol, internalPort int, preferredExternal int, lifetime time.Duration) (*Mapping, error)
	// RenewMapping 续租 m 代表的映射。PCP 实现必须复用 m 创建时的 nonce，
	// 以免被严格网关按 NOT_AUTHORIZED 拒绝。
	RenewMapping(ctx context.Context, m *Mapping, lifetime time.Duration) (*Mapping, error)
	DeletePortMapping(ctx context.Context, m *Mapping) error
	Close() error
}

// Config 为 PortMapper 的配置项。
type Config struct {
	// GatewayIP 指定缺省网关 IP；若为空则自动通过系统路由表探测。
	GatewayIP net.IP
	// LocalIP 指定本机用于映射的内网 IP；若为空则自动根据与网关的连接推导。
	LocalIP net.IP
	// PreferredProviders 定义协议探测优先级顺序。默认：[ProviderPCP, ProviderNATPMP, ProviderUPnP]。
	PreferredProviders []Provider
	// DefaultLifetime 端口映射默认租约时长，默认为 2 小时。
	DefaultLifetime time.Duration
	// ProbeTimeout 单个单播探测步骤的超时，默认为 1.5 秒。
	ProbeTimeout time.Duration
	// Description 映射描述信息（UPnP 使用），默认为 "gopkg-portmapper"。
	Description string
	// HTTPClient 用于 UPnP 调用的 HTTP 客户端。若为空则使用默认客户端。
	HTTPClient *http.Client

	// NATPMPPort 指定 NAT-PMP 服务的端口（默认 5351）。
	NATPMPPort int
	// PCPPort 指定 PCP 服务的端口（默认 5351）。
	PCPPort int
}

// DefaultConfig 返回推荐的默认配置。
func DefaultConfig() Config {
	return Config{
		PreferredProviders: []Provider{ProviderPCP, ProviderNATPMP, ProviderUPnP},
		DefaultLifetime:    2 * time.Hour,
		ProbeTimeout:       1500 * time.Millisecond,
		Description:        "gopkg-portmapper",
	}
}

// Mapping 表示一个已生效的网关端口映射租约。
type Mapping struct {
	mu           sync.Mutex
	client       Client
	Protocol     Protocol      `json:"protocol"`
	InternalPort int           `json:"internal_port"`
	ExternalPort int           `json:"external_port"`
	ExternalIP   net.IP        `json:"external_ip"`
	Lifetime     time.Duration `json:"lifetime"`
	CreatedAt    time.Time     `json:"created_at"`
	Provider     Provider      `json:"provider"`

	// PCP 专用状态
	nonce [12]byte

	released    bool
	renewCancel context.CancelFunc
}

// ExternalAddr 返回外部完整地址（IP:Port）。
func (m *Mapping) ExternalAddr() string {
	if m.ExternalIP == nil {
		return strconv.Itoa(m.ExternalPort)
	}
	return net.JoinHostPort(m.ExternalIP.String(), strconv.Itoa(m.ExternalPort))
}

// String 格式化映射详情。
func (m *Mapping) String() string {
	return fmt.Sprintf("%s mapping via %s: local %d -> ext %s (ttl %v)",
		m.Protocol, m.Provider, m.InternalPort, m.ExternalAddr(), m.Lifetime)
}

// Renew 为当前映射续期指定的时长。
func (m *Mapping) Renew(ctx context.Context, lifetime time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.released {
		return ErrMappingAlreadyReleased
	}
	if m.client == nil {
		return ErrMappingNotFound
	}

	newMapping, err := m.client.RenewMapping(ctx, m, lifetime)
	if err != nil {
		return err
	}

	m.ExternalPort = newMapping.ExternalPort
	if newMapping.ExternalIP != nil {
		m.ExternalIP = newMapping.ExternalIP
	}
	m.Lifetime = newMapping.Lifetime
	m.CreatedAt = time.Now()
	// m.nonce 保持不变：续租的映射身份与原映射相同。
	return nil
}

// Release 显式清理并注销网关上的端口映射。
func (m *Mapping) Release(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.released {
		return nil
	}
	if m.renewCancel != nil {
		m.renewCancel()
		m.renewCancel = nil
	}
	m.released = true

	if m.client == nil {
		return nil
	}
	return m.client.DeletePortMapping(ctx, m)
}

// IsReleased 检查该映射是否已被注销。
func (m *Mapping) IsReleased() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.released
}

// AutoRenew 启动后台协程自动定期为映射续期（按 interval 周期执行）。
// 返回的 stop 函数用于主动停止自动续期。
func (m *Mapping) AutoRenew(ctx context.Context, interval time.Duration) (stop func()) {
	m.mu.Lock()
	if m.released {
		m.mu.Unlock()
		return func() {}
	}
	if m.renewCancel != nil {
		m.renewCancel()
	}
	renewCtx, cancel := context.WithCancel(ctx)
	m.renewCancel = cancel
	m.mu.Unlock()

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-renewCtx.Done():
				return
			case <-ticker.C:
				m.mu.Lock()
				released := m.released
				lifetime := m.Lifetime
				m.mu.Unlock()
				if released {
					return
				}
				_ = m.Renew(renewCtx, lifetime)
			}
		}
	}()

	return cancel
}
