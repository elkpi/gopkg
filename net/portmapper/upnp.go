package portmapper

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	ssdpMulticastAddr = "239.255.255.250:1900"
)

// UPnPClient 实现了 UPnP IGD (Internet Gateway Device) 客户端。
type UPnPClient struct {
	controlURL  *url.URL
	serviceType string
	clientIP    net.IP
	description string
	httpClient  *http.Client
	mu          sync.Mutex
}

// NewUPnPClient 根据已知的 controlURL 和 serviceType 直接构造 UPnP 客户端。
func NewUPnPClient(controlURLStr, serviceType string, httpClient *http.Client) (*UPnPClient, error) {
	u, err := url.Parse(controlURLStr)
	if err != nil {
		return nil, err
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	return &UPnPClient{
		controlURL:  u,
		serviceType: serviceType,
		description: "gopkg-portmapper",
		httpClient:  httpClient,
	}, nil
}

// NewUPnPClientFromLocation 从设备的 root XML 描述地址初始化 UPnP 客户端。
func NewUPnPClientFromLocation(ctx context.Context, locationURLStr string, httpClient *http.Client) (*UPnPClient, error) {
	locURL, err := url.Parse(locationURLStr)
	if err != nil {
		return nil, err
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, locationURLStr, nil)
	if err != nil {
		return nil, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: failed to fetch device desc from %s (status %d)", ErrMappingFailed, locationURLStr, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	svcType, ctrlURLStr, err := parseRootDeviceXML(body)
	if err != nil {
		return nil, err
	}

	resolvedCtrlURL, err := locURL.Parse(ctrlURLStr)
	if err != nil {
		return nil, err
	}

	return &UPnPClient{
		controlURL:  resolvedCtrlURL,
		serviceType: svcType,
		description: "gopkg-portmapper",
		httpClient:  httpClient,
	}, nil
}

// Provider 返回提供者类型。
func (c *UPnPClient) Provider() Provider {
	return ProviderUPnP
}

// Close 释放客户端资源。
func (c *UPnPClient) Close() error {
	return nil
}

// SetLocalIP 设置映射使用的本机内网 IP。
func (c *UPnPClient) SetLocalIP(ip net.IP) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clientIP = ip
}

// SetDescription 设置 UPnP 映射描述。
func (c *UPnPClient) SetDescription(desc string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.description = desc
}

func (c *UPnPClient) getClientIP() (net.IP, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.clientIP != nil && !c.clientIP.IsUnspecified() {
		return c.clientIP, nil
	}

	host := c.controlURL.Hostname()
	targetIP := net.ParseIP(host)
	if targetIP != nil {
		ip, err := FindOutboundIP(targetIP)
		if err == nil {
			c.clientIP = ip
			return ip, nil
		}
	}

	ip, err := FindLocalIP()
	if err != nil {
		return nil, err
	}
	c.clientIP = ip
	return ip, nil
}

// XML 结构解析
type upnpRoot struct {
	XMLName xml.Name   `xml:"root"`
	Device  upnpDevice `xml:"device"`
}

type upnpDevice struct {
	DeviceType   string        `xml:"deviceType"`
	FriendlyName string        `xml:"friendlyName"`
	ServiceList  []upnpService `xml:"serviceList>service"`
	DeviceList   []upnpDevice  `xml:"deviceList>device"`
}

type upnpService struct {
	ServiceType string `xml:"serviceType"`
	ServiceId   string `xml:"serviceId"`
	ControlURL  string `xml:"controlURL"`
	SCPDURL     string `xml:"SCPDURL"`
}

func parseRootDeviceXML(xmlData []byte) (serviceType, controlURL string, err error) {
	var root upnpRoot
	if err := xml.Unmarshal(xmlData, &root); err != nil {
		return "", "", fmt.Errorf("%w: invalid XML device desc: %v", ErrMalformedResponse, err)
	}

	svcType, ctrlURL, found := findWANService(&root.Device)
	if !found {
		return "", "", fmt.Errorf("%w: no WANIPConnection or WANPPPConnection service found", ErrNoProviderAvailable)
	}

	return svcType, ctrlURL, nil
}

func findWANService(dev *upnpDevice) (string, string, bool) {
	for _, svc := range dev.ServiceList {
		if strings.Contains(svc.ServiceType, ":WANIPConnection:") ||
			strings.Contains(svc.ServiceType, ":WANPPPConnection:") {
			return svc.ServiceType, svc.ControlURL, true
		}
	}
	for i := range dev.DeviceList {
		if st, cu, ok := findWANService(&dev.DeviceList[i]); ok {
			return st, cu, true
		}
	}
	return "", "", false
}

type soapFaultEnvelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		Fault struct {
			FaultCode   string `xml:"faultcode"`
			FaultString string `xml:"faultstring"`
			Detail      struct {
				UPnPError struct {
					ErrorCode   int    `xml:"errorCode"`
					Description string `xml:"errorDescription"`
				} `xml:"UPnPError"`
			} `xml:"detail"`
		} `xml:"Fault"`
	} `xml:"Body"`
}

func (c *UPnPClient) executeSOAP(ctx context.Context, action string, argsXML string) ([]byte, error) {
	soapBody := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:%s xmlns:u="%s">
      %s
    </u:%s>
  </s:Body>
</s:Envelope>`, action, c.serviceType, argsXML, action)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.controlURL.String(), strings.NewReader(soapBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", fmt.Sprintf(`"%s#%s"`, c.serviceType, action))
	req.Header.Set("Connection", "close")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		var fault soapFaultEnvelope
		if xml.Unmarshal(respBody, &fault) == nil {
			errCode := fault.Body.Fault.Detail.UPnPError.ErrorCode
			errDesc := fault.Body.Fault.Detail.UPnPError.Description
			switch errCode {
			case 714: // NoSuchEntryInArray
				return nil, ErrMappingNotFound
			case 718: // ConflictInMappingEntry
				return nil, fmt.Errorf("%w: port conflict (code 718: %s)", ErrNoResources, errDesc)
			case 725: // OnlyPermanentLeasesSupported
				return nil, fmt.Errorf("%w: only permanent leases supported (code 725)", ErrMappingFailed)
			default:
				return nil, fmt.Errorf("%w: upnp soap fault %d (%s)", ErrMappingFailed, errCode, errDesc)
			}
		}
		return nil, fmt.Errorf("%w: HTTP status %d: %s", ErrMappingFailed, resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// AddPortMapping 请求 UPnP 端口映射。若路由器不支持指定租期（错误 725），将自动降级为永久租期（LeaseDuration 0）。
func (c *UPnPClient) AddPortMapping(ctx context.Context, proto Protocol, internalPort int, preferredExternal int, lifetime time.Duration) (*Mapping, error) {
	if proto != ProtocolTCP && proto != ProtocolUDP {
		return nil, ErrUnsupportedProtocol
	}

	clientIP, err := c.getClientIP()
	if err != nil {
		return nil, err
	}

	leaseDuration := int(lifetime.Seconds())
	if leaseDuration < 0 {
		leaseDuration = 0
	}

	args := fmt.Sprintf(`
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>%d</NewExternalPort>
<NewProtocol>%s</NewProtocol>
<NewInternalPort>%d</NewInternalPort>
<NewInternalClient>%s</NewInternalClient>
<NewEnabled>1</NewEnabled>
<NewPortMappingDescription>%s</NewPortMappingDescription>
<NewLeaseDuration>%d</NewLeaseDuration>`,
		preferredExternal, proto, internalPort, clientIP.String(), c.description, leaseDuration)

	_, err = c.executeSOAP(ctx, "AddPortMapping", args)
	if err != nil {
		// 若因不支持租期而失败（错误 725），尝试以永久租期重试
		if strings.Contains(err.Error(), "725") && leaseDuration != 0 {
			argsPermanent := fmt.Sprintf(`
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>%d</NewExternalPort>
<NewProtocol>%s</NewProtocol>
<NewInternalPort>%d</NewInternalPort>
<NewInternalClient>%s</NewInternalClient>
<NewEnabled>1</NewEnabled>
<NewPortMappingDescription>%s</NewPortMappingDescription>
<NewLeaseDuration>0</NewLeaseDuration>`,
				preferredExternal, proto, internalPort, clientIP.String(), c.description)
			_, err = c.executeSOAP(ctx, "AddPortMapping", argsPermanent)
			if err != nil {
				return nil, err
			}
			leaseDuration = 0
		} else {
			return nil, err
		}
	}

	extIP, _ := c.GetExternalIP(ctx)

	return &Mapping{
		client:       c,
		Protocol:     proto,
		InternalPort: internalPort,
		ExternalPort: preferredExternal,
		ExternalIP:   extIP,
		Lifetime:     time.Duration(leaseDuration) * time.Second,
		CreatedAt:    time.Now(),
		Provider:     ProviderUPnP,
	}, nil
}

// RenewMapping 以相同内外端口重新提交 AddPortMapping 续租。
func (c *UPnPClient) RenewMapping(ctx context.Context, m *Mapping, lifetime time.Duration) (*Mapping, error) {
	return c.AddPortMapping(ctx, m.Protocol, m.InternalPort, m.ExternalPort, lifetime)
}

// DeletePortMapping 删除 UPnP 端口映射。
func (c *UPnPClient) DeletePortMapping(ctx context.Context, m *Mapping) error {
	args := fmt.Sprintf(`
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>%d</NewExternalPort>
<NewProtocol>%s</NewProtocol>`, m.ExternalPort, m.Protocol)

	_, err := c.executeSOAP(ctx, "DeletePortMapping", args)
	if err != nil {
		if errors.Is(err, ErrMappingNotFound) {
			return nil
		}
		return err
	}
	return nil
}

// GetExternalIP 获取 UPnP 路由器的外部公网 IP。
func (c *UPnPClient) GetExternalIP(ctx context.Context) (net.IP, error) {
	respBody, err := c.executeSOAP(ctx, "GetExternalIPAddress", "")
	if err != nil {
		return nil, err
	}

	var resp struct {
		XMLName xml.Name `xml:"Envelope"`
		Body    struct {
			GetExternalIPAddressResponse struct {
				NewExternalIPAddress string `xml:"NewExternalIPAddress"`
			} `xml:"GetExternalIPAddressResponse"`
		} `xml:"Body"`
	}

	if err := xml.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("%w: failed to parse GetExternalIPAddressResponse: %v", ErrMalformedResponse, err)
	}

	ipStr := strings.TrimSpace(resp.Body.GetExternalIPAddressResponse.NewExternalIPAddress)
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("%w: invalid external IP string '%s'", ErrMalformedResponse, ipStr)
	}

	return ip, nil
}

// DiscoverUPnPGateway 通过 SSDP M-SEARCH 广播发现局域网内的 UPnP IGD 网关。
func DiscoverUPnPGateway(ctx context.Context, httpClient *http.Client) (*UPnPClient, error) {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}

	// 监听临时 UDP 端口用于接收响应
	udpConn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, err
	}
	defer udpConn.Close()

	raddr, err := net.ResolveUDPAddr("udp4", ssdpMulticastAddr)
	if err != nil {
		return nil, err
	}

	searchTargets := []string{
		"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
		"urn:schemas-upnp-org:service:WANIPConnection:1",
		"urn:schemas-upnp-org:service:WANPPPConnection:1",
	}

	for _, target := range searchTargets {
		searchMsg := fmt.Sprintf(
			"M-SEARCH * HTTP/1.1\r\n"+
				"HOST: %s\r\n"+
				"ST: %s\r\n"+
				"MAN: \"ssdp:discover\"\r\n"+
				"MX: 2\r\n\r\n", ssdpMulticastAddr, target)

		_, _ = udpConn.WriteToUDP([]byte(searchMsg), raddr)
	}

	type result struct {
		client *UPnPClient
		err    error
	}
	resCh := make(chan result, 1)

	go func() {
		buf := make([]byte, 2048)
		discoveredLocations := make(map[string]bool)

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			_ = udpConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, _, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					continue
				}
				return
			}

			location := parseSSDPLocation(buf[:n])
			if location == "" || discoveredLocations[location] {
				continue
			}
			discoveredLocations[location] = true

			client, err := NewUPnPClientFromLocation(ctx, location, httpClient)
			if err == nil && client != nil {
				select {
				case resCh <- result{client: client}:
				default:
				}
				return
			}
		}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-resCh:
		return res.client, res.err
	case <-time.After(2500 * time.Millisecond):
		return nil, ErrNoProviderAvailable
	}
}

// parseSSDPLocation 从 SSDP HTTP 响应头中解析 LOCATION。
func parseSSDPLocation(data []byte) string {
	reader := bufio.NewReader(bytes.NewReader(data))
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "location:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}
