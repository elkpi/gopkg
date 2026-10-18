package portmapper

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// MockGatewayOption 配置 Mock 网关特性。
type MockGatewayOption struct {
	EnablePCP    bool
	EnableNATPMP bool
	EnableUPnP   bool

	PCPResultCode    uint8
	NATPMPResultCode uint16
	UPnPRejectLease  bool // 模拟 725 错误

	ExternalIP net.IP
}

// DefaultMockOptions 返回默认全启用的网关配置。
func DefaultMockOptions() MockGatewayOption {
	return MockGatewayOption{
		EnablePCP:    true,
		EnableNATPMP: true,
		EnableUPnP:   true,
		ExternalIP:   net.ParseIP("203.0.113.199"),
	}
}

// MockGateway 是支持多协议模拟的仿真网关。
type MockGateway struct {
	opts MockGatewayOption

	// NAT-PMP & PCP UDP 监听
	udpConn *net.UDPConn
	UDPPort int

	// UPnP HTTP 模拟
	httpServer *httptest.Server
	RootXMLURL string

	mu           sync.Mutex
	mappingsPCP  map[string]int // nonce -> externalPort
	mappingsPMP  map[int]int    // internalPort -> externalPort
	mappingsUPnP map[string]int // key -> externalPort

	closed bool
}

// StartMockGateway 启动一个轻量级的全功能 Mock 网关。
func StartMockGateway(opts MockGatewayOption) (*MockGateway, error) {
	if opts.ExternalIP == nil {
		opts.ExternalIP = net.ParseIP("203.0.113.199")
	}

	mg := &MockGateway{
		opts:         opts,
		mappingsPCP:  make(map[string]int),
		mappingsPMP:  make(map[int]int),
		mappingsUPnP: make(map[string]int),
	}

	// 1. 启动 UDP 监听（处理 NAT-PMP 与 PCP）
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		return nil, err
	}
	mg.udpConn = udpConn
	mg.UDPPort = udpConn.LocalAddr().(*net.UDPAddr).Port

	go mg.serveUDP()

	// 2. 启动 UPnP HTTP 控制点
	if opts.EnableUPnP {
		mux := http.NewServeMux()
		mux.HandleFunc("/rootDesc.xml", mg.handleUPnPRootDesc)
		mux.HandleFunc("/ctl/IPConn", mg.handleUPnPControl)
		mg.httpServer = httptest.NewServer(mux)
		mg.RootXMLURL = mg.httpServer.URL + "/rootDesc.xml"
	}

	return mg, nil
}

// Close 停止网关仿真。
func (mg *MockGateway) Close() {
	mg.mu.Lock()
	defer mg.mu.Unlock()
	if mg.closed {
		return
	}
	mg.closed = true

	if mg.udpConn != nil {
		_ = mg.udpConn.Close()
	}
	if mg.httpServer != nil {
		mg.httpServer.Close()
	}
}

func (mg *MockGateway) serveUDP() {
	buf := make([]byte, 512)
	for {
		n, remoteAddr, err := mg.udpConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < 2 {
			continue
		}

		version := buf[0]
		switch version {
		case 0: // NAT-PMP (RFC 6886)
			if !mg.opts.EnableNATPMP {
				continue
			}
			mg.handleNATPMP(buf[:n], remoteAddr)

		case 2: // PCP (RFC 6887)
			if !mg.opts.EnablePCP {
				continue
			}
			mg.handlePCP(buf[:n], remoteAddr)
		}
	}
}

func (mg *MockGateway) handleNATPMP(req []byte, remote *net.UDPAddr) {
	op := req[1]
	switch op {
	case natpmpOpExternalIP:
		resp := make([]byte, 12)
		resp[0] = 0
		resp[1] = natpmpRespOpExternalIP
		binary.BigEndian.PutUint16(resp[2:4], mg.opts.NATPMPResultCode)
		binary.BigEndian.PutUint32(resp[4:8], 12345) // epoch
		copy(resp[8:12], mg.opts.ExternalIP.To4())
		_, _ = mg.udpConn.WriteToUDP(resp, remote)

	case natpmpOpMapTCP, natpmpOpMapUDP:
		if len(req) < 12 {
			return
		}
		internalPort := binary.BigEndian.Uint16(req[4:6])
		prefExtPort := binary.BigEndian.Uint16(req[6:8])
		lifetime := binary.BigEndian.Uint32(req[8:12])

		mg.mu.Lock()
		assignedPort := int(prefExtPort)
		if assignedPort == 0 {
			assignedPort = int(internalPort)
		}
		if lifetime == 0 {
			delete(mg.mappingsPMP, int(internalPort))
		} else {
			mg.mappingsPMP[int(internalPort)] = assignedPort
		}
		mg.mu.Unlock()

		resp := make([]byte, 16)
		resp[0] = 0
		resp[1] = op + 128
		binary.BigEndian.PutUint16(resp[2:4], mg.opts.NATPMPResultCode)
		binary.BigEndian.PutUint32(resp[4:8], 12345)
		binary.BigEndian.PutUint16(resp[8:10], internalPort)
		binary.BigEndian.PutUint16(resp[10:12], uint16(assignedPort))
		binary.BigEndian.PutUint32(resp[12:16], lifetime)
		_, _ = mg.udpConn.WriteToUDP(resp, remote)
	}
}

func (mg *MockGateway) handlePCP(req []byte, remote *net.UDPAddr) {
	if len(req) < 60 {
		return
	}
	opcode := req[1]

	// ANNOUNCE：零副作用探测，返回外部 IP
	if opcode == pcpOpcodeAnnounce {
		resp := make([]byte, 60)
		resp[0] = pcpVersion
		resp[1] = pcpOpcodeAnnounce | pcpRespMask
		resp[3] = mg.opts.PCPResultCode
		binary.BigEndian.PutUint32(resp[8:12], 54321)
		copy(resp[44:60], mg.opts.ExternalIP.To16())
		_, _ = mg.udpConn.WriteToUDP(resp, remote)
		return
	}

	if opcode != pcpOpcodeMap {
		return
	}

	lifetime := binary.BigEndian.Uint32(req[4:8])
	var nonce [12]byte
	copy(nonce[:], req[24:36])
	proto := req[36]
	internalPort := binary.BigEndian.Uint16(req[40:42])
	suggestedExtPort := binary.BigEndian.Uint16(req[42:44])

	mg.mu.Lock()
	assignedPort := int(suggestedExtPort)
	if assignedPort == 0 {
		assignedPort = int(internalPort)
	}
	nonceKey := string(nonce[:])
	if lifetime == 0 {
		delete(mg.mappingsPCP, nonceKey)
	} else {
		mg.mappingsPCP[nonceKey] = assignedPort
	}
	mg.mu.Unlock()

	resp := make([]byte, 60)
	resp[0] = pcpVersion
	resp[1] = pcpOpcodeMap | pcpRespMask // 0x81
	resp[2] = 0
	resp[3] = mg.opts.PCPResultCode
	binary.BigEndian.PutUint32(resp[4:8], lifetime)
	binary.BigEndian.PutUint32(resp[8:12], 54321) // Epoch

	copy(resp[24:36], nonce[:])
	resp[36] = proto
	binary.BigEndian.PutUint16(resp[40:42], internalPort)
	binary.BigEndian.PutUint16(resp[42:44], uint16(assignedPort))
	copy(resp[44:60], mg.opts.ExternalIP.To16())

	_, _ = mg.udpConn.WriteToUDP(resp, remote)
}

func (mg *MockGateway) handleUPnPRootDesc(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	_, _ = w.Write([]byte(sampleRootXML))
}

func (mg *MockGateway) handleUPnPControl(w http.ResponseWriter, r *http.Request) {
	action := r.Header.Get("SOAPAction")
	body, _ := io.ReadAll(r.Body)
	bodyStr := string(body)

	w.Header().Set("Content-Type", "text/xml; charset=utf-8")

	if strings.Contains(action, "GetExternalIPAddress") {
		resp := fmt.Sprintf(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewExternalIPAddress>%s</NewExternalIPAddress>
    </u:GetExternalIPAddressResponse>
  </s:Body>
</s:Envelope>`, mg.opts.ExternalIP.String())
		_, _ = w.Write([]byte(resp))
		return
	}

	if strings.Contains(action, "AddPortMapping") {
		if mg.opts.UPnPRejectLease && strings.Contains(bodyStr, "<NewLeaseDuration>3600</NewLeaseDuration>") {
			w.WriteHeader(http.StatusInternalServerError)
			resp := `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <s:Fault>
      <faultcode>s:Client</faultcode>
      <faultstring>UPnPError</faultstring>
      <detail>
        <UPnPError xmlns="urn:schemas-upnp-org:control-1-0">
          <errorCode>725</errorCode>
          <errorDescription>OnlyPermanentLeasesSupported</errorDescription>
        </UPnPError>
      </detail>
    </s:Fault>
  </s:Body>
</s:Envelope>`
			_, _ = w.Write([]byte(resp))
			return
		}

		resp := `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:AddPortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"/>
  </s:Body>
</s:Envelope>`
		_, _ = w.Write([]byte(resp))
		return
	}

	if strings.Contains(action, "DeletePortMapping") {
		resp := `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:DeletePortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"/>
  </s:Body>
</s:Envelope>`
		_, _ = w.Write([]byte(resp))
		return
	}

	http.NotFound(w, r)
}
