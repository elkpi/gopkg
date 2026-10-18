package portmapper

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const sampleRootXML = `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>Mock Gateway Router</friendlyName>
    <deviceList>
      <device>
        <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
        <deviceList>
          <device>
            <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
            <serviceList>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
                <controlURL>/ctl/IPConn</controlURL>
                <eventSubURL>/evt/IPConn</eventSubURL>
                <SCPDURL>/WANIPCn.xml</SCPDURL>
              </service>
            </serviceList>
          </device>
        </deviceList>
      </device>
    </deviceList>
  </device>
</root>`

func TestParseRootDeviceXML(t *testing.T) {
	svcType, ctrlURL, urlBase, err := parseRootDeviceXML([]byte(sampleRootXML))
	if err != nil {
		t.Fatalf("unexpected error parsing root XML: %v", err)
	}

	expectedSvc := "urn:schemas-upnp-org:service:WANIPConnection:1"
	if svcType != expectedSvc {
		t.Errorf("expected service type %s, got %s", expectedSvc, svcType)
	}

	expectedCtrl := "/ctl/IPConn"
	if ctrlURL != expectedCtrl {
		t.Errorf("expected control URL %s, got %s", expectedCtrl, ctrlURL)
	}
	if urlBase != "" {
		t.Errorf("expected empty URLBase, got %s", urlBase)
	}
}

func TestParseSSDPLocation(t *testing.T) {
	resp := "HTTP/1.1 200 OK\r\n" +
		"CACHE-CONTROL: max-age=120\r\n" +
		"LOCATION: http://192.168.1.1:1900/rootDesc.xml\r\n" +
		"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"

	loc := parseSSDPLocation([]byte(resp))
	expected := "http://192.168.1.1:1900/rootDesc.xml"
	if loc != expected {
		t.Errorf("expected location %s, got %s", expected, loc)
	}
}

func TestUPnPClient_DescriptionIsXMLEscaped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rootDesc.xml" {
			w.Header().Set("Content-Type", "text/xml")
			_, _ = w.Write([]byte(sampleRootXML))
			return
		}
		body, _ := io.ReadAll(r.Body)
		dec := xml.NewDecoder(strings.NewReader(string(body)))
		if err := dec.Decode(new(any)); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0"?><Envelope><Body><AddPortMappingResponse/></Body></Envelope>`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	client, err := NewUPnPClientFromLocation(ctx, srv.URL+"/rootDesc.xml", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	client.SetLocalIP(net.ParseIP("127.0.0.1"))
	client.SetDescription("review & test")

	if _, err := client.AddPortMapping(ctx, ProtocolTCP, 12345, 12345, time.Hour); err != nil {
		t.Fatalf("包含 & 的合法描述破坏了 SOAP XML：%v", err)
	}
}

func TestUPnPClient_HonorsURLBase(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rootDesc.xml" {
			w.Header().Set("Content-Type", "text/xml")
			fmt.Fprintf(w, `<?xml version="1.0"?>
<root>
  <URLBase>%s/service/</URLBase>
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <serviceList>
      <service>
        <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
        <controlURL>ctl/IPConn</controlURL>
      </service>
    </serviceList>
  </device>
</root>`, srv.URL)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	client, err := NewUPnPClientFromLocation(ctx, srv.URL+"/rootDesc.xml", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if want := srv.URL + "/service/ctl/IPConn"; client.controlURL.String() != want {
		t.Fatalf("controlURL = %s，期望按 URLBase 解析为 %s", client.controlURL, want)
	}
}

func TestUPnPClient_MockServer(t *testing.T) {
	var addCalls, delCalls, getIPCalls int

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rootDesc.xml":
			w.Header().Set("Content-Type", "text/xml")
			_, _ = w.Write([]byte(sampleRootXML))
			return

		case "/ctl/IPConn":
			action := r.Header.Get("SOAPAction")
			bodyBytes, _ := io.ReadAll(r.Body)
			bodyStr := string(bodyBytes)

			if strings.Contains(action, "GetExternalIPAddress") {
				getIPCalls++
				resp := `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewExternalIPAddress>198.51.100.200</NewExternalIPAddress>
    </u:GetExternalIPAddressResponse>
  </s:Body>
</s:Envelope>`
				w.Header().Set("Content-Type", "text/xml")
				_, _ = w.Write([]byte(resp))
				return
			}

			if strings.Contains(action, "AddPortMapping") {
				addCalls++
				// 模拟路由器对非零租期返回 725 错误（OnlyPermanentLeasesSupported），促使客户端降级为 0
				if strings.Contains(bodyStr, "<NewLeaseDuration>3600</NewLeaseDuration>") {
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
				w.Header().Set("Content-Type", "text/xml")
				_, _ = w.Write([]byte(resp))
				return
			}

			if strings.Contains(action, "DeletePortMapping") {
				delCalls++
				resp := `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:DeletePortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"/>
  </s:Body>
</s:Envelope>`
				w.Header().Set("Content-Type", "text/xml")
				_, _ = w.Write([]byte(resp))
				return
			}

		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// 从 mock server 根地址初始化
	client, err := NewUPnPClientFromLocation(ctx, ts.URL+"/rootDesc.xml", ts.Client())
	if err != nil {
		t.Fatalf("failed to create UPnP client: %v", err)
	}

	if client.Provider() != ProviderUPnP {
		t.Errorf("expected provider UPnP, got %v", client.Provider())
	}

	// 1. 获取外部公网 IP
	ip, err := client.GetExternalIP(ctx)
	if err != nil {
		t.Fatalf("GetExternalIP failed: %v", err)
	}
	if ip.String() != "198.51.100.200" {
		t.Errorf("expected 198.51.100.200, got %s", ip.String())
	}

	// 2. 添加端口映射（验证 725 租期自动降级）
	mapping, err := client.AddPortMapping(ctx, ProtocolTCP, 8080, 8080, 1*time.Hour)
	if err != nil {
		t.Fatalf("AddPortMapping failed: %v", err)
	}
	if mapping.ExternalPort != 8080 {
		t.Errorf("expected external port 8080, got %d", mapping.ExternalPort)
	}
	if mapping.Lifetime != 0 {
		t.Errorf("expected lifetime 0 after 725 retry, got %v", mapping.Lifetime)
	}

	// 3. 删除端口映射
	if err := client.DeletePortMapping(ctx, mapping); err != nil {
		t.Fatalf("DeletePortMapping failed: %v", err)
	}

	if addCalls < 2 {
		t.Errorf("expected at least 2 AddPortMapping calls due to 725 fallback, got %d", addCalls)
	}
	if delCalls != 1 {
		t.Errorf("expected 1 DeletePortMapping call, got %d", delCalls)
	}
}
