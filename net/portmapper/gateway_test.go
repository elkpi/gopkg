package portmapper

import (
	"net"
	"strings"
	"testing"
)

func TestParseLinuxRoute(t *testing.T) {
	sampleRoute := `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	0101A8C0	0003	0	0	100	00000000	0	0	0
wlan0	0006A8C0	00000000	0001	0	0	0	00FFFFFF	0	0	0
`
	gw, err := parseLinuxRoute(strings.NewReader(sampleRoute))
	if err != nil {
		t.Fatalf("unexpected error parsing route: %v", err)
	}

	expected := net.IPv4(192, 168, 1, 1)
	if !gw.Equal(expected) {
		t.Errorf("expected gateway %v, got %v", expected, gw)
	}
}

func TestParseLinuxRoute_NoDefaultRoute(t *testing.T) {
	sampleRoute := `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
wlan0	0006A8C0	00000000	0001	0	0	0	00FFFFFF	0	0	0
`
	_, err := parseLinuxRoute(strings.NewReader(sampleRoute))
	if err == nil {
		t.Fatal("expected error when no default route exists, got nil")
	}
}

func TestFindLocalIP(t *testing.T) {
	ip, err := FindLocalIP()
	if err != nil {
		t.Logf("FindLocalIP returned error in test env: %v", err)
		return
	}
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() {
		t.Errorf("invalid local IP found: %v", ip)
	}
}
