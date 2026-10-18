package underlay

import (
	"errors"
	"fmt"
	"net/netip"
)

var ErrProtectedDestination = errors.New("public carrier destination overlaps a protected overlay prefix")

func (f *Factory) Mark() uint32 { return f.mark }

func (f *Factory) WithProtectedNetworks(prefixes []netip.Prefix) *Factory {
	clone := *f
	clone.protected = append([]netip.Prefix(nil), prefixes...)
	return &clone
}

func (f *Factory) CheckDestination(ip netip.Addr) error {
	if !ip.IsValid() {
		return errors.New("invalid public carrier destination")
	}
	for _, prefix := range f.protected {
		if prefix.Contains(ip.Unmap()) {
			return fmt.Errorf("%w: %s within %s", ErrProtectedDestination, ip, prefix)
		}
	}
	return nil
}
