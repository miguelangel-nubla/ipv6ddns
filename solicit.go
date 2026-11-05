package ipv6ddns

import (
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/filter"
)

const solicitInterval = time.Minute

// solicitEUI64Loop asks for the EUI-64 addresses the tasks want. A stable address that sends no
// traffic is never seen otherwise, as hosts send from their temporary ones: routers don't learn it.
func (w *Worker) solicitEUI64Loop() {
	for {
		for _, target := range eui64Targets(w.config.Tasks, w.discWorker.Prefixes()) {
			if _, err := w.discWorker.Solicit(target); err != nil {
				w.logger.Errorf("error soliciting %s: %s", target, err)
			}
		}
		time.Sleep(solicitInterval)
	}
}

// eui64Targets returns the addresses to solicit: on each prefix, the EUI-64 address of every MAC
// that a task's filter names and asks an eui64 address of.
func eui64Targets(tasks map[string]config.Task, prefixes []netip.Prefix) []netip.Addr {
	seen := make(map[netip.Addr]bool)
	var targets []netip.Addr
	for _, task := range tasks {
		for _, f := range task.Filters {
			types := make([]string, len(f.IP.Type))
			for i, t := range f.IP.Type {
				types[i] = strings.ToLower(t)
			}
			if f.MAC.Address == "" || !slices.Contains(types, "eui64") {
				continue
			}
			mac, err := net.ParseMAC(f.MAC.Address)
			if err != nil {
				continue
			}
			for _, prefix := range prefixes {
				target, ok := eui64Address(prefix, mac)
				if !ok || seen[target] || !wantedScope(target, types) || !filter.CheckPrefix(target, f.IP.Prefix) {
					continue
				}
				seen[target] = true
				targets = append(targets, target)
			}
		}
	}
	return targets
}

// wantedScope tells whether the types ask for this kind of address; asking for neither global nor
// ula means both.
func wantedScope(addr netip.Addr, types []string) bool {
	global, ula := slices.Contains(types, "global"), slices.Contains(types, "ula")
	if !global && !ula {
		return true
	}
	if netip.MustParsePrefix("fc00::/7").Contains(addr) {
		return ula
	}
	return global
}

// eui64Address builds the address a MAC gets on a /64 (RFC 4291, appendix A).
func eui64Address(prefix netip.Prefix, mac net.HardwareAddr) (netip.Addr, bool) {
	if prefix.Bits() != 64 || !prefix.Addr().Is6() || len(mac) != 6 {
		return netip.Addr{}, false
	}
	addr := prefix.Masked().Addr().As16()
	addr[8] = mac[0] ^ 2
	addr[9] = mac[1]
	addr[10] = mac[2]
	addr[11] = 0xff
	addr[12] = 0xfe
	addr[13] = mac[3]
	addr[14] = mac[4]
	addr[15] = mac[5]
	return netip.AddrFrom16(addr), true
}
