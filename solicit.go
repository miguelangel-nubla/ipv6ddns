package ipv6ddns

import (
	"context"
	"errors"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/filter"
	"github.com/miguelangel-nubla/ipv6disc"
)

const solicitInterval = time.Minute

// solicitLoop asks, every solicitInterval, for the addresses the tasks want which aren't otherwise
// found. IPv6: the EUI-64 addresses, as a stable address that sends no traffic is never seen, hosts
// sending from their temporary ones. IPv4: the addresses of the MACs IPv4 filters name, by ARP to
// each alone, so a quiet host is found with nothing broadcast.
func (w *Worker) solicitLoop(ctx context.Context) {
	d := w.config.Discovery
	solicitIPv6, solicitIPv4 := d.IPv6.Enabled && d.IPv6.Solicit, d.IPv4.Enabled && d.IPv4.Solicit
	ipv4Targets := ipv4SolicitTargets(w.config.Tasks)

	ticker := time.NewTicker(solicitInterval)
	defer ticker.Stop()
	for {
		if solicitIPv6 {
			for _, target := range eui64Targets(w.config.Tasks, w.discWorker.Prefixes()) {
				if _, err := w.discWorker.Solicit(target); err != nil {
					w.logger.Errorf("error soliciting %s: %s", target, err)
				}
			}
		}
		if solicitIPv4 && len(ipv4Targets) > 0 {
			_, err := w.discWorker.SolicitIPv4(ctx, ipv4Targets)
			switch {
			case errors.Is(err, errors.ErrUnsupported):
				w.logger.Warnf("no IPv4 solicitation: %s", err)
				solicitIPv4 = false
			case err != nil && ctx.Err() == nil:
				w.logger.Errorf("error soliciting IPv4 addresses: %s", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
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
			// Family 6 by default; a filter of IPv4 only wants no IPv6 address.
			ipv6 := len(f.IP.Family) == 0 || slices.Contains(f.IP.Family, 6)
			if f.MAC.Address == "" || !ipv6 || !slices.Contains(types, "eui64") {
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

// ipv4SolicitTargets returns the hosts to ask for their IPv4 addresses: the MACs a task's filter
// names and takes IPv4 addresses of, with the prefixes those filters want them in. A MAC that a
// filter without an IPv4 prefix names is asked on every local subnet.
func ipv4SolicitTargets(tasks map[string]config.Task) []ipv6disc.IPv4Target {
	index := make(map[string]int)
	anywhere := make(map[string]bool)
	var targets []ipv6disc.IPv4Target
	for _, name := range slices.Sorted(maps.Keys(tasks)) {
		for _, f := range tasks[name].Filters {
			if f.MAC.Address == "" || !slices.Contains(f.IP.Family, 4) {
				continue
			}
			mac, err := net.ParseMAC(f.MAC.Address)
			prefix := f.IP.Prefix
			// An IPv6 prefix takes no IPv4 address: nothing to ask.
			if err != nil || prefix.IsValid() && !prefix.Addr().Is4() {
				continue
			}
			key := mac.String()
			i, ok := index[key]
			if !ok {
				i = len(targets)
				index[key] = i
				targets = append(targets, ipv6disc.IPv4Target{MAC: mac})
			}
			switch {
			case !prefix.IsValid():
				anywhere[key] = true
			case !slices.Contains(targets[i].Prefixes, prefix.Masked()):
				targets[i].Prefixes = append(targets[i].Prefixes, prefix.Masked())
			}
		}
	}
	for i := range targets {
		if anywhere[targets[i].MAC.String()] {
			targets[i].Prefixes = nil
		}
	}
	return targets
}
