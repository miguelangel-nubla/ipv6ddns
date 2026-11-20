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
	"go.uber.org/zap"
)

const solicitInterval = time.Minute

// solicitPrefixInterval is how often the worker looks for a /64 that the discovery came to listen
// on, to ask on it without waiting for the next round: at the start none is listened on yet.
const solicitPrefixInterval = 2 * time.Second

// solicitLoop asks, every solicitInterval, for the addresses the tasks want which aren't otherwise
// found. IPv6: the EUI-64 addresses, as a stable address that sends no traffic is never seen, hosts
// sending from their temporary ones; on a /64 that comes between two rounds, as all do at the
// start, as soon as it is listened on. IPv4: the addresses of the MACs IPv4 filters name, by ARP
// to each alone, so a quiet host is found with nothing broadcast.
func (w *Worker) solicitLoop(ctx context.Context) {
	d := w.config.Discovery
	solicitIPv6, solicitIPv4 := d.IPv6.Enabled && d.IPv6.Solicit, d.IPv4.Enabled && d.IPv4.Solicit
	ipv4Targets := ipv4SolicitTargets(w.config.Tasks)
	ipv6 := eui64Solicitor{tasks: w.config.Tasks, solicit: w.discWorker.Solicit, logger: w.logger}

	ticker := time.NewTicker(solicitInterval)
	defer ticker.Stop()
	// Without IPv6 solicitation, no prefixes to look for: a nil channel never fires.
	var newPrefixes <-chan time.Time
	if solicitIPv6 {
		prefixTicker := time.NewTicker(solicitPrefixInterval)
		defer prefixTicker.Stop()
		newPrefixes = prefixTicker.C
	}
	for round := true; ; {
		if solicitIPv6 {
			ipv6.ask(w.discWorker.Prefixes(), round)
		}
		if round && solicitIPv4 && len(ipv4Targets) > 0 {
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
			round = true
		case <-newPrefixes:
			round = false
		}
	}
}

// eui64Solicitor asks for the EUI-64 addresses the tasks want, on the /64s it is told of.
type eui64Solicitor struct {
	tasks map[string]config.Task
	// Worker.Solicit of the discovery: how many links the solicitation went out on.
	solicit func(netip.Addr) (int, error)
	logger  *zap.SugaredLogger
	// The /64s asked on in the last round or since, of those still there.
	asked map[netip.Prefix]bool
}

// ask solicits the addresses on the prefixes: on all of them in a round, on the ones not yet asked
// on otherwise. One that went and came back is asked on again.
func (s *eui64Solicitor) ask(prefixes []netip.Prefix, round bool) {
	asked := make(map[netip.Prefix]bool, len(prefixes))
	var pending []netip.Prefix
	for _, prefix := range prefixes {
		if round || !s.asked[prefix] {
			pending = append(pending, prefix)
		}
		asked[prefix] = true
	}
	s.asked = asked

	for _, target := range eui64Targets(s.tasks, pending) {
		sent, err := s.solicit(target)
		if err != nil {
			s.logger.Errorf("error soliciting %s: %s", target, err)
			continue
		}
		s.logger.Debugf("solicited %s on %d links", target, sent)
	}
}

// eui64Targets returns the addresses to solicit: on each prefix, the EUI-64 address of every MAC
// that a task's filter names and asks an eui64 address of. The prefixes are those the discovery
// listens on, which are never link-local: no fe80:: address is asked for.
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
				if !ok || seen[target] || !wanted(f, mac, target) {
					continue
				}
				seen[target] = true
				targets = append(targets, target)
			}
		}
	}
	return targets
}

// wanted tells whether the filter takes the address, of the MAC: its IP rules, by the filter's own
// checks. The other rules, as mac.mask and self, aren't looked at: an address that answers is
// matched by the whole filter, as any other, so at worst one is asked for nothing.
func wanted(f config.Filters, mac net.HardwareAddr, target netip.Addr) bool {
	// The checks read the address and its MAC only: no timers.
	addr := &ipv6disc.Addr{Addr: target, Hw: mac}
	return filter.CheckIPType(addr, f.IP.Type) && filter.CheckPrefix(target, f.IP.Prefix) &&
		filter.CheckSuffix(target, f.IP.Suffix) && filter.CheckMask(target, f.IP.Mask)
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
