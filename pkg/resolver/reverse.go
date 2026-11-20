package resolver

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// reverseAddr is the address a name of in-addr.arpa or ip6.arpa is the reverse of: false for any
// other name, and for one of a network, with fewer labels than an address has.
func reverseAddr(name string) (netip.Addr, bool) {
	name = strings.ToLower(dns.Fqdn(name))
	switch {
	case strings.HasSuffix(name, ".in-addr.arpa."):
		labels := strings.Split(strings.TrimSuffix(name, ".in-addr.arpa."), ".")
		if len(labels) != 4 {
			return netip.Addr{}, false
		}
		var b [4]byte
		for i, l := range labels {
			n, err := strconv.ParseUint(l, 10, 8)
			if err != nil || strconv.FormatUint(n, 10) != l {
				return netip.Addr{}, false
			}
			b[3-i] = byte(n)
		}
		return netip.AddrFrom4(b), true
	case strings.HasSuffix(name, ".ip6.arpa."):
		labels := strings.Split(strings.TrimSuffix(name, ".ip6.arpa."), ".")
		if len(labels) != 32 {
			return netip.Addr{}, false
		}
		var b [16]byte
		for i, l := range labels {
			n, err := strconv.ParseUint(l, 16, 8)
			if err != nil || len(l) != 1 {
				return netip.Addr{}, false
			}
			// The last nibble first.
			at := 31 - i
			b[at/2] |= byte(n) << (4 * (1 - at%2))
		}
		return netip.AddrFrom16(b), true
	}
	return netip.Addr{}, false
}

// reverseName is a name that an A or AAAA record gives an address, with the record's TTL.
type reverseName struct {
	name string
	ttl  uint32
}

// isWildcard tells whether name, absolute, is a wildcard's: it is no host's, and has no reverse.
func isWildcard(name string) bool {
	return strings.HasPrefix(name, "*.")
}

// indexReverse reads the addresses the A and AAAA records give, the zones' and the resolver's,
// each with its names: they don't change. Not a record that a deeper zone hides, which is never
// answered.
func (t *table) indexReverse() {
	t.reverseOf = make(map[netip.Addr][]reverseName)
	for _, n := range append([]*names{t.own}, t.zones...) {
		for name, records := range n.records {
			if isWildcard(name) || t.namesOf(name) != n {
				continue
			}
			for _, rr := range records {
				var addr netip.Addr
				switch rr := rr.(type) {
				case *dns.A:
					addr, _ = netip.AddrFromSlice(rr.A.To4())
				case *dns.AAAA:
					addr, _ = netip.AddrFromSlice(rr.AAAA)
				default:
					continue
				}
				addr = addr.Unmap()
				t.reverseOf[addr] = append(t.reverseOf[addr], reverseName{name, rr.Header().Ttl})
			}
		}
	}
}

// reverse are the PTR records of asked, a name of in-addr.arpa or ip6.arpa, of the names the
// resolver answers with the address it is the reverse of: those of the tasks that have it now,
// and of the A and AAAA records, the zones' and the resolver's, that give it; not a wildcard's.
// Sorted, each name once, with one TTL, as the records of a name and type have: the zone's, or the
// record's, the shortest of them. None for an address of no name.
func (t *table) reverse(asked string) []dns.RR {
	addr, ok := reverseAddr(asked)
	if !ok {
		return nil
	}
	found := slices.Clone(t.reverseOf[addr])
	for _, n := range t.zones {
		ttl := uint32(n.zone.TTL.Seconds())
		for name := range n.tasks {
			if !isWildcard(name) && t.namesOf(name) == n && slices.Contains(n.zone.Addresses.Get(name), addr) {
				found = append(found, reverseName{name, ttl})
			}
		}
	}
	if len(found) == 0 {
		return nil
	}
	ttl := found[0].ttl
	var matched []string
	for _, f := range found {
		ttl = min(ttl, f.ttl)
		matched = append(matched, f.name)
	}
	slices.Sort(matched)
	var records []dns.RR
	for _, name := range slices.Compact(matched) {
		records = append(records, &dns.PTR{Hdr: dns.RR_Header{Name: asked, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: ttl}, Ptr: name})
	}
	return records
}
