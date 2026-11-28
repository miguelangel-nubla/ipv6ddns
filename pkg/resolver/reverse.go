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
	p, ok := reversePrefix(name)
	if !ok || p.Bits() != p.Addr().BitLen() {
		return netip.Addr{}, false
	}
	return p.Addr(), true
}

// reversePrefix is the network a name of in-addr.arpa or ip6.arpa is the reverse of, of an octet
// of IPv4 a label, or four bits of IPv6: 192.168.1.0/24 of 1.168.192.in-addr.arpa., and an
// address, as a network of it alone, of a name with all its labels. False for any other name.
func reversePrefix(name string) (netip.Prefix, bool) {
	name = strings.ToLower(dns.Fqdn(name))
	switch {
	case strings.HasSuffix(name, ".in-addr.arpa."):
		labels := strings.Split(strings.TrimSuffix(name, ".in-addr.arpa."), ".")
		if len(labels) > 4 {
			return netip.Prefix{}, false
		}
		var b [4]byte
		for i, l := range labels {
			n, err := strconv.ParseUint(l, 10, 8)
			if err != nil || strconv.FormatUint(n, 10) != l {
				return netip.Prefix{}, false
			}
			// The last octet first.
			b[len(labels)-1-i] = byte(n)
		}
		return netip.PrefixFrom(netip.AddrFrom4(b), 8*len(labels)), true
	case strings.HasSuffix(name, ".ip6.arpa."):
		labels := strings.Split(strings.TrimSuffix(name, ".ip6.arpa."), ".")
		if len(labels) > 32 {
			return netip.Prefix{}, false
		}
		var b [16]byte
		for i, l := range labels {
			n, err := strconv.ParseUint(l, 16, 8)
			if err != nil || len(l) != 1 {
				return netip.Prefix{}, false
			}
			// The last nibble first.
			at := len(labels) - 1 - i
			b[at/2] |= byte(n) << (4 * (1 - at%2))
		}
		return netip.PrefixFrom(netip.AddrFrom16(b), 4*len(labels)), true
	}
	return netip.Prefix{}, false
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
		// The tasks' names, and those their templates made, which are there while they have
		// addresses.
		for _, name := range n.zone.Addresses.Names() {
			if t.reverses(n, name) && slices.Contains(n.zone.Addresses.Get(name), addr) {
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

// reverseAt tells whether asked, a name of in-addr.arpa or ip6.arpa that the resolver has no
// records of, is there all the same: the reverse of an address it has a name of, or a name above
// one, or above a record written, in its own or in a zone below. Such a name has no data, and is
// not one that isn't: no such name would deny, to a client that reads it so (RFC 8020), the names
// under it that the resolver answers.
func (t *table) reverseAt(asked string) bool {
	name := strings.ToLower(dns.Fqdn(asked))
	if t.namesOf(name).exists[name] {
		return true
	}
	for _, n := range t.zones {
		if dns.IsSubDomain(name, n.apex) && len(n.exists) > 0 {
			return true
		}
	}
	p, ok := reversePrefix(name)
	if !ok {
		return false
	}
	for addr := range t.reverseOf {
		if p.Contains(addr) {
			return true
		}
	}
	for _, n := range t.zones {
		for _, name := range n.zone.Addresses.Names() {
			if t.reverses(n, name) && slices.ContainsFunc(n.zone.Addresses.Get(name), p.Contains) {
				return true
			}
		}
	}
	return false
}

// reverses tells whether name, one with addresses of the zone n, is answered to the reverse of
// them: a task's, or one its template made; not one that a record has, whose answer is the
// record's, nor a wildcard, nor one that a deeper zone hides.
func (t *table) reverses(n *names, name string) bool {
	if _, task := n.tasks[name]; !task && len(n.records[name]) > 0 {
		return false
	}
	return !isWildcard(name) && t.namesOf(name) == n
}
