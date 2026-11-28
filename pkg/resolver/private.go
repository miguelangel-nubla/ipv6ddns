package resolver

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/miekg/dns"
)

// The reverse zones of the addresses that are no network's on the internet, as RFC 6303 has them,
// and RFC 7793 adds: a resolver answers them itself, so that their questions don't leave the
// network to servers that know nothing of them. IPv4: the private networks, this network, the
// loopback, link-local, the documentation's networks and the broadcast, and the shared address
// space of carriers. IPv6: the unspecified address and the loopback, the unique local addresses,
// link-local, and the documentation's.
var privateNetworks = func() []netip.Prefix {
	var networks []netip.Prefix
	for _, p := range []string{"10.0.0.0/8", "192.168.0.0/16", "0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16",
		"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "255.255.255.255/32",
		"::/128", "::1/128", "fd00::/8", "fe80::/12", "fe90::/12", "fea0::/12", "feb0::/12", "2001:db8::/32"} {
		networks = append(networks, netip.MustParsePrefix(p))
	}
	// Of a whole octet of the address each: 172.16.0.0/12 and 100.64.0.0/10 are 16 and 64 zones.
	for i := 16; i <= 31; i++ {
		networks = append(networks, netip.MustParsePrefix(fmt.Sprintf("172.%d.0.0/16", i)))
	}
	for i := 64; i <= 127; i++ {
		networks = append(networks, netip.MustParsePrefix(fmt.Sprintf("100.%d.0.0/16", i)))
	}
	return networks
}()

// reverseZone is the name of the reverse zone of a network whose prefix is of whole octets, for
// IPv4, or whole nibbles, for IPv6: 168.192.in-addr.arpa. of 192.168.0.0/16.
func reverseZone(p netip.Prefix) string {
	a := p.Addr()
	var labels []string
	if a.Is4() {
		b := a.As4()
		for i := 0; i < p.Bits()/8; i++ {
			labels = append(labels, fmt.Sprint(b[i]))
		}
		slices.Reverse(labels)
		return strings.Join(append(labels, "in-addr.arpa."), ".")
	}
	b := a.As16()
	for i := 0; i < p.Bits()/4; i++ {
		labels = append(labels, fmt.Sprintf("%x", b[i/2]>>(4*(1-i%2))&0xf))
	}
	slices.Reverse(labels)
	return strings.Join(append(labels, "ip6.arpa."), ".")
}

// privateZones are the reverse zones of privateNetworks, which the resolver answers itself.
func privateZones() []string {
	var zones []string
	for _, p := range privateNetworks {
		zones = append(zones, reverseZone(p))
	}
	return zones
}

// privateZone is the zone of privateZones that name, absolute, is in, or "".
func (s *Server) privateZone(name string) string {
	name = strings.ToLower(name)
	for _, z := range s.private {
		if name == z || strings.HasSuffix(name, "."+z) {
			return z
		}
	}
	return ""
}

// answerPrivate is the answer of a name of the private zone zone that the resolver has nothing of:
// as RFC 6303 has it, the zone's apex has its SOA and NS records, and no other name is. But one
// that is there, named: the reverse of an address the resolver has a name of, asked another type,
// or a name above one it answers, which has no data.
func answerPrivate(req *dns.Msg, zone string, named bool) (*dns.Msg, string) {
	q := req.Question[0]
	rcode, kind := dns.RcodeNameError, Local
	if named || strings.EqualFold(q.Name, zone) {
		rcode, kind = dns.RcodeSuccess, NoData
	}
	resp := reply(req, rcode)
	resp.Authoritative = true
	apex := strings.EqualFold(q.Name, zone)
	switch {
	case apex && (q.Qtype == dns.TypeSOA || q.Qtype == dns.TypeANY):
		resp.Answer = []dns.RR{privateSOA(zone)}
		kind = Local
	case apex && q.Qtype == dns.TypeNS:
		resp.Answer = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: privateTTL}, Ns: zone}}
		kind = Local
	default:
		resp.Ns = []dns.RR{privateSOA(zone)}
	}
	return resp, kind
}

// privateTTL is the TTL of the records of a private zone, and of its negative answers: RFC 6303's,
// three hours.
const privateTTL = 10800

// privateSOA is the SOA record of a private zone, as RFC 6303 gives it: its own name its server,
// and nobody.invalid. its mailbox.
func privateSOA(zone string) *dns.SOA {
	return &dns.SOA{
		Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: privateTTL},
		Ns:  zone, Mbox: "nobody.invalid.", Serial: 1, Refresh: 3600, Retry: 1200, Expire: 604800, Minttl: privateTTL,
	}
}
