package resolver

import (
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// The name that a client asks a resolver of the encrypted ones it is, as RFC 9462 has it, and the
// zone it is in, which no resolver forwards.
const (
	ddrName = "_dns.resolver.arpa."
	ddrZone = "resolver.arpa."
)

// The application protocol of HTTP/2, which DNS over HTTPS is said to speak: HTTP/3 isn't served.
const alpnH2 = "h2"

// ddrEntry is an encrypted entry, as Discovery of Designated Resolvers tells it: its port, and the
// addresses it listens on, of each port it has; v4, v6, whether it listens on all of a family's.
type ddrEntry struct {
	EncryptedListen
	port   uint16
	hints  []netip.Addr
	v4, v6 bool
}

// ddrEntries are the encrypted entries of the sockets listened on, in the order of the
// configuration: listened, the address of each socket; entryOf, the index of its entry.
func ddrEntries(entries []EncryptedListen, listened []net.Addr, entryOf []int) []ddrEntry {
	var result []ddrEntry
	for i, e := range entries {
		var of []ddrEntry
		for j, a := range listened {
			if entryOf[j] != i {
				continue
			}
			ap, err := netip.ParseAddrPort(a.String())
			if err != nil {
				continue
			}
			k := slices.IndexFunc(of, func(d ddrEntry) bool { return d.port == ap.Port() })
			if k < 0 {
				of = append(of, ddrEntry{EncryptedListen: e, port: ap.Port()})
				k = len(of) - 1
			}
			ip := ap.Addr().Unmap().WithZone("")
			switch {
			// All of a family's: the one the client asked, at answer time. Of [::], both, as Go
			// listens there.
			case ip.IsUnspecified():
				of[k].v4 = true
				of[k].v6 = of[k].v6 || ip.Is6()
			case hintable(ip) && !slices.Contains(of[k].hints, ip):
				of[k].hints = append(of[k].hints, ip)
			}
		}
		result = append(result, of...)
	}
	return result
}

// hintable tells whether ip is of use to a client as a hint, which has no zone: not a link-local
// one. One of the loopback is, to the clients of the machine, the only ones it has.
func hintable(ip netip.Addr) bool {
	return ip.IsValid() && !ip.IsUnspecified() && !ip.IsLinkLocalUnicast()
}

// hintsOf are the hints of e to a client at addr, which asked at local: its addresses, and, of
// a family it listens on all of, the one asked, or, of a socket that doesn't say it as UDP's, the
// machine's in a network of the client.
func hintsOf(e ddrEntry, addr, local net.Addr) []netip.Addr {
	hints := slices.Clone(e.hints)
	if !e.v4 && !e.v6 {
		return hints
	}
	add := func(ip netip.Addr) {
		ip = ip.Unmap().WithZone("")
		if (ip.Is4() && e.v4 || ip.Is6() && e.v6) && hintable(ip) && !slices.Contains(hints, ip) {
			hints = append(hints, ip)
		}
	}
	if ip, ok := addrOf(local); ok && !ip.IsUnspecified() {
		add(ip)
		return hints
	}
	from, ok := addrOf(addr)
	if !ok {
		return hints
	}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipNet, ok := a.(*net.IPNet); ok {
			ip, ok := netip.AddrFromSlice(ipNet.IP)
			ones, _ := ipNet.Mask.Size()
			if ok && netip.PrefixFrom(ip.Unmap(), ones).Masked().Contains(from) {
				add(ip)
			}
		}
	}
	return hints
}

// isDDR tells whether name is in the zone of Discovery of Designated Resolvers.
func isDDR(name string) bool {
	name = strings.ToLower(name)
	return name == ddrZone || strings.HasSuffix(name, "."+ddrZone)
}

// answerDDR answers a name of resolver.arpa, of a resolver with encrypted entries: of
// _dns.resolver.arpa, the entries whose allow takes the client, each an SVCB record for the name of
// its certificate; of resolver.arpa, no data; of any other, no such name.
func (s *Server) answerDDR(req *dns.Msg, remote net.Addr) (*dns.Msg, string) {
	q := req.Question[0]
	name := strings.ToLower(q.Name)
	resp := reply(req, dns.RcodeSuccess)
	resp.Authoritative = true
	if name == ddrName && (q.Qtype == dns.TypeSVCB || q.Qtype == dns.TypeANY) {
		resp.Answer = s.designated(remote)
	}
	switch {
	case len(resp.Answer) > 0:
		return resp, Local
	case name == ddrName || name == ddrZone:
		resp.Ns = []dns.RR{soa(ddrZone)}
		return resp, NoData
	}
	resp.Rcode = dns.RcodeNameError
	resp.Ns = []dns.RR{soa(ddrZone)}
	return resp, Local
}

// designated are the SVCB records of the encrypted entries whose allow takes the client: those
// with a name, which the client checks, their listener's server name or their certificate's,
// read now, as a renewal changes it. Of a socket that listeners share, the server's own.
func (s *Server) designated(remote net.Addr) []dns.RR {
	var addr, local net.Addr = remote, nil
	if c, ok := remote.(client); ok {
		addr, local = c.Addr, c.local
	}
	var records []dns.RR
	for _, e := range s.ddr {
		if !s.allowed(client{Addr: addr, allow: e.Allow}) {
			continue
		}
		target := s.serverName(e.EncryptedListen)
		if target == "" {
			continue
		}
		rr := &dns.SVCB{
			Hdr:      dns.RR_Header{Name: ddrName, Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: uint32(DefaultTTL.Seconds())},
			Priority: uint16(len(records) + 1),
			Target:   target,
		}
		alpn := map[string]string{TransportTLS: alpnTLS, TransportQUIC: alpnQUIC, TransportHTTPS: alpnH2}[e.Transport]
		rr.Value = append(rr.Value, &dns.SVCBAlpn{Alpn: []string{alpn}})
		if strconv.Itoa(int(e.port)) != DefaultPortOf(e.Transport) {
			rr.Value = append(rr.Value, &dns.SVCBPort{Port: e.port})
		}
		var v4, v6 []net.IP
		for _, ip := range hintsOf(e, addr, local) {
			if ip.Is4() {
				v4 = append(v4, net.IP(ip.AsSlice()))
			} else {
				v6 = append(v6, net.IP(ip.AsSlice()))
			}
		}
		if len(v4) > 0 {
			rr.Value = append(rr.Value, &dns.SVCBIPv4Hint{Hint: v4})
		}
		if len(v6) > 0 {
			rr.Value = append(rr.Value, &dns.SVCBIPv6Hint{Hint: v6})
		}
		if e.Transport == TransportHTTPS {
			rr.Value = append(rr.Value, &dns.SVCBDoHPath{Template: DoHPath + "{?dns}"})
		}
		records = append(records, rr)
	}
	return records
}

// certificateName is the name the certificate of e is for, which a client checks: its first DNS
// name that is no wildcard, or "" of none, or of no certificate yet.
func certificateName(s *Server, e EncryptedListen) string {
	cert := s.certificateOf(e)
	if cert == nil {
		return ""
	}
	// Get reads the files again when they changed, as for a handshake.
	c, err := cert.Get(nil)
	if err != nil || c.Leaf == nil {
		return ""
	}
	for _, n := range c.Leaf.DNSNames {
		if !strings.HasPrefix(n, "*") {
			return dns.Fqdn(strings.ToLower(n))
		}
	}
	return ""
}
