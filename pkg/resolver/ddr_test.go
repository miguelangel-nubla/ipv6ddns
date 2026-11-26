package resolver

import (
	"fmt"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/certfile"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/listen"
)

// svcbKeys are the keys of an SVCB record, by name, as text.
func svcbKeys(rr *dns.SVCB) map[string]string {
	keys := make(map[string]string)
	for _, kv := range rr.Value {
		keys[kv.Key().String()] = kv.String()
	}
	return keys
}

func portOf(t *testing.T, address string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func TestDDR(t *testing.T) {
	up := newUpstream(t)
	ca := newTestCA(t)
	s := startWithRoots(t, encryptedConfig(t, ca, up.address), ca)

	resp := query(t, s, "udp", "_dns.resolver.arpa.", dns.TypeSVCB, nil)
	if resp.Rcode != dns.RcodeSuccess || !resp.Authoritative || len(resp.Answer) != 3 {
		t.Fatalf("SVCB: %v", resp)
	}
	want := []map[string]string{
		{"alpn": alpnTLS, "port": portOf(t, addressOf(t, s, TransportTLS)), "ipv4hint": "127.0.0.1"},
		{"alpn": alpnH2, "port": portOf(t, addressOf(t, s, TransportHTTPS)), "ipv4hint": "127.0.0.1", "dohpath": "/dns-query{?dns}"},
		{"alpn": alpnQUIC, "port": portOf(t, addressOf(t, s, TransportQUIC)), "ipv4hint": "127.0.0.1"},
	}
	for i, rr := range resp.Answer {
		svcb, ok := rr.(*dns.SVCB)
		if !ok || svcb.Priority != uint16(i+1) || svcb.Target != encryptedName+"." || svcb.Hdr.Name != "_dns.resolver.arpa." ||
			svcb.Hdr.Ttl != uint32(DefaultTTL.Seconds()) {
			t.Errorf("record %d: %v", i, rr)
			continue
		}
		if got := svcbKeys(svcb); !maps.Equal(got, want[i]) {
			t.Errorf("record %d: keys %v, want %v", i, got, want[i])
		}
	}

	for _, tc := range []struct {
		name  string
		qtype uint16
		rcode int
	}{
		{"_dns.resolver.arpa.", dns.TypeA, dns.RcodeSuccess},
		{"resolver.arpa.", dns.TypeSVCB, dns.RcodeSuccess},
		{"other.resolver.arpa.", dns.TypeSVCB, dns.RcodeNameError},
		{"_DNS.Resolver.ARPA.", dns.TypeAAAA, dns.RcodeSuccess},
	} {
		resp := query(t, s, "udp", tc.name, tc.qtype, nil)
		if resp.Rcode != tc.rcode || !resp.Authoritative || len(resp.Answer) != 0 || len(resp.Ns) != 1 || resp.Ns[0].Header().Rrtype != dns.TypeSOA {
			t.Errorf("%s %s: %v", tc.name, dns.TypeToString[tc.qtype], resp)
		}
	}
	if n := up.queries.Load(); n != 0 {
		t.Errorf("%d queries forwarded", n)
	}
	if st := s.Status(); st.Queries[Local] != 2 || st.Queries[NoData] != 3 {
		t.Errorf("counted %v", st.Queries)
	}
}

// Without encrypted entries, resolver.arpa is a name as any other: asked upstream.
func TestDDRWithoutEncrypted(t *testing.T) {
	up := newUpstream(t)
	cfg, _ := testConfig(t, up.address)
	s := start(t, cfg)
	query(t, s, "udp", "_dns.resolver.arpa.", dns.TypeSVCB, nil)
	if n := up.queries.Load(); n != 1 {
		t.Errorf("%d queries forwarded, want 1", n)
	}
}

// An entry tells the clients its allow takes, and the name its certificate has, which is none of a
// wildcard alone.
func TestDDREntries(t *testing.T) {
	ca := newTestCA(t)
	cfg := encryptedConfig(t, ca)
	cfg.Encrypted[0].Allow = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	certFile, keyFile := writeCertificate(t, t.TempDir(), ca.leaf(t, []string{"*.home.arpa", "Other.home.arpa"}))
	other, err := certfile.Load(certFile, keyFile, false, t.Errorf)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Encrypted[1].Certificate = other
	wildFile, wildKey := writeCertificate(t, t.TempDir(), ca.leaf(t, []string{"*.home.arpa"}))
	wild, err := certfile.Load(wildFile, wildKey, false, t.Errorf)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Encrypted = append(cfg.Encrypted, EncryptedListen{Transport: TransportTLS, Entry: listen.Entry{Host: "127.0.0.1", Port: "0"},
		Line: "tls://127.0.0.1:0", Certificate: wild})
	s := startWithRoots(t, cfg, ca)

	resp := query(t, s, "udp", "_dns.resolver.arpa.", dns.TypeSVCB, nil)
	var got []string
	for _, rr := range resp.Answer {
		svcb := rr.(*dns.SVCB)
		got = append(got, strconv.Itoa(int(svcb.Priority))+" "+svcb.Target+" "+svcbKeys(svcb)["alpn"])
	}
	if want := []string{"1 other.home.arpa. h2", "2 " + encryptedName + ". doq"}; !slices.Equal(got, want) {
		t.Errorf("records %v, want %v", got, want)
	}
}

// The name is the certificate's of now: a renewal for another is told at once.
func TestDDRRenewal(t *testing.T) {
	saved := certfile.CheckInterval
	certfile.CheckInterval = 0
	t.Cleanup(func() { certfile.CheckInterval = saved })
	ca := newTestCA(t)
	cfg := encryptedConfig(t, ca)
	cfg.Encrypted = cfg.Encrypted[:1]
	certFile, keyFile := writeCertificate(t, t.TempDir(), ca.leaf(t, []string{encryptedName}))
	setCertificate(t, &cfg, t.Errorf, false, certFile, keyFile)
	s := startWithRoots(t, cfg, ca)
	target := func() string {
		resp := query(t, s, "udp", "_dns.resolver.arpa.", dns.TypeSVCB, nil)
		if len(resp.Answer) != 1 {
			t.Fatalf("SVCB: %v", resp)
		}
		return resp.Answer[0].(*dns.SVCB).Target
	}
	if got := target(); got != encryptedName+"." {
		t.Fatalf("target %s", got)
	}
	writeCertificate(t, filepath.Dir(certFile), ca.leaf(t, []string{"renewed.home.arpa"}))
	later := time.Now().Add(time.Second)
	os.Chtimes(certFile, later, later)
	if got := target(); got != "renewed.home.arpa." {
		t.Errorf("after renewal, target %s", got)
	}
}

func TestDDREntriesOfSockets(t *testing.T) {
	e := []EncryptedListen{{Transport: TransportTLS}, {Transport: TransportQUIC}}
	addr := func(s string) net.Addr { return net.TCPAddrFromAddrPort(netip.MustParseAddrPort(s)) }
	ips := func(s ...string) []netip.Addr {
		var r []netip.Addr
		for _, a := range s {
			r = append(r, netip.MustParseAddr(a))
		}
		return r
	}
	for _, tc := range []struct {
		name     string
		listened []string
		entryOf  []int
		want     []ddrEntry
	}{
		{"two ports of one entry, and an address of each family", []string{"192.0.2.1:853", "[2001:db8::1]:853", "0.0.0.0:853", "192.0.2.1:8853"}, []int{0, 0, 1, 1},
			[]ddrEntry{{port: 853, hints: ips("192.0.2.1", "2001:db8::1")}, {port: 853, v4: true}, {port: 8853, hints: ips("192.0.2.1")}}},
		{"all of both families", []string{"[::]:853"}, []int{0}, []ddrEntry{{port: 853, v4: true, v6: true}}},
		{"link-local, of two interfaces", []string{"[fe80::1%lo0]:853", "[fe80::1%en0]:853", "[2001:db8::1]:853"}, []int{0, 0, 0},
			[]ddrEntry{{port: 853, hints: ips("2001:db8::1")}}},
		{"IPv4-mapped", []string{"[::ffff:192.0.2.1]:853", "192.0.2.1:853"}, []int{0, 0}, []ddrEntry{{port: 853, hints: ips("192.0.2.1")}}},
	} {
		var listened []net.Addr
		for _, a := range tc.listened {
			listened = append(listened, addr(a))
		}
		got := ddrEntries(e, listened, tc.entryOf)
		if !slices.EqualFunc(got, tc.want, func(a, b ddrEntry) bool {
			return a.port == b.port && slices.Equal(a.hints, b.hints) && a.v4 == b.v4 && a.v6 == b.v6
		}) {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

// Of an entry on all addresses, the hint is the one the query came to; of a family it doesn't
// listen on, none.
func TestDDRHintsOf(t *testing.T) {
	addr := func(s string) net.Addr { return net.UDPAddrFromAddrPort(netip.MustParseAddrPort(s)) }
	for _, tc := range []struct {
		e     ddrEntry
		local string
		want  string
	}{
		{ddrEntry{v4: true}, "192.0.2.1:53", "[192.0.2.1]"},
		{ddrEntry{v4: true}, "[2001:db8::1]:53", "[]"},
		{ddrEntry{v4: true, v6: true}, "[2001:db8::1]:53", "[2001:db8::1]"},
		{ddrEntry{v4: true, v6: true}, "[::ffff:192.0.2.1]:53", "[192.0.2.1]"},
		{ddrEntry{v6: true, v4: true}, "[fe80::1%lo0]:53", "[]"},
		{ddrEntry{hints: []netip.Addr{netip.MustParseAddr("192.0.2.2")}}, "192.0.2.1:53", "[192.0.2.2]"},
	} {
		got := hintsOf(tc.e, addr("198.51.100.1:5353"), addr(tc.local))
		if s := fmt.Sprint(got); s != tc.want {
			t.Errorf("%+v at %s: %s, want %s", tc.e, tc.local, s, tc.want)
		}
	}
}

// The default allow is of the sockets of the entries without their own, in the order they are
// opened: a QUIC one before a TLS one isn't taken for it.
func TestDefaultAllowOfEncryptedOrder(t *testing.T) {
	if c, err := net.ListenPacket("udp6", "[::1]:0"); err != nil {
		t.Skip("no IPv6 loopback")
	} else {
		c.Close()
	}
	ca := newTestCA(t)
	cfg := encryptedConfig(t, ca)
	cfg.Encrypted = []EncryptedListen{
		{Transport: TransportQUIC, Entry: listen.Entry{Host: "::1", Port: "0"}, Line: "quic://[::1]:0", Allow: []netip.Prefix{netip.MustParsePrefix("::1/128")}},
		{Transport: TransportTLS, Entry: listen.Entry{Host: "127.0.0.1", Port: "0"}, Line: "tls://127.0.0.1:0"},
	}
	s := startWithRoots(t, cfg, ca)
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if slices.ContainsFunc(s.allow, func(p netip.Prefix) bool { return p.Addr().Is6() }) {
		t.Errorf("default allow %v has the QUIC socket's network", s.allow)
	}
}
