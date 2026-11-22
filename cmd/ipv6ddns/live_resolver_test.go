//go:build linux && integration

package main

// The resolver, as the command runs it, asked by dig, on machines of one link.

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/miguelangel-nubla/ipv6ddns/internal/livetest"
)

// fakeUpstream is a DNS server of the test's on a machine, at port 53 of its IPv4 address: it
// answers every A query with answer, or with the address hosts has for the name, a TXT query with
// many records, and a PTR query with reverseName; a name under gone.test doesn't exist, and one
// under empty.test has no data, each with an SOA of negative seconds. Or, as told, slowly, not at
// all, or truncated over UDP.
type fakeUpstream struct {
	address string
	answer  string
	// The addresses of some names, absolute, in lower case, in place of answer.
	hosts map[string]string
	mode  atomic.Value // "", "slow", "down", "truncate"
	// The TTL of its answers, and of that there is none.
	ttl      atomic.Uint32
	negative atomic.Uint32
	udp      atomic.Int64
	tcp      atomic.Int64
	// The names asked, each as often as it was.
	mutex sync.Mutex
	asked map[string]int
}

// reverseName is the name the upstream servers of the tests give every address.
const reverseName = "host.upstream.test."

// host gives a name, absolute, an address of its own.
func (u *fakeUpstream) host(name, address string) {
	u.mutex.Lock()
	defer u.mutex.Unlock()
	u.hosts[name] = address
}

// times is how many times the upstream was asked the name, absolute.
func (u *fakeUpstream) times(name string) int {
	u.mutex.Lock()
	defer u.mutex.Unlock()
	return u.asked[strings.ToLower(name)]
}

// answerTo is the upstream's answer to a query.
func (u *fakeUpstream) answerTo(req *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.RecursionAvailable = true
	q := req.Question[0]
	name := strings.ToLower(q.Name)
	u.mutex.Lock()
	u.asked[name]++
	u.mutex.Unlock()
	ttl := u.ttl.Load()
	header := func(rrtype uint16) dns.RR_Header {
		return dns.RR_Header{Name: q.Name, Rrtype: rrtype, Class: dns.ClassINET, Ttl: ttl}
	}
	soa := func(zone string) {
		negative := u.negative.Load()
		resp.Ns = append(resp.Ns, &dns.SOA{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: negative},
			Ns: "ns." + zone, Mbox: "hostmaster." + zone, Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: negative})
	}
	switch {
	case dns.IsSubDomain("gone.test.", name):
		resp.Rcode = dns.RcodeNameError
		soa("gone.test.")
	case dns.IsSubDomain("empty.test.", name):
		soa("empty.test.")
	case q.Qtype == dns.TypeA:
		answer := u.answer
		u.mutex.Lock()
		if a, ok := u.hosts[name]; ok {
			answer = a
		}
		u.mutex.Unlock()
		resp.Answer = append(resp.Answer, &dns.A{Hdr: header(dns.TypeA), A: net.ParseIP(answer)})
	case q.Qtype == dns.TypeTXT:
		for i := range 60 {
			resp.Answer = append(resp.Answer, &dns.TXT{Hdr: header(dns.TypeTXT), Txt: []string{fmt.Sprintf("an upstream record, long enough to fill a message, %02d", i)}})
		}
	case q.Qtype == dns.TypePTR:
		resp.Answer = append(resp.Answer, &dns.PTR{Hdr: header(dns.TypePTR), Ptr: reverseName})
	}
	if opt := req.IsEdns0(); opt != nil {
		resp.SetEdns0(opt.UDPSize(), opt.Do())
	}
	return resp
}

func startUpstream(t *testing.T, m *livetest.Machine, answer string) *fakeUpstream {
	t.Helper()
	u := &fakeUpstream{address: net.JoinHostPort(m.IPv4.String(), "53"), answer: answer, hosts: make(map[string]string), asked: make(map[string]int)}
	u.mode.Store("")
	u.ttl.Store(30)
	u.negative.Store(30)
	var pc net.PacketConn
	var l net.Listener
	if err := m.Do(func() (err error) {
		if pc, err = net.ListenPacket("udp4", u.address); err != nil {
			return err
		}
		l, err = net.Listen("tcp4", u.address)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		_, overUDP := w.RemoteAddr().(*net.UDPAddr)
		if overUDP {
			u.udp.Add(1)
		} else {
			u.tcp.Add(1)
		}
		mode := u.mode.Load().(string)
		switch mode {
		case "down":
			return
		case "slow":
			time.Sleep(3 * time.Second)
		}
		if mode == "truncate" && overUDP {
			resp := new(dns.Msg)
			resp.SetReply(req)
			resp.RecursionAvailable = true
			resp.Truncated = true
			w.WriteMsg(resp)
			return
		}
		w.WriteMsg(u.answerTo(req))
	})
	servers := []*dns.Server{{PacketConn: pc, Handler: handler}, {Listener: l, Handler: handler}}
	for _, s := range servers {
		go s.ActivateAndServe()
	}
	t.Cleanup(func() {
		for _, s := range servers {
			s.Shutdown()
		}
	})
	return u
}

// digAnswer is what dig tells of an answer.
type digAnswer struct {
	status string
	flags  []string
	// "name TYPE data", of the answer section.
	answers   []string
	authority []string
	// The TTL of each, in seconds.
	ttls, authorityTTLs []int
	output              string
}

func (d digAnswer) String() string { return d.output }

func (d digAnswer) has(flag string) bool { return slices.Contains(d.flags, flag) }

// data is the data of the answers of a type.
func (d digAnswer) data(rrtype string) []string {
	var out []string
	for _, a := range d.answers {
		if f := strings.SplitN(a, " ", 3); len(f) == 3 && f[1] == rrtype {
			out = append(out, f[2])
		}
	}
	slices.Sort(out)
	return out
}

// ttl is the TTL of the first answer, or of the first record of the authority when there is no
// answer: -1 with neither.
func (d digAnswer) ttl() int {
	switch {
	case len(d.ttls) > 0:
		return d.ttls[0]
	case len(d.authorityTTLs) > 0:
		return d.authorityTTLs[0]
	}
	return -1
}

// dig asks server, from the machine, with the real dig: args are dig's, as the name and the type.
func dig(t *testing.T, m *livetest.Machine, server string, args ...string) digAnswer {
	t.Helper()
	cmd := m.Command("dig", append([]string{"@" + server, "+time=6", "+tries=1", "+noall", "+comments", "+answer", "+authority"}, args...)...)
	cmd.Stderr = nil
	out, err := cmd.CombinedOutput()
	d := digAnswer{output: string(out)}
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			t.Fatalf("dig: %v", err)
		}
		d.status = "no answer"
		return d
	}
	section := ""
	for _, line := range strings.Split(string(out), "\n") {
		switch {
		case strings.Contains(line, "->>HEADER<<-"):
			_, s, _ := strings.Cut(line, "status: ")
			d.status, _, _ = strings.Cut(s, ",")
		case strings.HasPrefix(line, ";; flags:"):
			f, _, _ := strings.Cut(strings.TrimPrefix(line, ";; flags:"), ";")
			d.flags = strings.Fields(f)
		case strings.HasPrefix(line, ";; ANSWER SECTION"):
			section = "answer"
		case strings.HasPrefix(line, ";; AUTHORITY SECTION"):
			section = "authority"
		case strings.HasPrefix(line, ";") || strings.TrimSpace(line) == "":
		default:
			f := strings.Fields(line)
			if len(f) < 5 {
				continue
			}
			rr := f[0] + " " + f[3] + " " + strings.Join(f[4:], " ")
			ttl, _ := strconv.Atoi(f[1])
			if section == "authority" {
				d.authority, d.authorityTTLs = append(d.authority, rr), append(d.authorityTTLs, ttl)
			} else {
				d.answers, d.ttls = append(d.answers, rr), append(d.ttls, ttl)
			}
		}
	}
	return d
}

// A machine runs ipv6ddns with two resolvers: lan, for the link's network, and lab, for another on
// the same link. Its clients ask them with dig: the name of a peer that discovery finds has its
// addresses, through a change of one and the peer's leaving; the records, the CNAMEs, local and to
// upstream, and the names forwarded, whatever the upstream server does; a client outside allow is
// refused; and each resolver has its own answer for one name. A second machine, with the same
// configuration, answers the same; a second instance on the first machine doesn't start.
func TestLiveResolver(t *testing.T) {
	if _, err := exec.LookPath("dig"); err != nil {
		t.Fatal("the live tests of the resolver ask it with dig, of bind9-dnsutils: not found")
	}
	lan := livetest.NewLAN(t, 15)
	router := lan.Router
	srv := lan.Machine(t, "srv", 10)
	srv2 := lan.Machine(t, "srv2", 11)
	peer := lan.Machine(t, "peer", 20)
	client := lan.Machine(t, "client", 30)
	up := lan.Machine(t, "up", 40)
	up2 := lan.Machine(t, "up2", 41)
	outsider := lan.Machine(t, "outsider", 70)
	// The lab's network, on the same link: an address of it for each server, and for a client.
	for m, host := range map[*livetest.Machine]int{srv: 1, client: 2, srv2: 3} {
		m.IP(t, "addr", "add", fmt.Sprintf("10.77.0.%d/24", host), "dev", m.Interface)
	}

	upstream := startUpstream(t, up, "192.0.2.53")
	upstream2 := startUpstream(t, up2, "192.0.2.54")

	config := fmt.Sprintf(`
webserver:
  listen:
    - 8053
discovery:
  lifetime: 9s
  rediscover: 3s
  solicit:
    ipv6: true
resolvers:
  lan:
    listen:
      - 198.18.15.0/24
      - "fd00:c612:15::/64"
    # Hosts 1 to 63: the outsider, 70, isn't.
    allow:
      - 198.18.15.0/26
      - "fd00:c612:15::/122"
    upstream:
      - %s
      - %s
    records:
      - www.example.com. CNAME peer.home.arpa.
      - ext.example.com. CNAME far.upstream.test.
  lab:
    listen: 10.77.0.0/24
    upstream: %[1]s
credentials:
  home:
    provider: resolver
    settings:
      resolver: lan
      zone: home.arpa
      records:
        - printer A 198.18.15.50
        - files CNAME peer
        - out CNAME far.upstream.test.
        - '_ipp._tcp SRV 0 0 631 printer'
        - '*.dev A 198.18.15.51'
  labhome:
    provider: resolver
    settings:
      resolver: lab
      zone: home.arpa
      records:
        - printer A 10.77.0.50
tasks:
  peer:
    filter:
      - mac:
          address: "%[3]s"
        ip:
          prefix: "%[4]s"
    endpoints:
      home:
        - peer
`, up.IPv4, up2.IPv4, peer.MAC, lan.Prefix())
	one := configure(t, srv, router, "srv", 8053, config).start().serving()
	two := configure(t, srv2, router, "srv2", 8053, config).start().serving()
	server, server6, lab := srv.IPv4.String(), srv.IPv6.String(), "10.77.0.1"

	peerName := func(server string) func() bool {
		return func() bool {
			return slices.Equal(dig(t, client, server, "peer.home.arpa", "AAAA").data("AAAA"), []string{peer.IPv6.String()})
		}
	}
	tells := func(what ...string) func() string {
		return func() string { return dig(t, client, what[0], what[1:]...).String() }
	}
	waitFor(t, 60*time.Second, "the peer's address, answered", peerName(server), one.tells, tells(server, "peer.home.arpa", "AAAA"))
	// Over IPv6 too, and by the second machine, of the same configuration.
	waitFor(t, 60*time.Second, "the peer's address, answered over IPv6", peerName(server6), one.tells)
	waitFor(t, 60*time.Second, "the peer's address, answered by the second machine", peerName(srv2.IPv4.String()), two.tells)

	d := dig(t, client, server, "peer.home.arpa", "AAAA")
	if d.status != "NOERROR" || !d.has("aa") || !d.has("ra") {
		t.Errorf("the peer's name: %s", d)
	}
	// No IPv4 is discovered: no data of A, with the zone's SOA.
	if d := dig(t, client, server, "peer.home.arpa", "A"); d.status != "NOERROR" || len(d.answers) != 0 || len(d.authority) != 1 || !strings.HasPrefix(d.authority[0], "home.arpa. SOA") {
		t.Errorf("the peer's name, of A: %s", d)
	}

	for _, c := range []struct {
		server, name, qtype string
		want                []string
		aa                  bool
	}{
		{server, "printer.home.arpa", "A", []string{"printer.home.arpa. A 198.18.15.50"}, true},
		{server, "_ipp._tcp.home.arpa", "SRV", []string{"_ipp._tcp.home.arpa. SRV 0 0 631 printer.home.arpa."}, true},
		{server, "any.dev.home.arpa", "A", []string{"any.dev.home.arpa. A 198.18.15.51"}, true},
		{server, "files.home.arpa", "AAAA", []string{"files.home.arpa. CNAME peer.home.arpa.", "peer.home.arpa. AAAA " + peer.IPv6.String()}, true},
		{server, "www.example.com", "AAAA", []string{"www.example.com. CNAME peer.home.arpa.", "peer.home.arpa. AAAA " + peer.IPv6.String()}, false},
		{server, "out.home.arpa", "A", []string{"out.home.arpa. CNAME far.upstream.test.", "far.upstream.test. A 192.0.2.53"}, true},
		{server, "ext.example.com", "A", []string{"ext.example.com. CNAME far.upstream.test.", "far.upstream.test. A 192.0.2.53"}, false},
		// Forwarded: not of the zone, though in it, and of no zone.
		{server, "tv.home.arpa", "A", []string{"tv.home.arpa. A 192.0.2.53"}, false},
		{server, "example.org", "A", []string{"example.org. A 192.0.2.53"}, false},
		// Split horizon: the lab's own printer.
		{lab, "printer.home.arpa", "A", []string{"printer.home.arpa. A 10.77.0.50"}, true},
		{lab, "example.org", "A", []string{"example.org. A 192.0.2.53"}, false},
	} {
		d := dig(t, client, c.server, c.name, c.qtype)
		if d.status != "NOERROR" || !slices.Equal(d.answers, c.want) || d.has("aa") != c.aa {
			t.Errorf("%s %s at %s: %s, want %q, aa %t", c.name, c.qtype, c.server, d, c.want, c.aa)
		}
	}

	// The reverse of an address that a name has: the peer's, as discovered, and a record's, each
	// resolver its own names'; of a wildcard's, or of any other address, the upstream server's.
	peerReverse, err := dns.ReverseAddr(peer.IPv6.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		server, address, want string
		aa                    bool
	}{
		{server, peer.IPv6.String(), "peer.home.arpa.", true},
		{server6, peer.IPv6.String(), "peer.home.arpa.", true},
		{server, "198.18.15.50", "printer.home.arpa.", true},
		{server, "198.18.15.51", reverseName, false},
		{server, "198.18.15.77", reverseName, false},
		{lab, "10.77.0.50", "printer.home.arpa.", true},
		{lab, "198.18.15.50", reverseName, false},
	} {
		d := dig(t, client, c.server, "-x", c.address)
		if d.status != "NOERROR" || !slices.Equal(d.data("PTR"), []string{c.want}) || d.has("aa") != c.aa {
			t.Errorf("the reverse of %s at %s: %s, want %s, aa %t", c.address, c.server, d, c.want, c.aa)
		}
	}
	// The reverse of an address of a private network that a resolver has no name of, a unique
	// local one, or of 10.77.0.0/24: no such name, its own, as RFC 6303 has it; the peer's too, at
	// the lab, which doesn't name it. None is asked of the upstream servers, which are of no
	// private network.
	for _, c := range []struct{ server, address string }{
		{server, "fd00:c612:15::77"}, {server, "10.77.0.99"}, {lab, peer.IPv6.String()}, {lab, "10.77.0.99"},
	} {
		if d := dig(t, client, c.server, "-x", c.address); d.status != "NXDOMAIN" || !d.has("aa") || len(d.authority) != 1 {
			t.Errorf("the reverse of %s at %s: %s, want no such name, of the resolver's own", c.address, c.server, d)
		}
	}
	if got := upstream.times(peerReverse); got != 0 {
		t.Errorf("the reverse of the peer's address was asked upstream %d times, want none", got)
	}

	// A local answer too big for UDP: TC, and whole over TCP, which dig retries with.
	if d := dig(t, client, server, "+ignore", "+noedns", "big.example.org", "TXT"); !d.has("tc") {
		t.Errorf("a forwarded answer too big, over UDP: %s", d)
	}
	if d := dig(t, client, server, "big.example.org", "TXT"); len(d.answers) != 60 || d.has("tc") {
		t.Errorf("a forwarded answer too big, retried over TCP: %d records", len(d.answers))
	}

	// Outside allow: refused, and nothing asked upstream.
	before := upstream.udp.Load()
	if d := dig(t, outsider, server, "example.org", "A"); d.status != "REFUSED" || len(d.answers) != 0 {
		t.Errorf("the outsider: %s", d)
	}
	if d := dig(t, outsider, server6, "printer.home.arpa", "A"); d.status != "REFUSED" {
		t.Errorf("the outsider, over IPv6: %s", d)
	}
	if upstream.udp.Load() != before {
		t.Error("the outsider's query went upstream")
	}

	// The upstream server truncates: asked again over TCP. Of names not asked before, from here:
	// those that were are in the cache.
	upstream.mode.Store("truncate")
	tcp := upstream.tcp.Load()
	if d := dig(t, client, server, "truncated.example.org", "A"); !slices.Equal(d.answers, []string{"truncated.example.org. A 192.0.2.53"}) || upstream.tcp.Load() == tcp {
		t.Errorf("past a truncated upstream answer: %s", d)
	}
	// Slow, then down: the second answers; and the lab, which has it alone, fails.
	for _, mode := range []string{"slow", "down"} {
		upstream.mode.Store(mode)
		asked := upstream2.udp.Load()
		if d := dig(t, client, server, mode+".example.org", "A"); !slices.Equal(d.answers, []string{mode + ".example.org. A 192.0.2.54"}) || upstream2.udp.Load() == asked {
			t.Errorf("the first upstream %s: %s", mode, d)
		}
		if d := dig(t, client, lab, mode+".example.org", "A"); d.status != "SERVFAIL" {
			t.Errorf("the only upstream %s: %s", mode, d)
		}
	}
	// Local answers need no upstream.
	if d := dig(t, client, server, "printer.home.arpa", "A"); d.status != "NOERROR" || len(d.answers) != 1 {
		t.Errorf("a record, upstream down: %s", d)
	}
	upstream.mode.Store("")

	metrics := one.page("/metrics")
	for _, want := range []string{
		`ipv6ddns_resolver_serving{resolver="lan"} 1`,
		`ipv6ddns_resolver_queries_total{resolver="lan",kind="refused"} 2`,
		`ipv6ddns_resolver_queries_total{resolver="lab",kind="servfail"} 2`,
		fmt.Sprintf(`ipv6ddns_resolver_upstream_failures_total{resolver="lan",upstream="%s:53"} 2`, up.IPv4),
	} {
		if !strings.Contains(metrics, want) {
			t.Errorf("metrics without %s:\n%s", want, metrics)
		}
	}
	if s := one.status(); len(s.Resolvers) != 2 || s.Resolvers[1].Name != "lan" || !slices.Contains(s.Resolvers[1].Listening, net.JoinHostPort(server, "53")) {
		t.Errorf("status: %+v", s.Resolvers)
	}

	// The peer moves to another address: the name follows.
	moved := netip.MustParseAddr("fd00:c612:15::99")
	peer.IP(t, "addr", "add", moved.String()+"/64", "dev", peer.Interface, "nodad")
	peer.IP(t, "addr", "del", peer.IPv6.String()+"/64", "dev", peer.Interface)
	waitFor(t, 60*time.Second, "the peer's new address alone", func() bool {
		return slices.Equal(dig(t, client, server, "peer.home.arpa", "AAAA").data("AAAA"), []string{moved.String()})
	}, one.tells, tells(server, "peer.home.arpa", "AAAA"))
	// And its reverse: the new address is the peer's, and the one it had is no more, though it
	// was a moment ago: no such name, the resolver's own, of a unique local address.
	if d := dig(t, client, server, "-x", moved.String()); !slices.Equal(d.data("PTR"), []string{"peer.home.arpa."}) || !d.has("aa") {
		t.Errorf("the reverse of the peer's new address: %s", d)
	}
	if d := dig(t, client, server, "-x", peer.IPv6.String()); d.status != "NXDOMAIN" || !d.has("aa") {
		t.Errorf("the reverse of the address the peer had: %s", d)
	}
	// It leaves: no data, until it is back.
	peer.Leave(t)
	waitFor(t, 60*time.Second, "the peer's name without addresses", func() bool {
		d := dig(t, client, server, "peer.home.arpa", "AAAA")
		return d.status == "NOERROR" && len(d.answers) == 0 && len(d.authority) == 1
	}, one.tells, tells(server, "peer.home.arpa", "AAAA"))

	// A second instance with resolvers on the first's addresses doesn't start: lab's, first in
	// order, is taken.
	second := configure(t, srv, router, "srv-again", 8054, strings.Replace(config, "[8053]", "[8054]", 1)).start()
	select {
	case <-second.exited:
	case <-time.After(20 * time.Second):
		t.Fatalf("a second instance on the address started:\n%s", second.output.String())
	}
	if out := second.output.String(); !strings.Contains(out, "resolvers.lab.listen: ") || !strings.Contains(out, "address already in use") {
		t.Errorf("the second instance:\n%s", out)
	}
	// And the first goes on.
	if d := dig(t, client, server, "printer.home.arpa", "A"); d.status != "NOERROR" {
		t.Errorf("the first, after: %s", d)
	}
}

// An upstream server given by host name: the bootstrap server, on a machine of its own, tells its
// address, and the queries forwarded go there. Once found, it is still asked while the bootstrap
// server is down.
func TestLiveResolverUpstreamByName(t *testing.T) {
	if _, err := exec.LookPath("dig"); err != nil {
		t.Fatal("the live tests of the resolver ask it with dig, of bind9-dnsutils: not found")
	}
	lan := livetest.NewLAN(t, 16)
	srv := lan.Machine(t, "srv", 10)
	client := lan.Machine(t, "client", 30)
	up := lan.Machine(t, "up", 40)
	boot := lan.Machine(t, "boot", 41)
	upstream := startUpstream(t, up, "192.0.2.53")
	// It answers every A query with the upstream's address: dns.upstream.test's too.
	bootstrap := startUpstream(t, boot, up.IPv4.String())

	config := fmt.Sprintf(`
webserver:
  listen:
    - 8053
resolvers:
  lan:
    listen: 198.18.16.0/24
    upstream: dns.upstream.test
    bootstrap: %s
credentials: {}
tasks: {}
`, boot.IPv4)
	configure(t, srv, lan.Router, "srv", 8053, config).start().serving()
	server := srv.IPv4.String()

	// A name each: one asked again is in the cache.
	for i := range 3 {
		d := dig(t, client, server, fmt.Sprintf("n%d.example.org", i), "A")
		if d.status != "NOERROR" || !slices.Equal(d.data("A"), []string{"192.0.2.53"}) {
			t.Fatalf("query %d, forwarded to the upstream by name: %s", i, d)
		}
	}
	if got := upstream.udp.Load(); got != 3 {
		t.Errorf("the upstream was asked %d times, want 3", got)
	}
	// Its A and AAAA, once: the answer's TTL, 30s, is kept a minute.
	if got := bootstrap.udp.Load(); got != 2 {
		t.Errorf("the bootstrap server was asked %d times, want 2", got)
	}

	bootstrap.mode.Store("down")
	if d := dig(t, client, server, "example.net", "A"); d.status != "NOERROR" || !slices.Equal(d.data("A"), []string{"192.0.2.53"}) {
		t.Errorf("the bootstrap server down, the upstream found before: %s", d)
	}
	// What the bootstrap server is for alone: a name asked of the resolver isn't sent there.
	if got := bootstrap.udp.Load(); got != 2 {
		t.Errorf("the bootstrap server was asked %d times, want still 2", got)
	}
}
