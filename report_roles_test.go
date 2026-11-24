package ipv6ddns

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/ddns"
	"github.com/miguelangel-nubla/ipv6ddns/internal/reportpic"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/certfile"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/resolver"
	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/miguelangel-nubla/ipv6disc/pkg/pretty"
)

// The picture of the report in the README has the roles reportpic.Roles reads from its text: they
// are the roles the program gives, of every kind of line of the names, of the resolvers and of the discovery.
func TestReportPictureHasTheRolesOfTheProgram(t *testing.T) {
	// The names: one that works and waits for its debounce, one that fails and retries, one
	// whose last address went, and one that never had any.
	fail := errors.New("the provider refused")
	works := NewHostname(func(*ipv6disc.AddrCollection) error { return nil }, time.Hour, time.Hour)
	fails := NewHostname(func(*ipv6disc.AddrCollection) error { return fail }, 0, time.Hour)
	went := NewHostname(func(*ipv6disc.AddrCollection) error { return nil }, 0, time.Hour)
	never := NewHostname(func(*ipv6disc.AddrCollection) error { return nil }, 0, time.Hour)
	for _, h := range []*Hostname{works, fails, went, never} {
		t.Cleanup(h.Stop)
	}
	works.SetAddrCollection(collection(addr(macA, "2001:db8::a"), addr(macA, "192.0.2.10")))
	fails.SetAddrCollection(collection(addr(macA, "2001:db8::b")))
	for fails.status().updateError == nil {
		time.Sleep(time.Millisecond)
	}
	went.SetAddrCollection(collection(addr(macA, "2001:db8::c")))
	went.SetAddrCollection(ipv6disc.NewAddrCollection())

	state := NewState()
	state.providers["cloudflare"] = NewProvider()
	endpoint := NewEndpoint(pictureService{})
	state.providers["cloudflare"].endpoints["home"] = endpoint
	for name, h := range map[string]*Hostname{"works.example.com": works, "fails.example.com": fails, "went.example.com": went, "never.example.com": never} {
		endpoint.hostnames[name] = h
	}

	// The discovery: a host with a name two sources say, and addresses of two families.
	disc := ipv6disc.NewState()
	t.Cleanup(disc.Close)
	disc.SetFamilies(true, true)
	disc.SetNames(true, time.Hour)
	hw, _ := net.ParseMAC(macA)
	disc.Register(hw, netip.MustParseAddr("2001:db8::a"), "eth0", time.Hour, nil)
	disc.Report(hw, netip.MustParseAddr("192.0.2.10"), "router", "mikrotik", "leases", time.Hour, nil)
	disc.RegisterName(hw, "nas", "mdns on eth0", time.Hour)
	disc.ReportName(hw, "nas", "router", "leases", time.Hour)

	// The resolvers: one that serves, with an upstream that failed, and one that doesn't.
	resolvers := resolversPage("", []resolver.Status{
		{Name: "lan", Listening: []string{"192.168.1.2:53"}, Allow: []string{"192.168.1.0/24"}, Zones: []string{"lan.example.com"}, ZoneNames: map[string]int{"lan.example.com": 1},
			Serving: true, Upstreams: []string{"192.168.1.1", "tls://1.1.1.1"}, UpstreamFailures: map[string]uint64{"tls://1.1.1.1": 3}, Queries: map[string]uint64{resolver.Local: 7}, CacheSize: 10000, CacheEntries: 12},
		{Name: "guests", Error: "listen udp 192.168.2.1:53: bind: address already in use", Upstreams: []string{"192.168.1.1"}},
		// A certificate of each state: valid, ending soon, ended, and of files that don't read.
		{Name: "dot", Listening: []string{"tls://192.168.1.2:853"}, Serving: true, Upstreams: []string{"192.168.1.1"},
			Certificate: &resolver.CertificateStatus{Names: []string{"dns.lan.example.com"}, NotAfter: time.Now().Add(60 * 24 * time.Hour)}},
		{Name: "doh", Listening: []string{"https://192.168.1.2:443"}, Serving: true, Upstreams: []string{"192.168.1.1"},
			Certificate: &resolver.CertificateStatus{Names: []string{"dns.lan.example.com", "192.168.1.2"}, NotAfter: time.Now().Add(5 * 24 * time.Hour), Error: "open /ssl/privkey.pem: permission denied"}},
		{Name: "doq", Listening: []string{"quic://192.168.1.2:853"}, Serving: true, Upstreams: []string{"192.168.1.1"},
			Certificate: &resolver.CertificateStatus{Names: []string{"dns.lan.example.com"}, NotAfter: time.Now().Add(-time.Hour)}},
		// Of ACME: none yet, its attempt failed; and one, whose renewal failed.
		{Name: "acme", Listening: []string{"tls://192.168.1.2:853"}, Serving: true, Upstreams: []string{"192.168.1.1"},
			Certificate: &resolver.CertificateStatus{Managed: true, Renewal: "the check: 403 unauthorized", NextAttempt: time.Now().Add(time.Hour)}},
		{Name: "renewed", Listening: []string{"tls://192.168.1.3:853"}, Serving: true, Upstreams: []string{"192.168.1.1"},
			Certificate: &resolver.CertificateStatus{Managed: true, Names: []string{"dns.lan.example.com"}, NotAfter: time.Now().Add(20 * 24 * time.Hour), Renewal: "ordering: 429 rate limited"}},
	})

	// And the resolvers when all serve.
	one := resolversPage("", []resolver.Status{{Name: "lan", Listening: []string{"192.168.1.2:53"}, Serving: true, Upstreams: []string{"192.168.1.1"}}})
	for i, line := range reportpic.Roles(one.String()) {
		if want, have := roles(one[i]), roles(line); want != have {
			t.Errorf("the roles of %q:\n%s the program's\n%s the picture's", one[i].String(), want, have)
		}
	}
	if !strings.Contains(one.String(), "Resolvers: 1, 1 serving\n") {
		t.Errorf("the page of a resolver:\n%s", one.String())
	}

	for _, hide := range []bool{true, false} {
		page := append(state.Page("", hide), pretty.Line{})
		page = append(page, resolvers...)
		page = append(page, pretty.Line{})
		page = append(page, disc.Page("")...)
		text := page.String()
		for _, has := range []string{"1 failing", "retrying after the error", "(last update error: ", "(no address: the last one went", "(no address)\n", "debounce", "Resolvers: 7, 6 serving", "none yet", "(getting it failed: the check: 403 unauthorized; again at ", ", in 4 days", "expired on ", "(its files don't read again: ", "(3 failed)", "(0 failed)", "not serving: listen", "Cache: 12 of 10000", "        names:", "            nas "} {
			if !strings.Contains(text, has) {
				t.Fatalf("the page of the test has no %q:\n%s", has, text)
			}
		}
		got := reportpic.Roles(text)
		if len(got) != len(page) {
			t.Fatalf("%d lines, of %d", len(got), len(page))
		}
		for i := range page {
			if want, have := roles(page[i]), roles(got[i]); want != have {
				t.Errorf("the roles of %q:\n%s the program's\n%s the picture's", page[i].String(), want, have)
			}
		}
	}
}

// pictureService is a service that only names its domains.
type pictureService struct{ ddns.Service }

func (pictureService) Domain(hostname string) string { return hostname }

// roles is the role of each letter of a line, a digit each, and a space for a space: the role of
// a space shows nowhere.
func roles(line pretty.Line) string {
	var b strings.Builder
	for _, span := range line {
		for _, r := range span.Text {
			if r == ' ' {
				b.WriteByte(' ')
			} else {
				b.WriteByte('0' + byte(span.Role))
			}
		}
	}
	return b.String()
}

// The web server's section, of its certificate in each state, has the program's roles in the
// picture too.
func TestReportPictureHasTheRolesOfTheWebserver(t *testing.T) {
	for _, c := range []*certfile.Status{
		{Names: []string{"web.lan.example.com"}, NotAfter: time.Now().Add(60 * 24 * time.Hour)},
		{Names: []string{"web.lan.example.com"}, NotAfter: time.Now().Add(3 * 24 * time.Hour), Renewal: "ordering: 429 rate limited"},
		{Managed: true, Renewal: "the check: 403 unauthorized", NextAttempt: time.Now().Add(time.Hour)},
	} {
		var page pretty.Page
		page.Add(pretty.As(pretty.Heading, "Webserver:"))
		page.Add(certificateLine("    ", c, time.Now())...)
		for i, line := range reportpic.Roles(page.String()) {
			if want, have := roles(page[i]), roles(line); want != have {
				t.Errorf("the roles of %q:\n%s the program's\n%s the picture's", page[i].String(), want, have)
			}
		}
	}
}
