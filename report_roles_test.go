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
	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/miguelangel-nubla/ipv6disc/pkg/pretty"
)

// The picture of the report in the README has the roles reportpic.Roles reads from its text: they
// are the roles the program gives, of every kind of line of the names and of the discovery.
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

	for _, hide := range []bool{true, false} {
		page := append(state.Page("", hide), pretty.Line{})
		page = append(page, disc.Page("")...)
		text := page.String()
		for _, has := range []string{"1 failing", "retrying after the error", "(last update error: ", "(no address: the last one went", "(no address)\n", "debounce", "        names:", "            nas "} {
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
