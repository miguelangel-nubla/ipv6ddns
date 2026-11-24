package ddns

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/listen"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/resolver"
	"github.com/miguelangel-nubla/ipv6disc"
)

// An address is answered with no TTL past when it expires, as ipv6disc has it when the query
// comes, not when the name was updated: seen again, longer, without an update, it gets the zone's
// TTL back. Through a resolver that answers the provider's addresses, over the network.
func TestResolverTTLFollowsExpiry(t *testing.T) {
	service, err := NewService("resolver", json.RawMessage(`{"zone": "home.arpa"}`))
	if err != nil {
		t.Fatal(err)
	}
	r := service.(*Resolver)
	cfg := resolver.Config{
		Name:   "lan",
		Path:   "resolvers.lan",
		Listen: []listen.Entry{{Host: "127.0.0.1", Port: "0"}},
		Allow:  []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		Zones: []resolver.Zone{{
			Credential: "home", Name: "home.arpa.", TTL: time.Minute, Addresses: r.Addresses(),
			Tasks: map[string]string{"nas.home.arpa.": "nas"},
		}},
	}
	var s *resolver.Server
	// Port 0 over UDP can be taken over TCP by another test's server: then another.
	for try := 0; ; try++ {
		if s, err = resolver.New(cfg, t.Errorf); err != nil {
			t.Fatal(err)
		}
		if err = s.Start(); err == nil {
			break
		}
		if try == 5 || !strings.Contains(err.Error(), "address already in use") {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { s.Shutdown(context.Background()) })
	ttl := func() uint32 {
		t.Helper()
		m := new(dns.Msg)
		m.SetQuestion("nas.home.arpa.", dns.TypeAAAA)
		resp, _, err := (&dns.Client{Timeout: 3 * time.Second}).Exchange(m, s.Addresses()[0])
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Answer) != 1 {
			t.Fatalf("answer: %v", resp)
		}
		return resp.Answer[0].Header().Ttl
	}

	ip := netip.MustParseAddr("2001:db8::10")
	addrs := ipv6disc.NewAddrCollection()
	addrs.Add(ipv6disc.NewAddr(nil, ip, "ndp", 20*time.Second, nil))
	if err := r.Update("nas", addrs); err != nil {
		t.Fatal(err)
	}
	if got := ttl(); got < 18 || got > 20 {
		t.Errorf("expiring in 20s: TTL %d, want 19 or so", got)
	}
	// Another sighting, for an hour: the address the provider was given expires later, and the
	// provider isn't told.
	addrs.Seen(ipv6disc.NewAddr(nil, ip, "mdns", time.Hour, nil), "mdns")
	if got := ttl(); got != 60 {
		t.Errorf("seen again for an hour: TTL %d, want the zone's, 60", got)
	}
}
