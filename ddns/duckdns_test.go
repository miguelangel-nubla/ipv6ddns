package ddns

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
)

const duckToken = "01234567-89ab-cdef-0123-456789abcdef"

// fakeDuckDNS answers updates as the DuckDNS spec says: an IPv4 left out is the requester's,
// unless an IPv6 is given; clear empties both records; verbose tells them.
type fakeDuckDNS struct {
	mutex      sync.Mutex
	ipv4, ipv6 string
	requests   []url.Values
	refuse     bool
}

const requesterIPv4 = "203.0.113.7"

func (f *fakeDuckDNS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	q := r.URL.Query()
	f.requests = append(f.requests, q)
	if f.refuse || q.Get("token") != duckToken || !strings.EqualFold(q.Get("domains"), "nas") {
		w.Write([]byte("KO"))
		return
	}
	switch {
	case q.Get("clear") == "true":
		f.ipv4, f.ipv6 = "", ""
	default:
		ip, ipv6 := q.Get("ip"), q.Get("ipv6")
		if addr, err := netip.ParseAddr(ip); err == nil && addr.Is6() {
			f.ipv6, ip = ip, ""
		}
		if ipv6 != "" {
			f.ipv6 = ipv6
		}
		switch {
		case ip != "":
			f.ipv4 = ip
		case ipv6 == "":
			f.ipv4 = requesterIPv4 // detected
		}
	}
	if q.Get("verbose") == "true" {
		fmt.Fprintf(w, "OK\n%s\n%s\nUPDATED", f.ipv4, f.ipv6)
		return
	}
	w.Write([]byte("OK"))
}

func TestDuckDNSUpdate(t *testing.T) {
	for _, tt := range []struct {
		name               string
		before             [2]string
		addresses          []string
		wantIPv4, wantIPv6 string
	}{
		// DuckDNS takes one address of each family: the first.
		{"both", [2]string{}, []string{"2001:db8::10", "192.0.2.9", "2001:db8::9", "192.0.2.10"}, "192.0.2.9", "2001:db8::9"},
		{"IPv6 only, with an IPv4 before", [2]string{"192.0.2.1", "2001:db8::1"}, []string{"2001:db8::9"}, "", "2001:db8::9"},
		{"IPv6 only", [2]string{}, []string{"2001:db8::9"}, "", "2001:db8::9"},
		{"IPv4 only, with an IPv6 before", [2]string{"192.0.2.1", "2001:db8::1"}, []string{"192.0.2.9"}, "192.0.2.9", ""},
		{"no addresses", [2]string{"192.0.2.1", "2001:db8::1"}, nil, "", ""},
	} {
		fake := &fakeDuckDNS{ipv4: tt.before[0], ipv6: tt.before[1]}
		server := httptest.NewServer(fake)
		service := &DuckDNS{APIToken: duckToken, updateURL: server.URL}

		if err := service.Update("nas", collectionWith(tt.addresses...)); err != nil {
			t.Errorf("%s: %v", tt.name, err)
		}
		if fake.ipv4 != tt.wantIPv4 || fake.ipv6 != tt.wantIPv6 {
			t.Errorf("%s: got %q and %q, want %q and %q", tt.name, fake.ipv4, fake.ipv6, tt.wantIPv4, tt.wantIPv6)
		}
		for _, q := range fake.requests {
			for _, key := range []string{"ip", "ipv6"} {
				if v, ok := q[key]; ok && v[0] == "" {
					t.Errorf("%s: a request with an empty %s, which DuckDNS takes as the requester's: %v", tt.name, key, q)
				}
			}
		}

		// Once right, an update is one request.
		fake.requests = nil
		service.Update("nas", collectionWith(tt.addresses...))
		if len(fake.requests) != 1 {
			t.Errorf("%s: the second update made %d requests, want 1", tt.name, len(fake.requests))
		}
		server.Close()
	}
}

func TestDuckDNSRefused(t *testing.T) {
	server := httptest.NewServer(&fakeDuckDNS{refuse: true})
	defer server.Close()
	service := &DuckDNS{APIToken: duckToken, updateURL: server.URL}
	if err := service.Update("nas", collectionWith("2001:db8::9")); err == nil {
		t.Error("a KO answer: want an error")
	}
	// A name given with duckdns.org is the name DuckDNS knows, without it.
	accepting := &fakeDuckDNS{}
	server = httptest.NewServer(accepting)
	defer server.Close()
	service = &DuckDNS{APIToken: duckToken, updateURL: server.URL}
	for _, hostname := range []string{"nas.duckdns.org", "NAS.DuckDNS.org."} {
		if err := service.Update(hostname, collectionWith("2001:db8::9")); err != nil {
			t.Errorf("%s: %v", hostname, err)
		}
		if got := accepting.requests[len(accepting.requests)-1].Get("domains"); !strings.EqualFold(got, "nas") {
			t.Errorf("%s: asked for the domain %q, want nas", hostname, got)
		}
	}
	if service.Domain("nas") != "nas.duckdns.org" {
		t.Errorf("domain: %s", service.Domain("nas"))
	}
}

// The providers that send their token in the URL must not have it in their errors, which are
// logged.
func TestTokenNotInErrors(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	server.Close() // nothing listens there

	for name, update := range map[string]func() error{
		"duckdns": func() error { return (&DuckDNS{APIToken: duckToken, updateURL: server.URL}).Update("nas", desired()) },
		"technitium": func() error {
			return (&Technitium{Address: server.URL, Token: duckToken, Zone: "lan"}).Update("nas", desired())
		},
	} {
		err := update()
		if err == nil {
			t.Errorf("%s: want an error", name)
		} else if strings.Contains(err.Error(), duckToken) {
			t.Errorf("%s: the token is in the error: %v", name, err)
		}
	}
}
