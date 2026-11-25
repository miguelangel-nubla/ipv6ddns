package ddns

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
)

// gandiFake serves fake as Gandi's LiveDNS API serves the domain example.com, to the token
// "secret": its sets of records, each read, written whole and deleted, of a TTL of 300 at the
// least. The TXT sets are its own, by name.
type gandiFake struct {
	t     *testing.T
	fake  *fakeDNS
	mutex sync.Mutex
	txt   map[string]gandiRRset
	puts  int
	// Told to, its next request is refused as too many.
	throttle bool
}

func startGandiFake(t *testing.T, fake *fakeDNS) (*gandiFake, *httptest.Server) {
	g := &gandiFake{t: t, fake: fake, txt: map[string]gandiRRset{}}
	server := httptest.NewServer(g)
	t.Cleanup(server.Close)
	return g, server
}

func (g *gandiFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	fail := func(status int, message string) {
		w.WriteHeader(status)
		writeJSON(w, map[string]any{"code": status, "message": message, "object": "HTTPError"})
	}
	if g.throttle {
		g.throttle = false
		fail(http.StatusTooManyRequests, "Too many requests")
		return
	}
	if r.Header.Get("Authorization") != "Bearer secret" {
		fail(http.StatusUnauthorized, "The server could not verify that you authorized to access the document you requested.")
		return
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/domains/example.com/records/")
	parts := strings.Split(rest, "/")
	if !ok || len(parts) != 2 {
		fail(http.StatusNotFound, "Domain not found")
		return
	}
	sub, rrType := parts[0], parts[1]
	name := sub + ".example.com"
	if sub == "@" {
		name = "example.com"
	}
	g.fake.mutex.Lock()
	defer g.fake.mutex.Unlock()
	switch r.Method {
	case http.MethodGet:
		if rrType == "TXT" {
			if s, ok := g.txt[sub]; ok {
				writeJSON(w, s)
				return
			}
			fail(http.StatusNotFound, "Record not found")
			return
		}
		recs := slices.DeleteFunc(g.fake.of(name), func(rec record) bool { return rec.rrType != rrType })
		if len(recs) == 0 {
			fail(http.StatusNotFound, "Record not found")
			return
		}
		s := gandiRRset{Name: sub, Type: rrType, TTL: recs[0].ttl}
		for _, rec := range recs {
			s.Values = append(s.Values, rec.ip)
		}
		writeJSON(w, s)
	case http.MethodPut:
		var s gandiRRset
		json.NewDecoder(r.Body).Decode(&s)
		if s.TTL < 300 {
			fail(http.StatusBadRequest, "rrset_ttl: must be at least 300")
			return
		}
		g.puts++
		if rrType == "TXT" {
			g.txt[sub] = gandiRRset{Name: sub, Type: "TXT", TTL: s.TTL, Values: s.Values}
		} else {
			if slices.ContainsFunc(g.fake.records, func(rec record) bool { return rec.name == name && rec.rrType == rrType }) {
				g.fake.deleteWhere(func(rec record) bool { return rec.name == name && rec.rrType == rrType })
			}
			for _, v := range s.Values {
				g.fake.add(name, rrType, v, s.TTL)
			}
		}
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, map[string]string{"message": "DNS Record Created"})
	case http.MethodDelete:
		if rrType == "TXT" {
			delete(g.txt, sub)
		} else {
			g.fake.deleteWhere(func(rec record) bool { return rec.name == name && rec.rrType == rrType })
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		g.t.Errorf("unexpected %s %s", r.Method, r.URL)
	}
}

func gandiService(t *testing.T, server *httptest.Server, ttl time.Duration) *Gandi {
	t.Helper()
	settings := `{"token": "secret", "zone": "Example.com."}`
	if ttl != 0 {
		settings = fmt.Sprintf(`{"token": "secret", "zone": "Example.com.", "ttl": "%s"}`, ttl)
	}
	service, err := NewGandi(json.RawMessage(settings))
	if err != nil {
		t.Fatal(err)
	}
	g := service.(*Gandi)
	g.apiBaseURL = server.URL
	return g
}

// The scenario every provider runs, after a request refused as too many.
func TestGandiUpdate(t *testing.T) {
	fake := newFakeDNS(t, "nas.example.com", "other.example.com")
	api, server := startGandiFake(t, fake)
	api.throttle = true
	service := gandiService(t, server, 10*time.Minute)
	fake.check(func(addrs *ipv6disc.AddrCollection) error { return service.Update("nas", addrs) }, "nas.example.com", "other.example.com")
	for _, rec := range fake.of("nas.example.com") {
		if rec.ttl != 600 {
			t.Errorf("record %s: ttl %d, want 600", rec.ip, rec.ttl)
		}
	}
}

// A TTL below Gandi's least is raised to it, with a warning, once; without one, Gandi's own.
func TestGandiTTL(t *testing.T) {
	for _, c := range []struct {
		ttl      time.Duration
		want     int
		warnings int
	}{
		{0, 10800, 0},
		{time.Minute, 300, 1},
		{time.Hour, 3600, 0},
	} {
		fake := newFakeDNS(t, "nas.example.com", "other.example.com")
		_, server := startGandiFake(t, fake)
		service := gandiService(t, server, c.ttl)
		for range 2 {
			if err := service.Update("nas", collectionWith(newIP, newIPv4)); err != nil {
				t.Fatal(err)
			}
		}
		for _, rec := range fake.addresses("nas.example.com") {
			if rec.ttl != c.want {
				t.Errorf("ttl %s: a record of %d, want %d", c.ttl, rec.ttl, c.want)
			}
		}
		if w := service.Warnings(); len(w) != c.warnings {
			t.Errorf("ttl %s: warnings %q, want %d", c.ttl, w, c.warnings)
		}
	}
}

// The zone's own name, which the API calls @.
func TestGandiZoneItself(t *testing.T) {
	fake := newFakeDNS(t, "nas.example.com", "other.example.com")
	_, server := startGandiFake(t, fake)
	service := gandiService(t, server, 0)
	if err := service.Update("example.com", collectionWith(newIPv4)); err != nil {
		t.Fatal(err)
	}
	if got := fake.addresses("example.com"); len(got) != 1 || got[0].ip != newIPv4 {
		t.Errorf("the zone: %v", got)
	}
}

// What Gandi refuses, said.
func TestGandiRefused(t *testing.T) {
	fake := newFakeDNS(t, "nas.example.com", "other.example.com")
	_, server := startGandiFake(t, fake)
	service := gandiService(t, server, 0)
	service.Token = "wrong"
	if err := service.Update("nas", desired()); err == nil || !strings.Contains(err.Error(), "HTTP 401: the token is refused, which must manage the domain's technical configuration") {
		t.Errorf("a wrong token: %v", err)
	}
	service.Token, service.Zone = "secret", "example.net"
	if err := service.Update("nas", desired()); err == nil || !strings.Contains(err.Error(), "HTTP 404: the domain example.net isn't one of the account's, at LiveDNS") {
		t.Errorf("another domain: %v", err)
	}
}

// TXT records set, set again to others, and removed: the name's addresses stay.
func TestGandiSetTXT(t *testing.T) {
	fake := newFakeDNS(t, "nas.example.com", "other.example.com")
	api, server := startGandiFake(t, fake)
	service := gandiService(t, server, 0)
	for _, values := range [][]string{{"one"}, {"one", "two"}, nil} {
		if err := service.SetTXT("_acme-challenge.nas", values); err != nil {
			t.Fatal(err)
		}
		var want []string
		for _, v := range values {
			want = append(want, quoteTXT(v))
		}
		got := slices.Clone(api.txt["_acme-challenge.nas"].Values)
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("TXT %q: got %q", values, got)
		}
	}
	puts := api.puts
	if err := service.SetTXT("_acme-challenge.nas", nil); err != nil || api.puts != puts {
		t.Errorf("the same again: %v, %d writes", err, api.puts-puts)
	}
	if got := fake.addresses("nas.example.com"); len(got) != 2 {
		t.Errorf("the addresses of nas: %v", got)
	}
}
