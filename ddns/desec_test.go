package ddns

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
)

// deSECFake serves fake as deSEC's API serves a domain, example.com, of the token "secret": its
// least TTL, its sets of records, and a PATCH of several, all or none, an empty one removing its
// records. Told to, its next request is refused as too many, after a second's wait.
type deSECFake struct {
	t          *testing.T
	fake       *fakeDNS
	minimumTTL int
	mutex      sync.Mutex
	throttled  bool
	patches    int
	// TXT records, by subname, quoted as the API has them.
	txt map[string][]string
	// What the API refuses: a PATCH, with this status.
	failPatch int
}

func startDeSECFake(t *testing.T, fake *fakeDNS, minimumTTL int) (*deSECFake, *httptest.Server) {
	d := &deSECFake{t: t, fake: fake, minimumTTL: minimumTTL, txt: map[string][]string{}, throttled: true}
	server := httptest.NewServer(d)
	t.Cleanup(server.Close)
	return d, server
}

func (d *deSECFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mutex.Lock()
	throttled := d.throttled
	d.throttled = true
	d.mutex.Unlock()
	if !throttled {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	if r.Header.Get("Authorization") != "Token secret" {
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(w, map[string]string{"detail": "Invalid token."})
		return
	}
	path, ok := strings.CutPrefix(r.URL.Path, "/domains/example.com/")
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		writeJSON(w, map[string]string{"detail": "Not found."})
		return
	}
	d.fake.mutex.Lock()
	defer d.fake.mutex.Unlock()
	name := func(subname string) string {
		if subname == "" {
			return "example.com"
		}
		return subname + ".example.com"
	}
	switch {
	case r.Method == http.MethodGet && path == "":
		writeJSON(w, map[string]any{"name": "example.com", "minimum_ttl": d.minimumTTL})
	case r.Method == http.MethodGet && path == "rrsets/":
		subname := r.URL.Query().Get("subname")
		byType := map[string]*deSECRRset{}
		for _, rec := range d.fake.of(name(subname)) {
			s := byType[rec.rrType]
			if s == nil {
				s = &deSECRRset{Subname: subname, Type: rec.rrType, TTL: rec.ttl}
				byType[rec.rrType] = s
			}
			s.Records = append(s.Records, rec.ip)
		}
		sets := []deSECRRset{}
		for _, t := range slices.Sorted(mapKeys(byType)) {
			sets = append(sets, *byType[t])
		}
		if txt := d.txt[subname]; len(txt) > 0 {
			sets = append(sets, deSECRRset{Subname: subname, Type: "TXT", TTL: 3600, Records: txt})
		}
		writeJSON(w, sets)
	case r.Method == http.MethodPatch && path == "rrsets/":
		var sets []deSECRRset
		if err := json.NewDecoder(r.Body).Decode(&sets); err != nil {
			d.t.Errorf("a PATCH that isn't a list of sets: %v", err)
		}
		if d.failPatch != 0 {
			w.WriteHeader(d.failPatch)
			writeJSON(w, map[string]string{"detail": "refused"})
			return
		}
		// All or none: each set is checked first.
		for _, s := range sets {
			if len(s.Records) > 0 && s.TTL < d.minimumTTL {
				w.WriteHeader(http.StatusBadRequest)
				writeJSON(w, []map[string][]string{{"ttl": {"Ensure this value is greater than or equal to the minimum."}}})
				return
			}
		}
		d.patches++
		for _, s := range sets {
			if s.Type == "TXT" {
				d.txt[s.Subname] = s.Records
				continue
			}
			n := name(s.Subname)
			if slices.ContainsFunc(d.fake.records, func(rec record) bool { return rec.name == n && rec.rrType == s.Type }) {
				d.fake.deleteWhere(func(rec record) bool { return rec.name == n && rec.rrType == s.Type })
			}
			for _, ip := range s.Records {
				d.fake.add(n, s.Type, ip, s.TTL)
			}
		}
		w.WriteHeader(http.StatusOK)
		writeJSON(w, sets)
	default:
		d.t.Errorf("unexpected %s %s", r.Method, r.URL)
		w.WriteHeader(http.StatusBadRequest)
	}
}

func mapKeys[V any](m map[string]V) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

func deSECService(t *testing.T, server *httptest.Server, ttl time.Duration) *DeSEC {
	t.Helper()
	service, err := NewDeSEC(json.RawMessage(`{"token": "secret", "zone": "Example.com."}`))
	if err != nil {
		t.Fatal(err)
	}
	d := service.(*DeSEC)
	d.apiBaseURL, d.TTL.Duration = server.URL, ttl
	return d
}

// The scenario every provider runs, after a request refused as too many, which is asked again.
func TestDeSECUpdate(t *testing.T) {
	fake := newFakeDNS(t, "nas.example.com", "other.example.com")
	api, server := startDeSECFake(t, fake, 300)
	api.throttled = false
	service := deSECService(t, server, 10*time.Minute)
	fake.check(func(addrs *ipv6disc.AddrCollection) error { return service.Update("nas", addrs) }, "nas.example.com", "other.example.com")
	// Each change one request, of every set it changes: the first update, and the one without
	// addresses.
	if api.patches != 2 {
		t.Errorf("%d PATCHes, want 2", api.patches)
	}
}

// A TTL below the zone's least is raised to it, as deSEC refuses it, with a warning, once; without
// one in the settings, the least is the TTL.
func TestDeSECTTL(t *testing.T) {
	for _, c := range []struct {
		ttl      time.Duration
		want     int
		warnings int
	}{
		{0, 3600, 0},
		{time.Minute, 3600, 1},
		{2 * time.Hour, 7200, 0},
	} {
		fake := newFakeDNS(t, "nas.example.com", "other.example.com")
		_, server := startDeSECFake(t, fake, 3600)
		service := deSECService(t, server, c.ttl)
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

// The zone's own name, whose subname is empty, and a name in full, of another case.
func TestDeSECZoneItself(t *testing.T) {
	fake := newFakeDNS(t, "nas.example.com", "other.example.com")
	_, server := startDeSECFake(t, fake, 300)
	service := deSECService(t, server, 0)
	if err := service.Update("example.com", collectionWith(newIPv4)); err != nil {
		t.Fatal(err)
	}
	if err := service.Update("NAS.Example.com.", collectionWith(newIP)); err != nil {
		t.Fatal(err)
	}
	if got := fake.addresses("example.com"); len(got) != 1 || got[0].ip != newIPv4 {
		t.Errorf("the zone: %v", got)
	}
	if got := fake.addresses("nas.example.com"); len(got) != 1 || got[0].ip != newIP {
		t.Errorf("nas, in full: %v", got)
	}
}

// What deSEC refuses, said: the token, a zone not of the account, a PATCH.
func TestDeSECRefused(t *testing.T) {
	fake := newFakeDNS(t, "nas.example.com", "other.example.com")
	api, server := startDeSECFake(t, fake, 300)
	service := deSECService(t, server, 0)
	service.Token = "wrong"
	if err := service.Update("nas", desired()); err == nil || !strings.Contains(err.Error(), "HTTP 401: the token is refused: Invalid token.") {
		t.Errorf("a wrong token: %v", err)
	}
	service.Token, service.Zone = "secret", "example.net"
	if err := service.Update("nas", desired()); err == nil || !strings.Contains(err.Error(), "HTTP 404: the zone example.net isn't one of the account's") {
		t.Errorf("another zone: %v", err)
	}
	service.Zone = "example.com"
	api.failPatch = http.StatusInternalServerError
	err := service.Update("nas", desired())
	if err == nil || !strings.Contains(err.Error(), "writing the records of nas.example.com: HTTP 500: refused") {
		t.Errorf("a PATCH refused: %v", err)
	}
	// Nothing changed: the PATCH is all or none.
	if got := fake.addresses("nas.example.com"); len(got) != 2 {
		t.Errorf("after a PATCH refused: %v", got)
	}
}

// TXT records set, set again to others, and removed: the name's addresses stay.
func TestDeSECSetTXT(t *testing.T) {
	fake := newFakeDNS(t, "nas.example.com", "other.example.com")
	api, server := startDeSECFake(t, fake, 300)
	service := deSECService(t, server, 0)
	name := "_acme-challenge.nas.example.com"
	for _, values := range [][]string{{"one"}, {"one", `two "quoted"`}, nil} {
		if err := service.SetTXT(name, values); err != nil {
			t.Fatal(err)
		}
		var want []string
		for _, v := range values {
			want = append(want, quoteTXT(v))
		}
		got := api.txt["_acme-challenge.nas"]
		slices.Sort(got)
		slices.Sort(want)
		if len(got) != len(want) || !slices.Equal(got, want) {
			t.Errorf("TXT %q: got %q", values, got)
		}
	}
	patches := api.patches
	if err := service.SetTXT(name, nil); err != nil || api.patches != patches {
		t.Errorf("the same again: %v, %d PATCHes", err, api.patches-patches)
	}
	if got := fake.addresses("nas.example.com"); len(got) != 2 {
		t.Errorf("the addresses of nas: %v", got)
	}
	if q := quoteTXT(`a\b"c`); q != `"a\\b\"c"` {
		t.Errorf("quoted: %s", q)
	}
}
