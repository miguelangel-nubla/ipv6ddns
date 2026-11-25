package ddns

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
)

// porkbunFake serves fake as Porkbun's API serves the domain example.com, of the keys "pk" and
// "sk", with its API access on: its records, each made, edited and deleted apart, of a TTL of 600
// at the least, as Porkbun refuses less.
type porkbunFake struct {
	t     *testing.T
	fake  *fakeDNS
	mutex sync.Mutex
	// Told to, its next request is refused as too many.
	throttle bool
	// The API access of the domain is off.
	noAccess bool
}

func startPorkbunFake(t *testing.T, fake *fakeDNS) (*porkbunFake, *httptest.Server) {
	p := &porkbunFake{t: t, fake: fake}
	server := httptest.NewServer(p)
	t.Cleanup(server.Close)
	return p, server
}

func (p *porkbunFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	fail := func(status int, message string) {
		w.WriteHeader(status)
		writeJSON(w, map[string]string{"status": "ERROR", "message": message})
	}
	if p.throttle {
		p.throttle = false
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		p.t.Errorf("a %s: Porkbun's API takes POSTs alone", r.Method)
	}
	var body map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		p.t.Errorf("a body that isn't JSON: %v", err)
	}
	if body["apikey"] != "pk" || body["secretapikey"] != "sk" {
		fail(http.StatusBadRequest, "Invalid API key. (002)")
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 || parts[0] != "dns" || parts[2] != "example.com" {
		fail(http.StatusBadRequest, "Invalid domain.")
		return
	}
	if p.noAccess {
		fail(http.StatusBadRequest, "Domain is not opted in to API access.")
		return
	}
	p.fake.mutex.Lock()
	defer p.fake.mutex.Unlock()
	full := func(sub string) string {
		if sub == "" {
			return "example.com"
		}
		return sub + ".example.com"
	}
	ttlOf := func() (int, bool) {
		ttl, err := strconv.Atoi(body["ttl"])
		if err != nil || ttl < 600 {
			fail(http.StatusBadRequest, "TTL must be at least 600.")
			return 0, false
		}
		return ttl, true
	}
	switch parts[1] {
	case "retrieveByNameType":
		sub := ""
		if len(parts) > 4 {
			sub = parts[4]
		}
		records := []porkbunRecord{}
		for _, rec := range p.fake.of(full(sub)) {
			if rec.rrType == parts[3] {
				records = append(records, porkbunRecord{ID: rec.id, Name: rec.name, Type: rec.rrType, Content: rec.ip, TTL: strconv.Itoa(rec.ttl)})
			}
		}
		writeJSON(w, map[string]any{"status": "SUCCESS", "records": records})
		return
	case "create":
		ttl, ok := ttlOf()
		if !ok {
			return
		}
		rec := p.fake.add(full(body["name"]), body["type"], body["content"], ttl)
		writeJSON(w, map[string]any{"status": "SUCCESS", "id": rec.id})
		return
	case "edit":
		ttl, ok := ttlOf()
		if !ok {
			return
		}
		i := slices.IndexFunc(p.fake.records, func(rec record) bool { return rec.id == parts[3] })
		if i < 0 {
			fail(http.StatusBadRequest, "Edit error: no record of that id.")
			return
		}
		p.fake.records[i].ip, p.fake.records[i].ttl = body["content"], ttl
		p.fake.writes++
	case "delete":
		p.fake.deleteWhere(func(rec record) bool { return rec.id == parts[3] })
	default:
		p.t.Errorf("unexpected %s", r.URL.Path)
	}
	writeJSON(w, map[string]string{"status": "SUCCESS"})
}

func porkbunService(t *testing.T, server *httptest.Server, ttl time.Duration) *Porkbun {
	t.Helper()
	service, err := NewPorkbun(json.RawMessage(`{"api_key": "pk", "secret_api_key": "sk", "zone": "Example.com."}`))
	if err != nil {
		t.Fatal(err)
	}
	p := service.(*Porkbun)
	p.apiBaseURL, p.TTL.Duration = server.URL, ttl
	return p
}

// The scenario every provider runs, after a request refused as too many.
func TestPorkbunUpdate(t *testing.T) {
	fake := newFakeDNS(t, "nas.example.com", "other.example.com")
	api, server := startPorkbunFake(t, fake)
	api.throttle = true
	service := porkbunService(t, server, 20*time.Minute)
	fake.check(func(addrs *ipv6disc.AddrCollection) error { return service.Update("nas", addrs) }, "nas.example.com", "other.example.com")
	for _, rec := range fake.of("nas.example.com") {
		if rec.ttl != 1200 {
			t.Errorf("record %s: ttl %d, want 1200", rec.ip, rec.ttl)
		}
	}
}

// A TTL below Porkbun's least is raised to it, with a warning, once; without one, the least.
func TestPorkbunTTL(t *testing.T) {
	for _, c := range []struct {
		ttl      time.Duration
		want     int
		warnings int
	}{
		{0, 600, 0},
		{time.Minute, 600, 1},
		{time.Hour, 3600, 0},
	} {
		fake := newFakeDNS(t, "nas.example.com", "other.example.com")
		_, server := startPorkbunFake(t, fake)
		service := porkbunService(t, server, c.ttl)
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

// The zone's own name, of no subdomain in the path.
func TestPorkbunZoneItself(t *testing.T) {
	fake := newFakeDNS(t, "nas.example.com", "other.example.com")
	_, server := startPorkbunFake(t, fake)
	service := porkbunService(t, server, 0)
	if err := service.Update("example.com", collectionWith(newIPv4)); err != nil {
		t.Fatal(err)
	}
	if got := fake.addresses("example.com"); len(got) != 1 || got[0].ip != newIPv4 {
		t.Errorf("the zone: %v", got)
	}
}

// What Porkbun refuses, said, with what to do.
func TestPorkbunRefused(t *testing.T) {
	fake := newFakeDNS(t, "nas.example.com", "other.example.com")
	api, server := startPorkbunFake(t, fake)
	service := porkbunService(t, server, 0)
	service.SecretAPIKey = "wrong"
	if err := service.Update("nas", desired()); err == nil || !strings.Contains(err.Error(), "HTTP 400: the keys are refused: Invalid API key. (002)") {
		t.Errorf("a wrong key: %v", err)
	}
	service.SecretAPIKey = "sk"
	api.noAccess = true
	if err := service.Update("nas", desired()); err == nil || !strings.Contains(err.Error(), "Domain is not opted in to API access.: turn on API Access for example.com, in Porkbun's Domain Management") {
		t.Errorf("no API access: %v", err)
	}
}

// TXT records set, set again to others, and removed: the name's addresses stay.
func TestPorkbunSetTXT(t *testing.T) {
	fake := newFakeDNS(t, "nas.example.com", "other.example.com")
	_, server := startPorkbunFake(t, fake)
	service := porkbunService(t, server, 0)
	name := "_acme-challenge.nas.example.com"
	for _, values := range [][]string{{"one"}, {"one", "two"}, nil} {
		if err := service.SetTXT(name, values); err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, rec := range fake.of(name) {
			got = append(got, rec.ip)
		}
		slices.Sort(got)
		if !slices.Equal(got, values) {
			t.Errorf("TXT %q: got %q", values, got)
		}
	}
	writes := fake.writes
	if err := service.SetTXT(name, nil); err != nil || fake.writes != writes {
		t.Errorf("the same again: %v, %d writes", err, fake.writes-writes)
	}
	if got := fake.addresses("nas.example.com"); len(got) != 2 {
		t.Errorf("the addresses of nas: %v", got)
	}
}
