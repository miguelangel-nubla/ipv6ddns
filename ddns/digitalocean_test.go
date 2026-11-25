package ddns

import (
	"encoding/json"
	"fmt"
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

// digitalOceanFake serves fake as DigitalOcean's API serves the domain example.com, to the token
// "secret": its records, listed two a page, whatever is asked, and each made, changed and
// deleted apart.
type digitalOceanFake struct {
	t     *testing.T
	fake  *fakeDNS
	mutex sync.Mutex
	// Told to, its next request is refused as too many.
	throttle bool
}

func startDigitalOceanFake(t *testing.T, fake *fakeDNS) (*digitalOceanFake, *httptest.Server) {
	d := &digitalOceanFake{t: t, fake: fake}
	server := httptest.NewServer(d)
	t.Cleanup(server.Close)
	return d, server
}

func (d *digitalOceanFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	fail := func(status int, id, message string) {
		w.WriteHeader(status)
		writeJSON(w, map[string]string{"id": id, "message": message})
	}
	if d.throttle {
		d.throttle = false
		fail(http.StatusTooManyRequests, "too_many_requests", "API Rate limit exceeded.")
		return
	}
	if r.Header.Get("Authorization") != "Bearer secret" {
		fail(http.StatusUnauthorized, "unauthorized", "Unable to authenticate you.")
		return
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/domains/example.com/records")
	if !ok {
		fail(http.StatusNotFound, "not_found", "The resource you were accessing could not be found.")
		return
	}
	d.fake.mutex.Lock()
	defer d.fake.mutex.Unlock()
	full := func(name string) string {
		if name == "@" {
			return "example.com"
		}
		return name + ".example.com"
	}
	relative := func(fqdn string) string {
		if fqdn == "example.com" {
			return "@"
		}
		return strings.TrimSuffix(fqdn, ".example.com")
	}
	id := strings.TrimPrefix(rest, "/")
	switch {
	case r.Method == http.MethodGet && rest == "":
		q := r.URL.Query()
		var all []digitalOceanRecord
		for _, rec := range d.fake.of(q.Get("name")) {
			if rec.rrType == q.Get("type") {
				n, _ := strconv.ParseInt(rec.id, 10, 64)
				all = append(all, digitalOceanRecord{ID: n, Type: rec.rrType, Name: relative(rec.name), Data: rec.ip, TTL: rec.ttl})
			}
		}
		page, _ := strconv.Atoi(q.Get("page"))
		page = max(page, 1)
		from, to := min((page-1)*2, len(all)), min(page*2, len(all))
		answer := map[string]any{"domain_records": append([]digitalOceanRecord{}, all[from:to]...), "links": map[string]any{}}
		if to < len(all) {
			answer["links"] = map[string]any{"pages": map[string]string{"next": fmt.Sprintf("/v2/domains/example.com/records?page=%d", page+1)}}
		}
		writeJSON(w, answer)
	case r.Method == http.MethodPost && rest == "":
		var rec digitalOceanRecord
		json.NewDecoder(r.Body).Decode(&rec)
		if rec.TTL < 30 {
			fail(http.StatusUnprocessableEntity, "unprocessable_entity", "TTL must be at least 30.")
			return
		}
		added := d.fake.add(full(rec.Name), rec.Type, rec.Data, rec.TTL)
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, map[string]any{"domain_record": added})
	case r.Method == http.MethodPatch && id != "":
		var body struct {
			TTL int `json:"ttl"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		i := slices.IndexFunc(d.fake.records, func(rec record) bool { return rec.id == id })
		if i < 0 {
			fail(http.StatusNotFound, "not_found", "no such record")
			return
		}
		d.fake.records[i].ttl = body.TTL
		d.fake.writes++
		writeJSON(w, map[string]any{"domain_record": d.fake.records[i]})
	case r.Method == http.MethodDelete && id != "":
		d.fake.deleteWhere(func(rec record) bool { return rec.id == id })
		w.WriteHeader(http.StatusNoContent)
	default:
		d.t.Errorf("unexpected %s %s", r.Method, r.URL)
		w.WriteHeader(http.StatusBadRequest)
	}
}

func digitalOceanService(t *testing.T, server *httptest.Server, ttl time.Duration) *DigitalOcean {
	t.Helper()
	settings := `{"api_token": "secret", "zone": "Example.com."}`
	if ttl != 0 {
		settings = fmt.Sprintf(`{"api_token": "secret", "zone": "Example.com.", "ttl": "%s"}`, ttl)
	}
	service, err := NewDigitalOcean(json.RawMessage(settings))
	if err != nil {
		t.Fatal(err)
	}
	d := service.(*DigitalOcean)
	d.apiBaseURL = server.URL
	return d
}

// The scenario every provider runs, after a request refused as too many, its records two a page.
func TestDigitalOceanUpdate(t *testing.T) {
	fake := newFakeDNS(t, "nas.example.com", "other.example.com")
	api, server := startDigitalOceanFake(t, fake)
	api.throttle = true
	service := digitalOceanService(t, server, 10*time.Minute)
	fake.check(func(addrs *ipv6disc.AddrCollection) error { return service.Update("nas", addrs) }, "nas.example.com", "other.example.com")
	for _, rec := range fake.of("nas.example.com") {
		if rec.ttl != 600 {
			t.Errorf("record %s: ttl %d, want 600", rec.ip, rec.ttl)
		}
	}
}

// More records of a name than a page has: all of them read, the second of each address deleted.
func TestDigitalOceanPages(t *testing.T) {
	fake := newFakeDNS(t, "nas.example.com", "other.example.com")
	_, server := startDigitalOceanFake(t, fake)
	fake.mutex.Lock()
	for range 3 {
		fake.add("nas.example.com", "AAAA", newIP, 3600)
	}
	fake.mutex.Unlock()
	service := digitalOceanService(t, server, 0)
	if err := service.Update("nas", collectionWith(newIP)); err != nil {
		t.Fatal(err)
	}
	if got := fake.addresses("nas.example.com"); len(got) != 1 || got[0].ip != newIP || got[0].ttl != 3600 {
		t.Errorf("after the pages: %v", got)
	}
}

// The zone's own name, which the API calls @; and a TTL below DigitalOcean's least, refused at
// the start.
func TestDigitalOceanZoneItself(t *testing.T) {
	fake := newFakeDNS(t, "nas.example.com", "other.example.com")
	_, server := startDigitalOceanFake(t, fake)
	service := digitalOceanService(t, server, 0)
	if err := service.Update("example.com", collectionWith(newIPv4)); err != nil {
		t.Fatal(err)
	}
	if got := fake.addresses("example.com"); len(got) != 1 || got[0].ip != newIPv4 {
		t.Errorf("the zone: %v", got)
	}
	if _, err := NewDigitalOcean(json.RawMessage(`{"api_token": "t", "zone": "example.com", "ttl": "10s"}`)); err == nil || !strings.Contains(err.Error(), "below the least DigitalOcean takes, 30s") {
		t.Errorf("a TTL too low: %v", err)
	}
}

// What DigitalOcean refuses, said.
func TestDigitalOceanRefused(t *testing.T) {
	fake := newFakeDNS(t, "nas.example.com", "other.example.com")
	_, server := startDigitalOceanFake(t, fake)
	service := digitalOceanService(t, server, 0)
	service.APIToken = "wrong"
	if err := service.Update("nas", desired()); err == nil || !strings.Contains(err.Error(), "HTTP 401: the token is refused, which must have the write scope: Unable to authenticate you.") {
		t.Errorf("a wrong token: %v", err)
	}
	service.APIToken, service.Zone = "secret", "example.net"
	if err := service.Update("nas", desired()); err == nil || !strings.Contains(err.Error(), "HTTP 404: the domain example.net isn't one of the account's") {
		t.Errorf("another domain: %v", err)
	}
}

// TXT records set, set again to others, and removed: the name's addresses stay.
func TestDigitalOceanSetTXT(t *testing.T) {
	fake := newFakeDNS(t, "nas.example.com", "other.example.com")
	_, server := startDigitalOceanFake(t, fake)
	service := digitalOceanService(t, server, 0)
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
	if got := fake.addresses("nas.example.com"); len(got) != 2 {
		t.Errorf("the addresses of nas: %v", got)
	}
}
