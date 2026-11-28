package ddns

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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

// ovhFake serves fake as OVH's API serves the zone example.com, to the application "ak" of the
// secret "as" and the consumer "ck": each request signed, of its own clock, an hour ahead of this
// one's, as /auth/time tells; the records, listed by id and read apart, each made, changed and
// deleted; and the refreshes of the zone, counted.
type ovhFake struct {
	t         *testing.T
	fake      *fakeDNS
	mutex     sync.Mutex
	ahead     time.Duration
	refreshes int
	// Told to, its next request is refused as too many.
	throttle bool
	// Its refreshes fail, as its other requests don't.
	failRefresh bool
	// It lists the records of every name, whatever the name asked.
	wholeZone bool
}

func startOVHFake(t *testing.T, fake *fakeDNS) (*ovhFake, *httptest.Server) {
	o := &ovhFake{t: t, fake: fake, ahead: time.Hour}
	server := httptest.NewServer(o)
	t.Cleanup(server.Close)
	return o, server
}

func (o *ovhFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	fail := func(status int, message string) {
		w.WriteHeader(status)
		writeJSON(w, map[string]string{"message": message})
	}
	now := time.Now().Add(o.ahead)
	if r.URL.Path == "/auth/time" {
		fmt.Fprint(w, now.Unix())
		return
	}
	if o.throttle {
		o.throttle = false
		fail(http.StatusTooManyRequests, "Too many requests")
		return
	}
	body, _ := io.ReadAll(r.Body)
	timestamp := r.Header.Get("X-Ovh-Timestamp")
	sum := sha1.Sum([]byte(strings.Join([]string{"as", r.Header.Get("X-Ovh-Consumer"), r.Method, "http://" + r.Host + r.URL.RequestURI(), string(body), timestamp}, "+")))
	if r.Header.Get("X-Ovh-Application") != "ak" || r.Header.Get("X-Ovh-Consumer") != "ck" || r.Header.Get("X-Ovh-Signature") != "$1$"+hex.EncodeToString(sum[:]) {
		fail(http.StatusForbidden, "Invalid signature")
		return
	}
	if ts, _ := strconv.ParseInt(timestamp, 10, 64); now.Sub(time.Unix(ts, 0)).Abs() > 30*time.Second {
		fail(http.StatusUnauthorized, "Query is out of time")
		return
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/domain/zone/example.com")
	if !ok {
		fail(http.StatusNotFound, "This service does not exist")
		return
	}
	o.fake.mutex.Lock()
	defer o.fake.mutex.Unlock()
	full := func(sub string) string {
		if sub == "" {
			return "example.com"
		}
		return sub + ".example.com"
	}
	relative := func(name string) string {
		if name == "example.com" {
			return ""
		}
		return strings.TrimSuffix(name, ".example.com")
	}
	find := func(id string) int {
		return slices.IndexFunc(o.fake.records, func(rec record) bool { return rec.id == id })
	}
	id := strings.TrimPrefix(rest, "/record/")
	switch {
	case r.Method == http.MethodPost && rest == "/refresh" && o.failRefresh:
		fail(http.StatusInternalServerError, "Internal server error")
		return
	case r.Method == http.MethodPost && rest == "/refresh":
		o.refreshes++
	case r.Method == http.MethodGet && rest == "/record":
		q := r.URL.Query()
		ids := []int64{}
		listed := o.fake.of(full(q.Get("subDomain")))
		if o.wholeZone {
			listed = o.fake.records
		}
		for _, rec := range listed {
			if rec.rrType == q.Get("fieldType") {
				n, _ := strconv.ParseInt(rec.id, 10, 64)
				ids = append(ids, n)
			}
		}
		writeJSON(w, ids)
		return
	case r.Method == http.MethodGet && id != rest:
		i := find(id)
		if i < 0 {
			fail(http.StatusNotFound, "no such record")
			return
		}
		rec := o.fake.records[i]
		n, _ := strconv.ParseInt(rec.id, 10, 64)
		writeJSON(w, ovhRecord{ID: n, FieldType: rec.rrType, SubDomain: relative(rec.name), Target: rec.ip, TTL: rec.ttl})
		return
	case r.Method == http.MethodPost && rest == "/record":
		var rec ovhRecord
		json.Unmarshal(body, &rec)
		added := o.fake.add(full(rec.SubDomain), rec.FieldType, rec.Target, rec.TTL)
		writeJSON(w, added)
		return
	case r.Method == http.MethodPut && id != rest:
		var change struct {
			Target string `json:"target"`
			TTL    int    `json:"ttl"`
		}
		json.Unmarshal(body, &change)
		i := find(id)
		if i < 0 {
			fail(http.StatusNotFound, "no such record")
			return
		}
		o.fake.records[i].ip, o.fake.records[i].ttl = change.Target, change.TTL
		o.fake.writes++
	case r.Method == http.MethodDelete && id != rest:
		o.fake.deleteWhere(func(rec record) bool { return rec.id == id })
	default:
		o.t.Errorf("unexpected %s %s", r.Method, r.URL)
		fail(http.StatusBadRequest, "unexpected")
		return
	}
	w.Write([]byte("null"))
}

func ovhService(t *testing.T, server *httptest.Server, ttl time.Duration) *OVH {
	t.Helper()
	settings := `{"application_key": "ak", "application_secret": "as", "consumer_key": "ck", "zone": "Example.com."}`
	service, err := NewOVH(json.RawMessage(settings))
	if err != nil {
		t.Fatal(err)
	}
	o := service.(*OVH)
	o.apiBaseURL, o.TTL.Duration = server.URL, ttl
	return o
}

// The scenario every provider runs, after a request refused as too many, signed of OVH's clock,
// an hour ahead: the zone refreshed after each update that changed it, and after no other.
func TestOVHUpdate(t *testing.T) {
	fake := newFakeDNS(t, "nas.example.com", "other.example.com")
	api, server := startOVHFake(t, fake)
	api.throttle = true
	service := ovhService(t, server, 10*time.Minute)
	fake.check(func(addrs *ipv6disc.AddrCollection) error { return service.Update("nas", addrs) }, "nas.example.com", "other.example.com")
	if api.refreshes != 2 {
		t.Errorf("%d refreshes, want 2: of the first update and of the one without addresses", api.refreshes)
	}
	for _, rec := range fake.of("nas.example.com") {
		if rec.ttl != 600 {
			t.Errorf("record %s: ttl %d, want 600", rec.ip, rec.ttl)
		}
	}
}

// The zone's own name, of an empty subdomain; and the endpoints and TTLs the settings may give.
func TestOVHSettings(t *testing.T) {
	fake := newFakeDNS(t, "nas.example.com", "other.example.com")
	_, server := startOVHFake(t, fake)
	service := ovhService(t, server, 0)
	if err := service.Update("example.com", collectionWith(newIPv4)); err != nil {
		t.Fatal(err)
	}
	if got := fake.addresses("example.com"); len(got) != 1 || got[0].ip != newIPv4 || got[0].ttl != 3600 {
		t.Errorf("the zone: %v", got)
	}
	keys := `"application_key": "a", "application_secret": "b", "consumer_key": "c", "zone": "example.com"`
	for _, c := range []struct{ settings, base, err string }{
		{keys, "https://eu.api.ovh.com/1.0", ""},
		{keys + `, "endpoint": "ovh-ca"`, "https://ca.api.ovh.com/1.0", ""},
		{keys + `, "endpoint": "https://api.example.net/1.0/"`, "https://api.example.net/1.0", ""},
		{keys + `, "endpoint": "ovh-mars"`, "", `the endpoint "ovh-mars" is none of ovh-eu, ovh-ca and ovh-us, nor an https:// URL`},
		{keys + `, "ttl": "30s"`, "", "below the least OVH takes, 60s"},
	} {
		s, err := NewOVH(json.RawMessage("{" + c.settings + "}"))
		switch {
		case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Errorf("%s: %v, want %s", c.settings, err, c.err)
		case c.err == "" && (err != nil || s.(*OVH).apiBaseURL != c.base):
			t.Errorf("%s: %v, %v", c.settings, s, err)
		}
	}
}

// What OVH refuses, said; and an update that fails halfway still refreshes what it changed.
func TestOVHRefused(t *testing.T) {
	fake := newFakeDNS(t, "nas.example.com", "other.example.com")
	api, server := startOVHFake(t, fake)
	service := ovhService(t, server, 0)
	service.ApplicationSecret = "wrong"
	if err := service.Update("nas", desired()); err == nil || !strings.Contains(err.Error(), "HTTP 403: the keys are refused, of which the consumer key must allow GET, POST, PUT and DELETE on /domain/zone/example.com/*: Invalid signature") {
		t.Errorf("a wrong secret: %v", err)
	}
	service.ApplicationSecret, service.Zone = "as", "example.net"
	if err := service.Update("nas", desired()); err == nil || !strings.Contains(err.Error(), "the zone example.net isn't one of the account's, or the endpoint isn't its") {
		t.Errorf("another zone: %v", err)
	}
	// A clock never asked: refused as out of time.
	stale := ovhService(t, server, 0)
	stale.clockKnown = true
	if err := stale.Update("nas", desired()); err == nil || !strings.Contains(err.Error(), "Query is out of time") {
		t.Errorf("a clock an hour off: %v", err)
	}
	if api.refreshes != 0 {
		t.Errorf("refreshed %d times, of nothing changed", api.refreshes)
	}
}

// TXT records set, set again to others, and removed, each refreshed: the name's addresses stay.
func TestOVHSetTXT(t *testing.T) {
	fake := newFakeDNS(t, "nas.example.com", "other.example.com")
	api, server := startOVHFake(t, fake)
	service := ovhService(t, server, 0)
	name := "_acme-challenge.nas.example.com"
	for i, values := range [][]string{{"one"}, {"one", "two"}, nil} {
		if err := service.SetTXT(name, values); err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, rec := range fake.of(name) {
			got = append(got, rec.ip)
		}
		slices.Sort(got)
		if !slices.Equal(got, values) || api.refreshes != i+1 {
			t.Errorf("TXT %q: got %q, %d refreshes", values, got, api.refreshes)
		}
	}
	if err := service.SetTXT(name, nil); err != nil || api.refreshes != 3 {
		t.Errorf("the same again: %v, %d refreshes", err, api.refreshes)
	}
}

// A refresh that failed is one the next update owes: it finds the records as wanted, and nothing
// to change, and they are written and not served until the zone is refreshed.
func TestOVHRefreshesAfterFailedRefresh(t *testing.T) {
	for name, update := range map[string]func(*OVH) error{
		"addresses": func(o *OVH) error { return o.Update("nas", desired()) },
		"TXT":       func(o *OVH) error { return o.SetTXT("_acme-challenge.nas.example.com", []string{"token"}) },
	} {
		t.Run(name, func(t *testing.T) {
			fake := newFakeDNS(t, "nas.example.com", "other.example.com")
			api, server := startOVHFake(t, fake)
			service := ovhService(t, server, 0)

			api.failRefresh = true
			if err := update(service); err == nil || !strings.Contains(err.Error(), "refreshing the zone") {
				t.Fatalf("the update whose refresh failed: %v", err)
			}
			api.failRefresh = false
			writes := fake.writes
			if err := update(service); err != nil {
				t.Fatal(err)
			}
			if fake.writes != writes || api.refreshes != 1 {
				t.Errorf("the update after one whose refresh failed: %d writes and %d refreshes, want none and one", fake.writes-writes, api.refreshes)
			}
			if err := update(service); err != nil || api.refreshes != 1 {
				t.Errorf("the one after it, with nothing left to serve: %v, %d refreshes", err, api.refreshes)
			}
		})
	}
}

// A listing with the records of other names, as of an API that took the zone's empty name for
// every name, is not the name's: they are neither counted as its own nor deleted.
func TestOVHRecordsOfOtherNames(t *testing.T) {
	fake := newFakeDNS(t, "nas.example.com", "other.example.com")
	api, server := startOVHFake(t, fake)
	fake.add("other.example.com", "TXT", "keep", 300)
	api.wholeZone = true
	service := ovhService(t, server, 0)
	if err := service.Update("example.com", collectionWith(newIPv4)); err != nil {
		t.Fatal(err)
	}
	if err := service.SetTXT("example.com", nil); err != nil {
		t.Fatal(err)
	}
	if got := fake.addresses("example.com"); len(got) != 1 || got[0].ip != newIPv4 {
		t.Errorf("the zone: %v", got)
	}
	if nas, other := fake.of("nas.example.com"), fake.of("other.example.com"); len(nas) != 2 || len(other) != 2 {
		t.Errorf("the other names: nas has %v, and other %v, want the 2 of each", nas, other)
	}
}
