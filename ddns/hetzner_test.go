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

// hetznerFake serves fake as the Hetzner Cloud API serves a zone, example.com of id 42, to the
// token "secret": its sets of records, and their changes, each an action that is running when
// made and done when asked after. The TXT records are its own, by name.
type hetznerFake struct {
	t       *testing.T
	fake    *fakeDNS
	zoneTTL int
	mutex   sync.Mutex
	actions map[int64]string
	nextID  int64
	changes int
	txt     map[string][]string
	txtTTL  map[string]int
	// The status a change's action ends with: success, unless told.
	ends string
	// Told to, its next request is refused as too many.
	throttle bool
}

func startHetznerFake(t *testing.T, fake *fakeDNS) (*hetznerFake, *httptest.Server) {
	h := &hetznerFake{t: t, fake: fake, zoneTTL: 3600, actions: map[int64]string{}, txt: map[string][]string{}, txtTTL: map[string]int{}, ends: "success"}
	server := httptest.NewServer(h)
	t.Cleanup(server.Close)
	return h, server
}

func (h *hetznerFake) action() map[string]any {
	h.nextID++
	h.actions[h.nextID] = h.ends
	h.changes++
	return map[string]any{"action": map[string]any{"id": h.nextID, "status": "running"}}
}

func (h *hetznerFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	if h.throttle {
		h.throttle = false
		w.WriteHeader(http.StatusTooManyRequests)
		writeJSON(w, map[string]any{"error": map[string]string{"code": "rate_limit_exceeded", "message": "slow down"}})
		return
	}
	if r.Header.Get("Authorization") != "Bearer secret" {
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(w, map[string]any{"error": map[string]string{"code": "unauthorized", "message": "unable to authenticate"}})
		return
	}
	h.fake.mutex.Lock()
	defer h.fake.mutex.Unlock()
	name := func(sub string) string {
		if sub == "@" {
			return "example.com"
		}
		return sub + ".example.com"
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/zones":
		zones := []map[string]any{}
		if r.URL.Query().Get("name") == "example.com" {
			zones = append(zones, map[string]any{"id": 42, "name": "example.com", "ttl": h.zoneTTL})
		}
		writeJSON(w, map[string]any{"zones": zones})
	case r.Method == http.MethodGet && len(parts) == 2 && parts[0] == "actions":
		var id int64
		fmt.Sscan(parts[1], &id)
		status := h.actions[id]
		a := map[string]any{"id": id, "status": status}
		if status == "error" {
			a["error"] = map[string]string{"code": "action_failed", "message": "the zone is locked"}
		}
		writeJSON(w, map[string]any{"action": a})
	case len(parts) >= 3 && parts[0] == "zones" && parts[1] == "42" && parts[2] == "rrsets":
		h.rrsets(w, r, parts[3:], name)
	default:
		w.WriteHeader(http.StatusNotFound)
		writeJSON(w, map[string]any{"error": map[string]string{"code": "not_found", "message": "not found"}})
	}
}

func (h *hetznerFake) rrsets(w http.ResponseWriter, r *http.Request, rest []string, name func(string) string) {
	ttlOf := func(ttl int) *int {
		if ttl == 0 {
			return nil
		}
		return &ttl
	}
	switch {
	case r.Method == http.MethodGet && len(rest) == 0:
		sub, rrType := r.URL.Query().Get("name"), r.URL.Query().Get("type")
		sets := []hetznerRRset{}
		if rrType == "TXT" {
			if v := h.txt[sub]; len(v) > 0 {
				s := hetznerRRset{Name: sub, Type: "TXT", TTL: ttlOf(h.txtTTL[sub])}
				for _, x := range v {
					s.Records = append(s.Records, hetznerRecord{Value: x})
				}
				sets = append(sets, s)
			}
		} else if recs := slices.DeleteFunc(h.fake.of(name(sub)), func(rec record) bool { return rec.rrType != rrType }); len(recs) > 0 {
			s := hetznerRRset{Name: sub, Type: rrType, TTL: ttlOf(recs[0].ttl)}
			for _, rec := range recs {
				s.Records = append(s.Records, hetznerRecord{Value: rec.ip})
			}
			sets = append(sets, s)
		}
		writeJSON(w, map[string]any{"rrsets": sets})
	case r.Method == http.MethodPost && len(rest) == 0:
		var s hetznerRRset
		json.NewDecoder(r.Body).Decode(&s)
		ttl := 0
		if s.TTL != nil {
			ttl = *s.TTL
		}
		if s.Type == "TXT" {
			h.txt[s.Name], h.txtTTL[s.Name] = nil, ttl
			for _, rec := range s.Records {
				h.txt[s.Name] = append(h.txt[s.Name], rec.Value)
			}
		} else {
			for _, rec := range s.Records {
				h.fake.add(name(s.Name), s.Type, rec.Value, ttl)
			}
		}
		writeJSON(w, h.action())
	case len(rest) == 2 && r.Method == http.MethodDelete:
		if rest[1] == "TXT" {
			delete(h.txt, rest[0])
		} else {
			h.fake.deleteWhere(func(rec record) bool { return rec.name == name(rest[0]) && rec.rrType == rest[1] })
		}
		writeJSON(w, h.action())
	case len(rest) == 4 && rest[2] == "actions" && rest[3] == "set_records":
		var body struct {
			Records []hetznerRecord `json:"records"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if rest[1] == "TXT" {
			h.txt[rest[0]] = nil
			for _, rec := range body.Records {
				h.txt[rest[0]] = append(h.txt[rest[0]], rec.Value)
			}
		} else {
			n := name(rest[0])
			ttl := 0
			if recs := slices.DeleteFunc(h.fake.of(n), func(rec record) bool { return rec.rrType != rest[1] }); len(recs) > 0 {
				ttl = recs[0].ttl
			}
			h.fake.deleteWhere(func(rec record) bool { return rec.name == n && rec.rrType == rest[1] })
			for _, rec := range body.Records {
				h.fake.add(n, rest[1], rec.Value, ttl)
			}
		}
		writeJSON(w, h.action())
	case len(rest) == 4 && rest[2] == "actions" && rest[3] == "change_ttl":
		var body struct {
			TTL int `json:"ttl"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if rest[1] == "TXT" {
			h.txtTTL[rest[0]] = body.TTL
		} else {
			for i, rec := range h.fake.records {
				if rec.name == name(rest[0]) && rec.rrType == rest[1] {
					h.fake.records[i].ttl = body.TTL
				}
			}
			h.fake.writes++
		}
		writeJSON(w, h.action())
	default:
		h.t.Errorf("unexpected %s %s", r.Method, r.URL)
		w.WriteHeader(http.StatusBadRequest)
	}
}

func hetznerService(t *testing.T, server *httptest.Server, ttl time.Duration) *Hetzner {
	t.Helper()
	service, err := NewHetzner(json.RawMessage(`{"api_token": "secret", "zone": "Example.com."}`))
	if err != nil {
		t.Fatal(err)
	}
	h := service.(*Hetzner)
	h.apiBaseURL, h.poll, h.TTL.Duration = server.URL, time.Millisecond, ttl
	return h
}

// The scenario every provider runs, after a request refused as too many: each change waited for.
func TestHetznerUpdate(t *testing.T) {
	fake := newFakeDNS(t, "nas.example.com", "other.example.com")
	api, server := startHetznerFake(t, fake)
	api.throttle = true
	service := hetznerService(t, server, 10*time.Minute)
	fake.check(func(addrs *ipv6disc.AddrCollection) error { return service.Update("nas", addrs) }, "nas.example.com", "other.example.com")
	// The records of the first update, which check leaves: of the settings' TTL.
	for _, rec := range fake.of("nas.example.com") {
		if rec.ttl != 600 {
			t.Errorf("record %s: ttl %d, want 600", rec.ip, rec.ttl)
		}
	}
}

// A TTL in the settings is set on a set that has another; without one, the set's stays, and a new
// one has the zone's.
func TestHetznerTTL(t *testing.T) {
	fake := newFakeDNS(t, "nas.example.com", "other.example.com")
	_, server := startHetznerFake(t, fake)
	service := hetznerService(t, server, 0)
	if err := service.Update("nas", collectionWith(wantedIP, newIPv4)); err != nil {
		t.Fatal(err)
	}
	for _, rec := range fake.addresses("nas.example.com") {
		if want := map[string]int{"AAAA": 300, "A": 0}[rec.rrType]; rec.ttl != want {
			t.Errorf("without a TTL: %s of %d, want %d", rec.rrType, rec.ttl, want)
		}
	}
	service.TTL.Duration = 10 * time.Minute
	if err := service.Update("nas", collectionWith(wantedIP, newIPv4)); err != nil {
		t.Fatal(err)
	}
	for _, rec := range fake.addresses("nas.example.com") {
		if rec.ttl != 600 {
			t.Errorf("with a TTL: %s of %d, want 600", rec.rrType, rec.ttl)
		}
	}
}

// The zone's own name, which the API calls @.
func TestHetznerZoneItself(t *testing.T) {
	fake := newFakeDNS(t, "nas.example.com", "other.example.com")
	_, server := startHetznerFake(t, fake)
	service := hetznerService(t, server, 0)
	if err := service.Update("example.com.", collectionWith(newIPv4)); err != nil {
		t.Fatal(err)
	}
	if got := fake.addresses("example.com"); len(got) != 1 || got[0].ip != newIPv4 {
		t.Errorf("the zone: %v", got)
	}
}

// What Hetzner refuses, said: the token, a zone not of the project, and a change whose action
// fails.
func TestHetznerRefused(t *testing.T) {
	fake := newFakeDNS(t, "nas.example.com", "other.example.com")
	api, server := startHetznerFake(t, fake)
	service := hetznerService(t, server, 0)
	service.APIToken = "wrong"
	if err := service.Update("nas", desired()); err == nil || !strings.Contains(err.Error(), "HTTP 401: the token is refused") || !strings.Contains(err.Error(), "unauthorized: unable to authenticate") {
		t.Errorf("a wrong token: %v", err)
	}
	other := hetznerService(t, server, 0)
	other.Zone = "example.net"
	if err := other.Update("nas", desired()); err == nil || !strings.Contains(err.Error(), "the zone example.net isn't one of the project's") {
		t.Errorf("another zone: %v", err)
	}
	service.APIToken = "secret"
	api.mutex.Lock()
	api.ends = "error"
	api.mutex.Unlock()
	if err := service.Update("nas", desired()); err == nil || !strings.Contains(err.Error(), "the change failed: action_failed: the zone is locked") {
		t.Errorf("an action that fails: %v", err)
	}
}

// TXT records set, set again to others, and removed: the name's addresses stay, and the TTL is
// the challenge's.
func TestHetznerSetTXT(t *testing.T) {
	fake := newFakeDNS(t, "nas.example.com", "other.example.com")
	api, server := startHetznerFake(t, fake)
	service := hetznerService(t, server, 0)
	for _, values := range [][]string{{"one"}, {"one", "two"}, nil} {
		if err := service.SetTXT("_acme-challenge.nas", values); err != nil {
			t.Fatal(err)
		}
		var want []string
		for _, v := range values {
			want = append(want, quoteTXT(v))
		}
		got := slices.Clone(api.txt["_acme-challenge.nas"])
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("TXT %q: got %q", values, got)
		}
		if len(values) > 0 && api.txtTTL["_acme-challenge.nas"] != txtTTL {
			t.Errorf("TXT %q: TTL %d", values, api.txtTTL["_acme-challenge.nas"])
		}
	}
	changes := api.changes
	if err := service.SetTXT("_acme-challenge.nas", nil); err != nil || api.changes != changes {
		t.Errorf("the same again: %v, %d changes", err, api.changes-changes)
	}
	if got := fake.addresses("nas.example.com"); len(got) != 2 {
		t.Errorf("the addresses of nas: %v", got)
	}
}
