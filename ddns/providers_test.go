package ddns

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
)

// The scenario every provider runs: the name has the address wanted, in another form, and one not
// wanted any more; another name has a record that must stay.
const (
	wantedIP    = "2001:db8::1"
	wantedAsSet = "2001:0db8:0:0::1"
	obsoleteIP  = "2001:db8::dead"
	newIP       = "2001:db8::2"
	newIPv4     = "192.0.2.1"
)

func desired() *ipv6disc.AddrCollection {
	c := ipv6disc.NewAddrCollection()
	for _, ip := range []string{wantedIP, newIP, newIPv4} {
		c.Add(ipv6disc.NewAddr(nil, netip.MustParseAddr(ip), "test", time.Hour, nil))
	}
	return c
}

// record is a record of a fake DNS server.
type record struct {
	id, name, rrType, ip string
	ttl                  int
	proxied              bool
}

// fakeDNS is the record store of a fake provider API, counting the changes made to it.
type fakeDNS struct {
	t       *testing.T
	mutex   sync.Mutex
	records []record
	nextID  int
	writes  int
}

func newFakeDNS(t *testing.T, name, otherName string) *fakeDNS {
	f := &fakeDNS{t: t}
	f.add(name, "AAAA", wantedAsSet, 300)
	f.add(name, "AAAA", obsoleteIP, 300)
	f.add(otherName, "AAAA", obsoleteIP, 300)
	f.writes = 0
	return f
}

func (f *fakeDNS) add(name, rrType, ip string, ttl int) record {
	f.nextID++
	r := record{id: fmt.Sprint(f.nextID), name: name, rrType: strings.ToUpper(rrType), ip: ip, ttl: ttl}
	f.records = append(f.records, r)
	f.writes++
	return r
}

func (f *fakeDNS) deleteWhere(match func(record) bool) {
	n := len(f.records)
	f.records = slices.DeleteFunc(f.records, match)
	if len(f.records) == n {
		f.t.Errorf("delete of a record that isn't there")
	}
	f.writes++
}

func (f *fakeDNS) of(name string) []record {
	var result []record
	for _, r := range f.records {
		if r.name == name {
			result = append(result, r)
		}
	}
	return result
}

// check runs the update twice: the records must be the desired ones after the first, and the
// second must change nothing.
func (f *fakeDNS) check(update func() error, name, otherName string) {
	f.t.Helper()
	if err := update(); err != nil {
		f.t.Fatalf("update: %v", err)
	}

	f.mutex.Lock()
	var got []string
	for _, r := range f.of(name) {
		ip, _ := canonicalIP(r.ip)
		got = append(got, r.rrType+" "+ip)
	}
	slices.Sort(got)
	want := []string{"A " + newIPv4, "AAAA " + wantedIP, "AAAA " + newIP}
	if !slices.Equal(got, want) {
		f.t.Errorf("records of %s: got %v, want %v", name, got, want)
	}
	if other := f.of(otherName); len(other) != 1 {
		f.t.Errorf("records of %s: got %v, want its one record untouched", otherName, other)
	}
	writes := f.writes
	f.mutex.Unlock()

	if err := update(); err != nil {
		f.t.Fatalf("second update: %v", err)
	}
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if f.writes != writes {
		f.t.Errorf("the second update made %d changes, want none", f.writes-writes)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func sameIP(a, b string) bool {
	x, okX := canonicalIP(a)
	y, okY := canonicalIP(b)
	return okX && okY && x == y
}

func TestTechnitiumUpdate(t *testing.T) {
	fake := newFakeDNS(t, "nas.example.com", "other.example.com")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fake.mutex.Lock()
		defer fake.mutex.Unlock()
		q := r.URL.Query()
		if q.Get("token") != "secret" || q.Get("zone") != "example.com" {
			t.Errorf("request %s", r.URL)
		}
		domain := q.Get("domain")
		switch r.URL.Path {
		case "/api/zones/records/get":
			var records []map[string]any
			for _, rec := range fake.of(domain) {
				records = append(records, map[string]any{"type": rec.rrType, "ttl": rec.ttl, "rData": map[string]string{"ipAddress": rec.ip}})
			}
			writeJSON(w, map[string]any{"status": "ok", "response": map[string]any{"records": records}})
			return
		case "/api/zones/records/add":
			fake.add(domain, q.Get("type"), q.Get("ipAddress"), 0)
		case "/api/zones/records/delete":
			fake.deleteWhere(func(rec record) bool {
				return rec.name == domain && rec.rrType == q.Get("type") && sameIP(rec.ip, q.Get("ipAddress"))
			})
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
		writeJSON(w, map[string]any{"status": "ok"})
	}))
	defer server.Close()

	service := &Technitium{Address: server.URL, Token: "secret", Zone: "example.com"}
	fake.check(func() error { return service.Update("nas", desired()) }, "nas.example.com", "other.example.com")
}

func TestOpnsenseUnboundUpdate(t *testing.T) {
	fake := newFakeDNS(t, "nas.lan", "other.lan")
	fake.add("nas.lan", "AAAA", wantedIP, 0) // a duplicate
	fake.writes = 0
	reconfigures := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fake.mutex.Lock()
		defer fake.mutex.Unlock()
		if user, pass, _ := r.BasicAuth(); user != "key" || pass != "secret" {
			t.Errorf("credentials %s:%s", user, pass)
		}
		switch {
		case r.URL.Path == "/api/unbound/settings/searchHostOverride":
			var rows []map[string]string
			for _, rec := range fake.records {
				host, domain := SplitFQDN(rec.name)
				rows = append(rows, map[string]string{"uuid": rec.id, "hostname": host, "domain": domain, "rr": strings.ToLower(rec.rrType), "server": rec.ip})
			}
			writeJSON(w, map[string]any{"rows": rows})
		case r.URL.Path == "/api/unbound/settings/addHostOverride":
			var body struct{ Host map[string]string }
			json.NewDecoder(r.Body).Decode(&body)
			fake.add(body.Host["hostname"]+"."+body.Host["domain"], body.Host["rr"], body.Host["server"], 0)
			writeJSON(w, map[string]string{"result": "saved"})
		case strings.HasPrefix(r.URL.Path, "/api/unbound/settings/delHostOverride/"):
			id := strings.TrimPrefix(r.URL.Path, "/api/unbound/settings/delHostOverride/")
			fake.deleteWhere(func(rec record) bool { return rec.id == id })
			writeJSON(w, map[string]string{"result": "deleted"})
		case r.URL.Path == "/api/unbound/service/reconfigure":
			reconfigures++
			writeJSON(w, map[string]string{"status": "ok"})
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
	}))
	defer server.Close()

	service := &OpnsenseUnbound{Address: server.URL + "/", Key: "key", Secret: "secret", Zone: "lan"}
	fake.check(func() error { return service.Update("nas", desired()) }, "nas.lan", "other.lan")
	if reconfigures != 1 {
		t.Errorf("got %d reconfigures, want 1: none when nothing changes", reconfigures)
	}
}

func TestPfsenseRestapiUnboundUpdate(t *testing.T) {
	// pfSense keeps one override per name, with all its addresses.
	type override struct {
		ID     int      `json:"id"`
		Host   string   `json:"host"`
		Domain string   `json:"domain"`
		IP     []string `json:"ip"`
	}
	var mutex sync.Mutex
	overrides := []override{{0, "nas", "lan", []string{wantedAsSet, obsoleteIP}}, {1, "other", "lan", []string{obsoleteIP}}}
	writes, applies := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mutex.Lock()
		defer mutex.Unlock()
		if r.Header.Get("X-API-Key") != "key" {
			t.Errorf("no API key")
		}
		var body override
		json.NewDecoder(r.Body).Decode(&body)
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v2/services/dns_resolver/host_overrides":
			writeJSON(w, map[string]any{"status": "ok", "code": 200, "data": overrides})
			return
		case "POST /api/v2/services/dns_resolver/host_override":
			body.ID = len(overrides)
			overrides = append(overrides, body)
		case "PATCH /api/v2/services/dns_resolver/host_override":
			for i := range overrides {
				if overrides[i].ID == body.ID {
					overrides[i].IP = body.IP
				}
			}
		case "DELETE /api/v2/services/dns_resolver/host_override":
			t.Errorf("delete of an override that keeps addresses")
		case "POST /api/v2/services/dns_resolver/apply":
			applies++
			writeJSON(w, map[string]any{"status": "ok", "code": 200})
			return
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		writes++
		writeJSON(w, map[string]any{"status": "ok", "code": 200})
	}))
	defer server.Close()

	service := &PfsenseRestapiUnbound{Address: server.URL, Key: "key", Zone: "lan"}
	for range 2 {
		if err := service.Update("nas", desired()); err != nil {
			t.Fatal(err)
		}
	}
	mutex.Lock()
	defer mutex.Unlock()
	got := slices.Clone(overrides[0].IP)
	slices.Sort(got)
	if want := []string{newIPv4, wantedIP, newIP}; !slices.Equal(got, want) || len(overrides) != 2 || len(overrides[1].IP) != 1 {
		t.Errorf("got overrides %v, want nas with %v and other untouched", overrides, want)
	}
	if writes != 1 || applies != 1 {
		t.Errorf("got %d writes and %d applies, want one of each: none when nothing changes", writes, applies)
	}
}

func TestGravityUpdate(t *testing.T) {
	fake := newFakeDNS(t, "nas", "other")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fake.mutex.Lock()
		defer fake.mutex.Unlock()
		q := r.URL.Query()
		if r.Header.Get("Authorization") != "Bearer key" || q.Get("zone") != "example.com." || r.URL.Path != "/api/v1/dns/zones/records" {
			t.Errorf("request %s %s", r.Method, r.URL)
		}
		hostname := q.Get("hostname")
		switch r.Method {
		case http.MethodGet:
			records := []map[string]string{}
			for _, rec := range fake.of(hostname) {
				records = append(records, map[string]string{"uid": rec.id, "hostname": rec.name, "type": rec.rrType, "data": rec.ip})
			}
			writeJSON(w, map[string]any{"records": records})
			return
		case http.MethodPost: // the client's "put"
			var body struct{ Type, Data string }
			json.NewDecoder(r.Body).Decode(&body)
			fake.add(hostname, body.Type, body.Data, 0)
		case http.MethodDelete:
			fake.deleteWhere(func(rec record) bool { return rec.id == q.Get("uid") && rec.name == hostname })
		}
		writeJSON(w, map[string]any{})
	}))
	defer server.Close()

	service := &Gravity{Server: server.URL, APIKey: "key", Zone: "example.com."}
	fake.check(func() error { return service.Update("nas", desired()) }, "nas", "other")
}

func TestCloudflareUpdate(t *testing.T) {
	fake := newFakeDNS(t, "nas.example.com", "other.example.com")
	fake.add("nas.example.com", "AAAA", wantedIP, 300) // a duplicate
	fake.writes = 0
	cloudflareRecord := func(rec record) map[string]any {
		return map[string]any{"id": rec.id, "type": rec.rrType, "name": rec.name, "content": rec.ip, "ttl": rec.ttl, "proxied": rec.proxied}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fake.mutex.Lock()
		defer fake.mutex.Unlock()
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Errorf("no token")
		}
		const records = "/zones/z1/dns_records"
		var result any
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			result = []map[string]string{{"id": "z1", "name": "example.com"}}
		case r.Method == http.MethodGet && r.URL.Path == records:
			list := []map[string]any{}
			for _, rec := range fake.of(r.URL.Query().Get("name")) {
				list = append(list, cloudflareRecord(rec))
			}
			result = list
		case r.Method == http.MethodPost && r.URL.Path == records:
			var body struct {
				Type, Name, Content string
				TTL                 int
				Proxied             bool
			}
			json.NewDecoder(r.Body).Decode(&body)
			rec := fake.add(body.Name, body.Type, body.Content, body.TTL)
			result = cloudflareRecord(rec)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, records+"/"):
			id := strings.TrimPrefix(r.URL.Path, records+"/")
			fake.deleteWhere(func(rec record) bool { return rec.id == id })
			result = map[string]string{"id": id}
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, records+"/"):
			id := strings.TrimPrefix(r.URL.Path, records+"/")
			var body struct{ TTL int }
			json.NewDecoder(r.Body).Decode(&body)
			for i := range fake.records {
				if fake.records[i].id == id {
					fake.records[i].ttl = body.TTL
					result = cloudflareRecord(fake.records[i])
				}
			}
			fake.writes++
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
		}
		writeJSON(w, map[string]any{"success": true, "result": result, "result_info": map[string]int{"page": 1, "per_page": 100, "total_pages": 1, "count": 1, "total_count": 1}})
	}))
	defer server.Close()

	service := &Cloudflare{APIToken: "token", Zone: "example.com", apiBaseURL: server.URL}
	service.TTL.Duration = 5 * time.Minute
	fake.check(func() error { return service.Update("nas", desired()) }, "nas.example.com", "other.example.com")
	for _, rec := range fake.of("nas.example.com") {
		if rec.ttl != 300 {
			t.Errorf("record %s: ttl %d, want 300", rec.ip, rec.ttl)
		}
	}
}
