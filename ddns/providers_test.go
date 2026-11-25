package ddns

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
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
	// Disabled at the provider: not answered, and ipv6ddns's to leave alone.
	disabled bool
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

// addresses are the A and AAAA records of name: the ones of a provider.
func (f *fakeDNS) addresses(name string) []record {
	return slices.DeleteFunc(f.of(name), func(r record) bool { return r.rrType != "A" && r.rrType != "AAAA" })
}

// check runs the update twice: the records must be the desired ones after the first, and the
// second must change nothing. Then it runs one without addresses, which leaves the name without
// A and AAAA records, and the other name with its own.
func (f *fakeDNS) check(update func(*ipv6disc.AddrCollection) error, name, otherName string) {
	f.t.Helper()
	if err := update(desired()); err != nil {
		f.t.Fatalf("update: %v", err)
	}

	f.mutex.Lock()
	var got []string
	for _, r := range f.addresses(name) {
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
	// The records as the provider left them, for the caller to look at after.
	records := slices.Clone(f.records)
	f.mutex.Unlock()

	if err := update(desired()); err != nil {
		f.t.Fatalf("second update: %v", err)
	}
	f.mutex.Lock()
	if f.writes != writes {
		f.t.Errorf("the second update made %d changes, want none", f.writes-writes)
	}
	f.mutex.Unlock()

	if err := update(ipv6disc.NewAddrCollection()); err != nil {
		f.t.Fatalf("update without addresses: %v", err)
	}
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if left := f.addresses(name); len(left) != 0 {
		f.t.Errorf("without addresses, %s keeps %v", name, left)
	}
	if other := f.of(otherName); len(other) != 1 {
		f.t.Errorf("without addresses for %s, the records of %s: got %v, want its one record", name, otherName, other)
	}
	f.records = records
}

// disabledIP is the address of a disabled record that the name no longer has.
const disabledIP = "2001:db8::bad"

// checkDisabled runs the update with the desired addresses, then with none, on a name with two
// disabled records: one of an address it no longer has, and one of an address it has. A disabled
// record is the provider's: both stay as they are, disabled and of their TTL, and no record is
// added beside the one of the address it has, which so stays unanswered.
func (f *fakeDNS) checkDisabled(update func(*ipv6disc.AddrCollection) error, name string) {
	f.t.Helper()
	f.mutex.Lock()
	// The address of the disabled record wanted has that record alone.
	f.records = slices.DeleteFunc(f.records, func(r record) bool { return r.name == name && sameIP(r.ip, newIP) })
	var disabled []string
	for _, ip := range []string{disabledIP, newIP} {
		r := f.add(name, "AAAA", ip, 300)
		f.records[len(f.records)-1].disabled = true
		disabled = append(disabled, r.id)
	}
	f.mutex.Unlock()

	for i, addrs := range []*ipv6disc.AddrCollection{desired(), ipv6disc.NewAddrCollection()} {
		if err := update(addrs); err != nil {
			f.t.Fatalf("update %d: %v", i+1, err)
		}
		f.mutex.Lock()
		for _, id := range disabled {
			j := slices.IndexFunc(f.records, func(r record) bool { return r.id == id })
			if j < 0 || !f.records[j].disabled || f.records[j].ttl != 300 {
				f.t.Errorf("update %d: the disabled record %s was changed or removed: %v", i+1, id, f.records)
			}
		}
		var withNewIP, enabled []string
		for _, r := range f.addresses(name) {
			if sameIP(r.ip, newIP) {
				withNewIP = append(withNewIP, r.id)
			}
			if !r.disabled {
				ip, _ := canonicalIP(r.ip)
				enabled = append(enabled, r.rrType+" "+ip)
			}
		}
		if len(withNewIP) != 1 {
			f.t.Errorf("update %d: the address of the disabled record has %d records, want that one alone: %v", i+1, len(withNewIP), f.records)
		}
		slices.Sort(enabled)
		want := []string{"A " + newIPv4, "AAAA " + wantedIP}
		if i == 1 {
			want = nil
		}
		if !slices.Equal(enabled, want) {
			f.t.Errorf("update %d: the records enabled are %v, want %v", i+1, enabled, want)
		}
		f.mutex.Unlock()
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

// technitiumFake serves fake as Technitium's records API: its records, disabled or not, and the
// add, update and delete of one.
func technitiumFake(t *testing.T, fake *fakeDNS) *httptest.Server {
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
				records = append(records, map[string]any{"type": rec.rrType, "ttl": rec.ttl, "disabled": rec.disabled, "rData": map[string]string{"ipAddress": rec.ip}})
			}
			writeJSON(w, map[string]any{"status": "ok", "response": map[string]any{"records": records}})
			return
		case "/api/zones/records/add":
			ttl, _ := strconv.Atoi(q.Get("ttl"))
			fake.add(domain, q.Get("type"), q.Get("ipAddress"), ttl)
			// Technitium enables the disabled records of the type of one added.
			for i, rec := range fake.records {
				if rec.name == domain && rec.rrType == q.Get("type") {
					fake.records[i].disabled = false
				}
			}
		case "/api/zones/records/update":
			ttl, _ := strconv.Atoi(q.Get("ttl"))
			if q.Get("newIpAddress") != q.Get("ipAddress") {
				t.Errorf("an update moves the record to another address: %s", r.URL.RawQuery)
			}
			for i, rec := range fake.records {
				if rec.name == domain && rec.rrType == q.Get("type") && sameIP(rec.ip, q.Get("ipAddress")) {
					fake.records[i].ttl = ttl
					if q.Get("disable") == "false" {
						fake.records[i].disabled = false
					}
				}
			}
			fake.writes++
		case "/api/zones/records/delete":
			fake.deleteWhere(func(rec record) bool {
				return rec.name == domain && rec.rrType == q.Get("type") && sameIP(rec.ip, q.Get("ipAddress"))
			})
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
		writeJSON(w, map[string]any{"status": "ok"})
	}))
	t.Cleanup(server.Close)
	return server
}

func TestTechnitiumUpdate(t *testing.T) {
	fake := newFakeDNS(t, "nas.example.com", "other.example.com")
	server := technitiumFake(t, fake)
	service := &Technitium{Address: server.URL, Token: "secret", Zone: "example.com"}
	service.TTL.Duration = 10 * time.Minute
	fake.check(func(addrs *ipv6disc.AddrCollection) error { return service.Update("nas", addrs) }, "nas.example.com", "other.example.com")
	for _, rec := range fake.of("nas.example.com") {
		if rec.ttl != 600 {
			t.Errorf("record %s: ttl %d, want 600: of the one it had too", rec.ip, rec.ttl)
		}
	}
}

// At Technitium a disabled record is as any other, since Technitium enables it when a record of
// its type is added: one of an address the name has is enabled, even when nothing is added, and
// keeps its TTL without one in the settings; one of an address it no longer has is deleted.
func TestTechnitiumDisabled(t *testing.T) {
	fake := newFakeDNS(t, "nas.example.com", "other.example.com")
	server := technitiumFake(t, fake)
	fake.mutex.Lock()
	fake.records = slices.DeleteFunc(fake.records, func(r record) bool { return r.name == "nas.example.com" })
	fake.add("nas.example.com", "AAAA", wantedIP, 300)
	fake.add("nas.example.com", "AAAA", disabledIP, 300)
	for i := range fake.records {
		fake.records[i].disabled = fake.records[i].name == "nas.example.com"
	}
	fake.writes = 0
	fake.mutex.Unlock()
	service := &Technitium{Address: server.URL, Token: "secret", Zone: "example.com"}
	if err := service.Update("nas", collectionWith(wantedIP)); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, rec := range fake.of("nas.example.com") {
		got = append(got, fmt.Sprintf("%s %s %d disabled=%v", rec.rrType, rec.ip, rec.ttl, rec.disabled))
	}
	if want := []string{"AAAA " + wantedIP + " 300 disabled=false"}; !slices.Equal(got, want) {
		t.Errorf("the records: %v, want %v", got, want)
	}
}

// An answer that is none of the API's tells its HTTP status, and one that refuses its status: never
// the token, which is in the URL.
func TestTechnitiumErrors(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		want       []string
	}{
		{"not the API", "<html>Bad Gateway</html>", http.StatusBadGateway, []string{"HTTP 502 Bad Gateway", "not an answer of Technitium's API"}},
		{"refused", `{"status":"invalid-token","errorMessage":"Invalid token or session expired."}`, http.StatusOK, []string{`"invalid-token"`, "Invalid token or session expired."}},
		{"refused without a message", `{"status":"error"}`, http.StatusOK, []string{`API status "error", HTTP 200 OK`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			}))
			defer server.Close()

			service := &Technitium{Address: server.URL, Token: "secret-token", Zone: "example.com"}
			addrs := ipv6disc.NewAddrCollection()
			addrs.Add(ipv6disc.NewAddr(nil, netip.MustParseAddr(wantedIP), "test", time.Hour, nil))
			err := service.Update("nas", addrs)
			if err == nil {
				t.Fatal("no error")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q, without %q", err, want)
				}
			}
			if strings.Contains(err.Error(), "secret-token") {
				t.Errorf("error %q has the token", err)
			}
		})
	}
}

func TestOpnsenseUnboundUpdate(t *testing.T) {
	fake := newFakeDNS(t, "nas.lan", "other.lan")
	fake.add("nas.lan", "AAAA", wantedIP, 300) // a duplicate
	fake.add("nas.lan", "MX", "mail.lan", 300) // not a record of the provider's
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
				row := map[string]string{"uuid": rec.id, "enabled": "1", "hostname": host, "domain": domain, "server": rec.ip, "ttl": strconv.Itoa(rec.ttl)}
				if rec.disabled {
					row["enabled"] = "0"
				}
				// The type as OPNsense tells it: its description up to 25.1, and since the
				// type, with the description apart. Some rows of each.
				description := map[string]string{"A": "A (IPv4 address)", "AAAA": "AAAA (IPv6 address)", "MX": "MX (Mail server)"}[rec.rrType]
				if id, _ := strconv.Atoi(rec.id); id%2 == 0 {
					row["rr"] = description
				} else {
					row["rr"], row["%rr"] = rec.rrType, description
				}
				rows = append(rows, row)
			}
			writeJSON(w, map[string]any{"rows": rows})
		case r.URL.Path == "/api/unbound/settings/addHostOverride":
			var body struct{ Host map[string]string }
			json.NewDecoder(r.Body).Decode(&body)
			ttl, _ := strconv.Atoi(body.Host["ttl"])
			fake.add(body.Host["hostname"]+"."+body.Host["domain"], body.Host["rr"], body.Host["server"], ttl)
			writeJSON(w, map[string]string{"result": "saved"})
		case strings.HasPrefix(r.URL.Path, "/api/unbound/settings/setHostOverride/"):
			id := strings.TrimPrefix(r.URL.Path, "/api/unbound/settings/setHostOverride/")
			var body struct{ Host map[string]string }
			json.NewDecoder(r.Body).Decode(&body)
			for i, rec := range fake.records {
				if rec.id == id {
					if rec.name != body.Host["hostname"]+"."+body.Host["domain"] || !sameIP(rec.ip, body.Host["server"]) {
						t.Errorf("override %s set to another name or address: %v", id, body.Host)
					}
					fake.records[i].ttl, _ = strconv.Atoi(body.Host["ttl"])
				}
			}
			fake.writes++
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
	service.TTL.Duration = 10 * time.Minute
	fake.check(func(addrs *ipv6disc.AddrCollection) error { return service.Update("nas", addrs) }, "nas.lan", "other.lan")
	for _, rec := range fake.addresses("nas.lan") {
		if rec.ttl != 600 {
			t.Errorf("record %s: ttl %d, want 600: of the one it had too", rec.ip, rec.ttl)
		}
	}
	if len(fake.of("nas.lan")) != 4 {
		t.Errorf("the MX override of the name is gone: %v", fake.records)
	}
	if reconfigures != 2 {
		t.Errorf("got %d reconfigures, want 2, one for each update that changes something: none when nothing changes", reconfigures)
	}
	fake.checkDisabled(func(addrs *ipv6disc.AddrCollection) error { return service.Update("nas", addrs) }, "nas.lan")
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

// The ID of a pfSense override is its position in the list. Two names of a pfSense that lose their
// addresses at once, each read before the other deletes: the second would delete what moved to
// its position, the override of another name.
func TestPfsenseRestapiUnboundConcurrentDeletes(t *testing.T) {
	type override struct {
		ID     int      `json:"id"`
		Host   string   `json:"host"`
		Domain string   `json:"domain"`
		IP     []string `json:"ip"`
	}
	var mutex sync.Mutex
	hosts := []string{"first", "a", "b", "last"}
	reads := 0
	// A read waits for the other update's, for a while: both are made before either deletes,
	// unless one waits for the other to end.
	secondRead := make(chan struct{})
	deletes := 0
	firstDelete := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v2/services/dns_resolver/host_overrides":
			mutex.Lock()
			var overrides []override
			for i, host := range hosts {
				overrides = append(overrides, override{i, host, "lan", []string{obsoleteIP}})
			}
			reads++
			if reads == 2 {
				close(secondRead)
			}
			mutex.Unlock()
			select {
			case <-secondRead:
			case <-time.After(200 * time.Millisecond):
			}
			writeJSON(w, map[string]any{"status": "ok", "code": 200, "data": overrides})
			return
		case "DELETE /api/v2/services/dns_resolver/host_override":
			id, _ := strconv.Atoi(r.URL.Query().Get("id"))
			// The delete of the one further in the list waits for the other, for a while: its
			// position is the one read before then.
			if id == 2 {
				select {
				case <-firstDelete:
				case <-time.After(200 * time.Millisecond):
				}
			}
			mutex.Lock()
			hosts = slices.Delete(hosts, id, id+1)
			deletes++
			if deletes == 1 {
				close(firstDelete)
			}
			mutex.Unlock()
		}
		writeJSON(w, map[string]any{"status": "ok", "code": 200})
	}))
	defer server.Close()

	// Two credentials of the same pfSense wait for each other too.
	var updates sync.WaitGroup
	for _, name := range []string{"a", "b"} {
		service := &PfsenseRestapiUnbound{Address: server.URL, Key: "key", Zone: "lan"}
		updates.Go(func() {
			if err := service.Update(name, collectionWith()); err != nil {
				t.Errorf("%s: %v", name, err)
			}
		})
	}
	updates.Wait()
	if want := []string{"first", "last"}; !slices.Equal(hosts, want) {
		t.Errorf("got the overrides of %v, want those of %v", hosts, want)
	}
}

// gravityFake serves the records API of Gravity from fake, whose record names are those within
// the zone. As Gravity, it lists the records of the whole zone without a hostname, and needs one,
// and since v0.32 a TTL, to put a record: one with the uid of another replaces it. And as Gravity
// 0.34, which tools/live-providers.sh runs, it puts a record under its name in lower case, and
// lists those of the name in the case asked.
func gravityFake(t *testing.T, fake *fakeDNS, tellsTTL bool) *httptest.Server {
	server := httptest.NewServer(gravityHandler(t, fake, tellsTTL))
	t.Cleanup(server.Close)
	return server
}

func gravityHandler(t *testing.T, fake *fakeDNS, tellsTTL bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fake.mutex.Lock()
		defer fake.mutex.Unlock()
		q := r.URL.Query()
		if r.Header.Get("Authorization") != "Bearer key" || q.Get("zone") != "example.com." || r.URL.Path != "/api/v1/dns/zones/records" {
			t.Errorf("request %s %s", r.Method, r.URL)
		}
		hostname := q.Get("hostname")
		if r.Method != http.MethodGet && hostname == "" {
			t.Errorf("%s without a hostname", r.Method)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodGet:
			records := []map[string]any{}
			for _, rec := range fake.records {
				if hostname != "" && rec.name != hostname {
					continue
				}
				row := map[string]any{"uid": rec.id, "hostname": rec.name, "type": rec.rrType, "data": rec.ip}
				if tellsTTL {
					row["ttl"] = rec.ttl
				}
				records = append(records, row)
			}
			writeJSON(w, map[string]any{"records": records})
			return
		case http.MethodPost: // the client's "put"
			var body struct {
				Type, Data string
				TTL        *int
			}
			json.NewDecoder(r.Body).Decode(&body)
			if body.TTL == nil || *body.TTL <= 0 {
				t.Errorf("put of %s without a TTL", body.Data)
				w.WriteHeader(http.StatusUnprocessableEntity)
				return
			}
			replaced := false
			hostname = strings.ToLower(hostname)
			for i := range fake.records {
				if fake.records[i].id == q.Get("uid") && fake.records[i].name == hostname {
					fake.records[i].ttl = *body.TTL
					fake.writes++
					replaced = true
				}
			}
			if !replaced {
				fake.add(hostname, body.Type, body.Data, *body.TTL)
			}
		case http.MethodDelete:
			fake.deleteWhere(func(rec record) bool {
				return rec.id == q.Get("uid") && rec.name == hostname && rec.rrType == q.Get("type")
			})
		}
		writeJSON(w, map[string]any{})
	})
}

func TestGravityUpdate(t *testing.T) {
	for hostname, name := range map[string]string{
		"nas": "nas",
		// The zone itself is @, and a name given with its zone is the same name.
		"": "@", "example.com": "@", "nas.example.com.": "nas",
		// And in another case too: Gravity has it in lower case.
		"NAS": "nas", "Nas.Example.COM": "nas",
	} {
		fake := newFakeDNS(t, name, "other")
		fake.add(name, "MX", "mail.example.com.", 300)
		// A duplicate, of an address wanted: the address has one record, as each other.
		fake.add(name, "AAAA", wantedIP, 600)
		fake.writes = 0
		server := gravityFake(t, fake, true)

		service := &Gravity{Server: server.URL, APIKey: "key", Zone: "example.com."}
		service.TTL.Duration = 10 * time.Minute
		fake.check(func(addrs *ipv6disc.AddrCollection) error { return service.Update(hostname, addrs) }, name, "other")
		for _, rec := range fake.addresses(name) {
			if rec.ttl != 600 {
				t.Errorf("%q: record %s: ttl %d, want 600: of the one it had too", hostname, rec.ip, rec.ttl)
			}
		}
		if len(fake.of(name)) != 4 {
			t.Errorf("%q: the MX record of the name is gone: %v", hostname, fake.records)
		}
	}
}

// A listing with the records of other names, which a Gravity gives for the whole zone, is not the
// name's: they are neither counted as its own nor deleted.
func TestGravityRecordsOfOtherNames(t *testing.T) {
	fake := newFakeDNS(t, "nas", "other")
	fake.add("other", "AAAA", newIP, 300)
	fake.writes = 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The whole zone, whatever the name asked.
		q := r.URL.Query()
		q.Del("hostname")
		if r.Method != http.MethodGet {
			q.Set("hostname", r.URL.Query().Get("hostname"))
		}
		r.URL.RawQuery = q.Encode()
		gravityHandler(t, fake, true).ServeHTTP(w, r)
	}))
	defer server.Close()

	service := &Gravity{Server: server.URL, APIKey: "key", Zone: "example.com."}
	service.TTL.Duration = 5 * time.Minute
	if err := service.Update("nas", desired()); err != nil {
		t.Fatal(err)
	}
	if got := len(fake.of("nas")); got != 3 {
		t.Errorf("nas: got %d records, want 3: %v", got, fake.records)
	}
	if got := len(fake.of("other")); got != 2 {
		t.Errorf("other: got %d records, want its 2: %v", got, fake.records)
	}
}

// A Gravity before v0.32 tells no TTL: there is none to fix, update after update.
func TestGravityWithoutTTL(t *testing.T) {
	fake := newFakeDNS(t, "nas", "other")
	server := gravityFake(t, fake, false)
	service := &Gravity{Server: server.URL, APIKey: "key", Zone: "example.com."}
	fake.check(func(addrs *ipv6disc.AddrCollection) error { return service.Update("nas", addrs) }, "nas", "other")
	for _, rec := range fake.of("nas") {
		if ip, _ := canonicalIP(rec.ip); ip != wantedIP && rec.ttl != 300 {
			t.Errorf("record %s: ttl %d, want the default, 300", rec.ip, rec.ttl)
		}
	}
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
	fake.check(func(addrs *ipv6disc.AddrCollection) error { return service.Update("nas", addrs) }, "nas.example.com", "other.example.com")
	for _, rec := range fake.of("nas.example.com") {
		if rec.ttl != 300 {
			t.Errorf("record %s: ttl %d, want 300", rec.ip, rec.ttl)
		}
	}
}
