package ddns

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// The providers that keep TXT records, as the DNS challenge of ACME needs.
var (
	_ TXTWriter = (*RFC2136)(nil)
	_ TXTWriter = (*Cloudflare)(nil)
	_ TXTWriter = (*Route53)(nil)
	_ TXTWriter = (*DuckDNS)(nil)
	_ TXTWriter = (*DeSEC)(nil)
	_ TXTWriter = (*Hetzner)(nil)
	_ TXTWriter = (*Porkbun)(nil)
	_ TXTWriter = (*DigitalOcean)(nil)
	_ TXTWriter = (*Gandi)(nil)
	_ TXTWriter = (*OVH)(nil)
)

// The providers registered as TXT writers are those whose services are, and no other: of each
// provider's type, with the schema test's list of them.
func TestTXTProvidersRegistered(t *testing.T) {
	for name, v := range providerTypes() {
		_, writes := reflect.New(reflect.TypeOf(v)).Interface().(TXTWriter)
		if writes != WritesTXT(name) {
			t.Errorf("%s: a TXTWriter %v, registered as one %v", name, writes, WritesTXT(name))
		}
	}
	if got := TXTProviders(); got != "cloudflare, desec, digitalocean, duckdns, gandi, hetzner, ovh, porkbun, rfc2136 or route53" {
		t.Errorf("listed as %q", got)
	}
}

// TXT records set, set again to others, and removed: the name's other records stay, as do another
// name's TXT records.
func TestRFC2136SetTXT(t *testing.T) {
	fake := &fakeRFC2136{t: t, records: []string{
		"_acme-challenge.nas.example.com.\t60\tIN\tTXT\t\"old\"",
		"nas.example.com.\t300\tIN\tAAAA\t" + wantedIP,
		"_acme-challenge.other.example.com.\t60\tIN\tTXT\t\"theirs\"",
	}}
	service := &RFC2136{Server: startFakeRFC2136(t, fake, nil), Zone: "example.com"}
	txt := func() []string { return fake.of("_acme-challenge.nas.example.com.") }

	if err := service.SetTXT("_acme-challenge.nas", []string{"b", "a"}); err != nil {
		t.Fatal(err)
	}
	want := []string{"_acme-challenge.nas.example.com.\t60\tIN\tTXT\t\"a\"", "_acme-challenge.nas.example.com.\t60\tIN\tTXT\t\"b\""}
	if got := txt(); !slices.Equal(got, want) {
		t.Errorf("TXT records: %q", got)
	}
	if err := service.SetTXT("_acme-challenge.nas.example.com.", nil); err != nil {
		t.Fatal(err)
	}
	if got := txt(); len(got) != 0 {
		t.Errorf("after removing: %q", got)
	}
	if len(fake.of("nas.example.com.")) != 1 || len(fake.of("_acme-challenge.other.example.com.")) != 1 {
		t.Errorf("the other records: %q", fake.records)
	}
}

// Cloudflare's TXT records: a value already there stays, in quotes or not; the others go, and the
// missing ones come, with a short TTL.
func TestCloudflareSetTXT(t *testing.T) {
	type rec struct{ ID, Type, Name, Content string }
	records := []rec{
		{"1", "TXT", "_acme-challenge.nas.example.com", `"keep"`},
		{"2", "TXT", "_acme-challenge.nas.example.com", "stale"},
		{"3", "AAAA", "_acme-challenge.nas.example.com", wantedIP},
		{"4", "TXT", "other.example.com", "theirs"},
	}
	next, ttls := 10, []int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const path = "/zones/z1/dns_records"
		var result any
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			result = []map[string]string{{"id": "z1", "name": "example.com"}}
		case r.Method == http.MethodGet && r.URL.Path == path:
			q := r.URL.Query()
			list := []rec{}
			for _, x := range records {
				if x.Name == q.Get("name") && (q.Get("type") == "" || x.Type == q.Get("type")) {
					list = append(list, x)
				}
			}
			result = list
		case r.Method == http.MethodPost && r.URL.Path == path:
			var body struct {
				Type, Name, Content string
				TTL                 int
			}
			json.NewDecoder(r.Body).Decode(&body)
			next++
			x := rec{ID: strings.Repeat("n", next), Type: body.Type, Name: body.Name, Content: body.Content}
			records = append(records, x)
			ttls = append(ttls, body.TTL)
			result = x
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, path+"/"):
			id := strings.TrimPrefix(r.URL.Path, path+"/")
			records = slices.DeleteFunc(records, func(x rec) bool { return x.ID == id })
			result = map[string]string{"id": id}
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
		}
		writeJSON(w, map[string]any{"success": true, "result": result, "result_info": map[string]int{"page": 1, "per_page": 100, "total_pages": 1, "count": 1, "total_count": 1}})
	}))
	defer server.Close()
	service := &Cloudflare{APIToken: "token", Zone: "example.com", apiBaseURL: server.URL}

	if err := service.SetTXT("_acme-challenge.nas", []string{"keep", "new"}); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, x := range records {
		got = append(got, x.ID+" "+x.Type+" "+x.Name+" "+x.Content)
	}
	want := []string{
		`1 TXT _acme-challenge.nas.example.com "keep"`,
		"3 AAAA _acme-challenge.nas.example.com " + wantedIP,
		"4 TXT other.example.com theirs",
		strings.Repeat("n", 11) + " TXT _acme-challenge.nas.example.com new",
	}
	if !slices.Equal(got, want) || !slices.Equal(ttls, []int{txtTTL}) {
		t.Errorf("records:\n%s\nwant\n%s\nTTLs %v", strings.Join(got, "\n"), strings.Join(want, "\n"), ttls)
	}
	if err := service.SetTXT("_acme-challenge.nas.example.com", nil); err != nil {
		t.Fatal(err)
	}
	if n := len(records); n != 2 {
		t.Errorf("after removing, %d records: %v", n, records)
	}
}

// Route 53's TXT record set, quoted, upserted, waited for, and deleted as it is.
func TestRoute53SetTXT(t *testing.T) {
	fake := &fakeRoute53{t: t, sets: map[string]route53RecordSet{}}
	fake.put(recordSet("nas.example.com.", "AAAA", 300, wantedIP))
	server := httptest.NewServer(fake)
	defer server.Close()
	service := &Route53{AccessKeyID: "a", SecretAccessKey: "s", Region: "us-east-1", HostedZoneID: "Z1", endpoint: server.URL}

	if err := service.SetTXT("_acme-challenge.nas", []string{"a", "b"}); err != nil {
		t.Fatal(err)
	}
	set, ok := fake.sets[fake.key("_acme-challenge.nas.example.com.", "TXT")]
	if !ok || set.TTL != txtTTL || !slices.Equal(set.values(), []string{`"a"`, `"b"`}) {
		t.Errorf("the TXT set: %+v", set)
	}
	if err := service.SetTXT("_acme-challenge.nas.example.com", nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := fake.sets[fake.key("_acme-challenge.nas.example.com.", "TXT")]; ok {
		t.Error("the TXT set stays")
	}
	if err := service.SetTXT("_acme-challenge.nas", nil); err != nil {
		t.Errorf("removing what isn't there: %v", err)
	}
	if _, ok := fake.sets[fake.key("nas.example.com.", "AAAA")]; !ok {
		t.Error("the name's AAAA set is gone")
	}
}

// DuckDNS's one TXT record of a name, of _acme-challenge under it too: set, and cleared; and two
// values are refused, as DuckDNS keeps one.
func TestDuckDNSSetTXT(t *testing.T) {
	fake := &fakeDuckDNS{ipv4: "192.0.2.1"}
	server := httptest.NewServer(fake)
	defer server.Close()
	service := &DuckDNS{APIToken: duckToken, updateURL: server.URL}

	if err := service.SetTXT("_acme-challenge.nas.duckdns.org", []string{"token"}); err != nil {
		t.Fatal(err)
	}
	if fake.txt != "token" || fake.ipv4 != "192.0.2.1" {
		t.Errorf("TXT %q, address %q", fake.txt, fake.ipv4)
	}
	if err := service.SetTXT("_acme-challenge.nas", nil); err != nil {
		t.Fatal(err)
	}
	if fake.txt != "" || fake.ipv4 != "192.0.2.1" {
		t.Errorf("after clearing: TXT %q, address %q", fake.txt, fake.ipv4)
	}
	if err := service.SetTXT("nas", []string{"a", "b"}); err == nil || !strings.Contains(err.Error(), "one TXT record") {
		t.Errorf("two values: %v", err)
	}
}
