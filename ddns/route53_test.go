package ddns

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
)

type route53RecordSet struct {
	Name    string `xml:"Name"`
	Type    string `xml:"Type"`
	TTL     int64  `xml:"TTL"`
	Records []struct {
		Value string `xml:"Value"`
	} `xml:"ResourceRecords>ResourceRecord"`
}

func (rs route53RecordSet) values() []string {
	var values []string
	for _, r := range rs.Records {
		values = append(values, r.Value)
	}
	return values
}

func recordSet(name, rrType string, ttl int64, values ...string) route53RecordSet {
	rs := route53RecordSet{Name: name, Type: rrType, TTL: ttl}
	for _, v := range values {
		rs.Records = append(rs.Records, struct {
			Value string `xml:"Value"`
		}{v})
	}
	return rs
}

// fakeRoute53 keeps the record sets of hosted zone Z1, example.com., the way Route53 does: names in
// lower case, a wildcard as \052.
type fakeRoute53 struct {
	t       *testing.T
	mutex   sync.Mutex
	sets    map[string]route53RecordSet
	changes int
}

func (f *fakeRoute53) key(name, rrType string) string {
	return route53Name(name) + " " + rrType
}

func (f *fakeRoute53) put(rs route53RecordSet) {
	rs.Name = strings.ReplaceAll(route53Name(rs.Name), "*", `\052`)
	f.sets[f.key(rs.Name, rs.Type)] = rs
}

func (f *fakeRoute53) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	w.Header().Set("Content-Type", "text/xml")
	const zone = "/2013-04-01/hostedzone/Z1"
	path := strings.TrimSuffix(r.URL.Path, "/")
	switch {
	case r.Method == http.MethodGet && path == zone:
		w.Write([]byte(`<GetHostedZoneResponse><HostedZone><Id>/hostedzone/Z1</Id><Name>example.com.</Name><CallerReference>x</CallerReference></HostedZone></GetHostedZoneResponse>`))
	case r.Method == http.MethodGet && path == zone+"/rrset":
		start := route53Name(r.URL.Query().Get("name"))
		var sets []route53RecordSet
		for _, rs := range f.sets {
			if strings.ReplaceAll(rs.Name, `\052`, "*") >= start {
				sets = append(sets, rs)
			}
		}
		sort.Slice(sets, func(i, j int) bool { return sets[i].Name+sets[i].Type < sets[j].Name+sets[j].Type })
		body, _ := xml.Marshal(struct {
			XMLName     xml.Name           `xml:"ListResourceRecordSetsResponse"`
			Sets        []route53RecordSet `xml:"ResourceRecordSets>ResourceRecordSet"`
			IsTruncated bool               `xml:"IsTruncated"`
			MaxItems    int                `xml:"MaxItems"`
		}{Sets: sets, MaxItems: 10})
		w.Write(body)
	case r.Method == http.MethodPost && path == zone+"/rrset":
		var request struct {
			Changes []struct {
				Action string           `xml:"Action"`
				Set    route53RecordSet `xml:"ResourceRecordSet"`
			} `xml:"ChangeBatch>Changes>Change"`
		}
		if err := xml.NewDecoder(r.Body).Decode(&request); err != nil {
			f.t.Errorf("change request: %v", err)
		}
		f.changes++
		for _, change := range request.Changes {
			key := f.key(change.Set.Name, change.Set.Type)
			switch change.Action {
			case "UPSERT":
				f.put(change.Set)
			case "DELETE":
				// Route53 deletes only the set as it is.
				existing, ok := f.sets[key]
				if !ok || existing.TTL != change.Set.TTL || !slices.Equal(existing.values(), change.Set.values()) {
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte(`<ErrorResponse><Error><Type>Sender</Type><Code>InvalidChangeBatch</Code><Message>not found</Message></Error></ErrorResponse>`))
					return
				}
				delete(f.sets, key)
			default:
				f.t.Errorf("action %s", change.Action)
			}
		}
		w.Write([]byte(`<ChangeResourceRecordSetsResponse><ChangeInfo><Id>/change/C1</Id><Status>PENDING</Status><SubmittedAt>2026-01-01T00:00:00Z</SubmittedAt></ChangeInfo></ChangeResourceRecordSetsResponse>`))
	default:
		f.t.Errorf("unexpected %s %s", r.Method, r.URL)
		w.WriteHeader(http.StatusNotFound)
	}
}

func collectionWith(ips ...string) *ipv6disc.AddrCollection {
	c := ipv6disc.NewAddrCollection()
	for _, ip := range ips {
		c.Add(ipv6disc.NewAddr(nil, netip.MustParseAddr(ip), "test", time.Hour, nil))
	}
	return c
}

func TestRoute53Update(t *testing.T) {
	for _, hostname := range []string{"nas", "*.nas"} {
		fake := &fakeRoute53{t: t, sets: map[string]route53RecordSet{}}
		name := hostname + ".example.com."
		fake.put(recordSet(name, "AAAA", 300, wantedAsSet, obsoleteIP))
		fake.put(recordSet("other.example.com.", "AAAA", 300, obsoleteIP))
		server := httptest.NewServer(fake)

		service := &Route53{AccessKeyID: "a", SecretAccessKey: "s", Region: "us-east-1", HostedZoneID: "Z1", endpoint: server.URL}
		service.TTL.Duration = 5 * time.Minute
		update := func(c *ipv6disc.AddrCollection) {
			t.Helper()
			if err := service.Update(hostname, c); err != nil {
				t.Fatalf("%s: %v", hostname, err)
			}
		}

		update(desired())
		got := map[string][]string{}
		for _, rs := range fake.sets {
			if route53Name(rs.Name) == route53Name(name) {
				values := rs.values()
				slices.Sort(values)
				got[rs.Type] = values
			}
		}
		if want := (map[string][]string{"A": {newIPv4}, "AAAA": {wantedIP, newIP}}); !equalSets(got, want) {
			t.Errorf("%s: got %v, want %v", hostname, got, want)
		}
		if other := fake.sets[fake.key("other.example.com.", "AAAA")]; len(other.values()) != 1 {
			t.Errorf("%s: other.example.com changed: %v", hostname, other)
		}
		if service.Domain(hostname) != hostname+".example.com" {
			t.Errorf("domain: %s", service.Domain(hostname))
		}

		changes := fake.changes
		update(desired())
		if fake.changes != changes {
			t.Errorf("%s: the second update changed the record sets", hostname)
		}

		// Without IPv6 addresses, the AAAA set goes.
		update(collectionWith(newIPv4))
		if _, ok := fake.sets[fake.key(name, "AAAA")]; ok {
			t.Errorf("%s: the AAAA set is still there", hostname)
		}
		server.Close()
	}
}

func equalSets(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if !slices.Equal(v, b[k]) {
			return false
		}
	}
	return true
}
