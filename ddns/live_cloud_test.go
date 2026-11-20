//go:build live

// The live tests of the providers that are a service: each runs when its variables give it an
// account and a name, and is skipped without them. The name is the only one whose records a test
// reads, makes or deletes: its A and AAAA records, which are gone when it ends, and a TXT record
// it makes to see it left alone, and deletes. So it must be a name with nothing of its own.

package ddns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
)

// cloudName is the name the test is given in variable, in zone, and the ways to spell it. The
// zone itself is refused: its records are not the test's to delete.
func cloudName(t *testing.T, variable, zone string) (fqdn string, spellings []string) {
	t.Helper()
	zone = strings.Trim(zone, ".")
	fqdn = strings.ToLower(FQDN(liveEnv(t, variable), zone))
	relative := RelativeName(fqdn, zone)
	if relative == "" || !inZone(fqdn, zone) {
		t.Fatalf("%s is %s: want a name of the zone %s, not the zone itself", variable, fqdn, zone)
	}
	return fqdn, []string{relative, fqdn, fqdn + "."}
}

// Cloudflare: IPV6DDNS_LIVE_CLOUDFLARE has the settings, with a token for the zone, and
// IPV6DDNS_LIVE_CLOUDFLARE_NAME the name to use in it. The records are not proxied, whatever the
// settings say: a proxied one has no TTL to see. They are looked up with the API, asked as its
// documentation says and not through the provider's client.
func TestLiveCloudflare(t *testing.T) {
	const api = "https://api.cloudflare.com/client/v4"
	s := &liveServer{provider: "cloudflare", settings: liveSettings(t, "IPV6DDNS_LIVE_CLOUDFLARE"), ttls: []string{"5m", "10m"}}
	s.settings["proxied"] = false
	s.zone = strings.Trim(fmt.Sprint(s.settings["zone"]), ".")
	fqdn, spellings := cloudName(t, "IPV6DDNS_LIVE_CLOUDFLARE_NAME", s.zone)

	type cloudflareRecord struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Type    string `json:"type"`
		Content string `json:"content"`
		TTL     int    `json:"ttl"`
	}
	call := func(t *testing.T, method, path string, body any, result any) {
		t.Helper()
		var payload io.Reader
		if body != nil {
			raw, _ := json.Marshal(body)
			payload = bytes.NewReader(raw)
		}
		request, err := http.NewRequest(method, api+path, payload)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+fmt.Sprint(s.settings["api_token"]))
		request.Header.Set("Content-Type", "application/json")
		response, err := (&http.Client{Timeout: 30 * time.Second}).Do(request)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, withoutURL(err))
		}
		defer response.Body.Close()
		var reply struct {
			Success bool            `json:"success"`
			Errors  json.RawMessage `json:"errors"`
			Result  json.RawMessage `json:"result"`
		}
		if err := json.NewDecoder(response.Body).Decode(&reply); err != nil || !reply.Success {
			t.Fatalf("%s %s: %s, %v, %s", method, path, response.Status, err, reply.Errors)
		}
		if result != nil {
			if err := json.Unmarshal(reply.Result, result); err != nil {
				t.Fatalf("%s %s: %v", method, path, err)
			}
		}
	}

	var zones []struct {
		ID string `json:"id"`
	}
	call(t, http.MethodGet, "/zones?name="+url.QueryEscape(s.zone), nil, &zones)
	if len(zones) != 1 {
		t.Fatalf("%d zones of the name %s", len(zones), s.zone)
	}
	recordsPath := "/zones/" + zones[0].ID + "/dns_records"
	list := func(t *testing.T, fqdn, rrType string) []cloudflareRecord {
		t.Helper()
		var records []cloudflareRecord
		call(t, http.MethodGet, recordsPath+"?per_page=100&name="+url.QueryEscape(fqdn)+"&type="+rrType, nil, &records)
		return records
	}
	s.records = func(t *testing.T, fqdn, rrType string) []liveRecord {
		t.Helper()
		var records []liveRecord
		for _, record := range list(t, fqdn, rrType) {
			if !strings.EqualFold(record.Name, fqdn) || record.Type != rrType {
				t.Fatalf("asked for the %s records of %s, got one of %s, %s", rrType, fqdn, record.Name, record.Type)
			}
			records = append(records, liveRecord{strings.Trim(record.Content, `"`), record.TTL})
		}
		return records
	}

	// The TXT record of the name, which no update is to touch.
	if len(list(t, fqdn, "TXT")) == 0 {
		call(t, http.MethodPost, recordsPath, map[string]any{"type": "TXT", "name": fqdn, "content": `"` + liveKeep + `"`, "ttl": 300}, nil)
	}
	t.Cleanup(func() {
		for _, record := range list(t, fqdn, "TXT") {
			if strings.Trim(record.Content, `"`) == liveKeep {
				call(t, http.MethodDelete, recordsPath+"/"+record.ID, nil, nil)
			}
		}
	})
	s.fixtures = func(t *testing.T) {
		t.Helper()
		if got := s.records(t, fqdn, "TXT"); len(got) != 1 || got[0].data != liveKeep {
			t.Errorf("%s has the TXT records %v, want its %q untouched", fqdn, got, liveKeep)
		}
	}
	s.service = func(t *testing.T, raw json.RawMessage) (Service, func() int) {
		t.Helper()
		service, err := NewService("cloudflare", raw)
		if err != nil {
			t.Fatal(err)
		}
		proxied, writes := countingProxy(t, api, func(r *http.Request) bool { return r.Method != http.MethodGet })
		service.(*Cloudflare).apiBaseURL = proxied
		return service, writes
	}

	s.run(t, fqdn, spellings...)
}

// Route 53: IPV6DDNS_LIVE_ROUTE53 has the settings, with the access key and the hosted zone, and
// IPV6DDNS_LIVE_ROUTE53_NAME the name to use in it. The record sets are looked up with the SDK,
// one by one. The changes are not counted: a request is signed for the host it goes to, and
// nothing can stand between.
func TestLiveRoute53(t *testing.T) {
	s := &liveServer{provider: "route53", settings: liveSettings(t, "IPV6DDNS_LIVE_ROUTE53"), ttls: []string{"5m", "1m30s"}}
	zoneID := fmt.Sprint(s.settings["hosted_zone_id"])
	client := route53.New(route53.Options{
		Region:      fmt.Sprint(s.settings["region"]),
		Credentials: credentials.NewStaticCredentialsProvider(fmt.Sprint(s.settings["access_key_id"]), fmt.Sprint(s.settings["secret_access_key"]), ""),
		HTTPClient:  &http.Client{Timeout: 30 * time.Second},
	})
	ctx := context.Background()
	zone, err := client.GetHostedZone(ctx, &route53.GetHostedZoneInput{Id: aws.String(zoneID)})
	if err != nil {
		t.Fatal(err)
	}
	s.zone = strings.Trim(aws.ToString(zone.HostedZone.Name), ".")
	fqdn, spellings := cloudName(t, "IPV6DDNS_LIVE_ROUTE53_NAME", s.zone)

	recordSet := func(t *testing.T, fqdn, rrType string) *types.ResourceRecordSet {
		t.Helper()
		output, err := client.ListResourceRecordSets(ctx, &route53.ListResourceRecordSetsInput{
			HostedZoneId:    aws.String(zoneID),
			StartRecordName: aws.String(fqdn + "."),
			StartRecordType: types.RRType(rrType),
			MaxItems:        aws.Int32(1),
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, set := range output.ResourceRecordSets {
			if route53Name(aws.ToString(set.Name)) == route53Name(fqdn) && set.Type == types.RRType(rrType) {
				return &set
			}
		}
		return nil
	}
	s.records = func(t *testing.T, fqdn, rrType string) []liveRecord {
		t.Helper()
		set := recordSet(t, fqdn, rrType)
		if set == nil {
			return nil
		}
		var records []liveRecord
		for _, record := range set.ResourceRecords {
			records = append(records, liveRecord{strings.Trim(aws.ToString(record.Value), `"`), int(aws.ToInt64(set.TTL))})
		}
		return records
	}
	change := func(t *testing.T, action types.ChangeAction, set *types.ResourceRecordSet) {
		t.Helper()
		_, err := client.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
			HostedZoneId: aws.String(zoneID),
			ChangeBatch:  &types.ChangeBatch{Changes: []types.Change{{Action: action, ResourceRecordSet: set}}},
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	// The TXT record set of the name, which no update is to touch.
	if recordSet(t, fqdn, "TXT") == nil {
		change(t, types.ChangeActionCreate, &types.ResourceRecordSet{
			Name: aws.String(fqdn + "."), Type: types.RRTypeTxt, TTL: aws.Int64(300),
			ResourceRecords: []types.ResourceRecord{{Value: aws.String(`"` + liveKeep + `"`)}},
		})
	}
	t.Cleanup(func() {
		if set := recordSet(t, fqdn, "TXT"); set != nil && len(set.ResourceRecords) == 1 && aws.ToString(set.ResourceRecords[0].Value) == `"`+liveKeep+`"` {
			change(t, types.ChangeActionDelete, set)
		}
	})
	s.fixtures = func(t *testing.T) {
		t.Helper()
		if got := s.records(t, fqdn, "TXT"); len(got) != 1 || got[0].data != liveKeep {
			t.Errorf("%s has the TXT records %v, want its %q untouched", fqdn, got, liveKeep)
		}
	}
	s.service = func(t *testing.T, raw json.RawMessage) (Service, func() int) {
		t.Helper()
		service, err := NewService("route53", raw)
		if err != nil {
			t.Fatal(err)
		}
		return service, nil
	}

	s.run(t, fqdn, spellings...)
}

// DuckDNS: IPV6DDNS_LIVE_DUCKDNS has the settings, the token, and IPV6DDNS_LIVE_DUCKDNS_NAME a
// name of the account, whose addresses the test replaces and leaves cleared. DuckDNS has one
// address of each family for a name, and tells them in the answer to an update only: they are
// looked up with DNS queries to its own name servers, which take a while to follow.
func TestLiveDuckDNS(t *testing.T) {
	s := &liveServer{provider: "duckdns", settings: liveSettings(t, "IPV6DDNS_LIVE_DUCKDNS"), zone: "duckdns.org", settle: 2 * time.Minute}
	fqdn, spellings := cloudName(t, "IPV6DDNS_LIVE_DUCKDNS_NAME", s.zone)

	servers, err := net.LookupHost("ns1.duckdns.org")
	if err != nil || len(servers) == 0 {
		t.Fatalf("the name server of DuckDNS: %v", err)
	}
	s.records = dnsRecords(net.JoinHostPort(servers[0], "53"))

	service, err := NewService("duckdns", s.with("", nil))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := service.Update(spellings[0], collectionWith()); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	for i, step := range []struct {
		name string
		ips  []string
		want []string
	}{
		{"created", []string{"2001:db8::1", "192.0.2.1"}, []string{"AAAA 2001:db8::1", "A 192.0.2.1"}},
		{"unchanged", []string{"2001:db8::1", "192.0.2.1"}, []string{"AAAA 2001:db8::1", "A 192.0.2.1"}},
		{"changed", []string{"2001:db8::2", "192.0.2.2"}, []string{"AAAA 2001:db8::2", "A 192.0.2.2"}},
		{"IPv6 only", []string{"2001:db8::2"}, []string{"AAAA 2001:db8::2"}},
		{"IPv4 only", []string{"192.0.2.2"}, []string{"A 192.0.2.2"}},
		{"without addresses", nil, nil},
	} {
		hostname := spellings[i%len(spellings)]
		if err := service.Update(hostname, collectionWith(step.ips...)); err != nil {
			t.Fatalf("%s: Update(%q): %v", step.name, hostname, err)
		}
		s.expect(t, step.name, fqdn, "", step.want...)
	}
}
