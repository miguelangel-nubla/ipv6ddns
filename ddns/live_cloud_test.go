//go:build live

// The live tests of the providers that are a service: each runs when its variables give it an
// account and a name, and is skipped without them. The name is the only one whose records a test
// reads, makes or deletes: its A and AAAA records, which are gone when it ends, and a TXT record
// it makes to see it left alone, and deletes. So it must be a name with nothing of its own.

package ddns

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
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

// deSEC: IPV6DDNS_LIVE_DESEC has the settings, with a token for the domain, and
// IPV6DDNS_LIVE_DESEC_NAME the name to use in it. The records are read with the API, asked as its
// documentation says and not through the provider's client. Its TTLs are an hour at the least.
func TestLiveDeSEC(t *testing.T) {
	const api = "https://desec.io/api/v1"
	s := &liveServer{provider: "desec", settings: liveSettings(t, "IPV6DDNS_LIVE_DESEC"), ttls: []string{"1h", "2h"}}
	s.zone = strings.ToLower(strings.Trim(fmt.Sprint(s.settings["zone"]), "."))
	fqdn, spellings := cloudName(t, "IPV6DDNS_LIVE_DESEC_NAME", s.zone)
	subname := RelativeName(fqdn, s.zone)
	domain := api + "/domains/" + url.PathEscape(s.zone)

	call := func(t *testing.T, method, path string, body any, result any) int {
		t.Helper()
		var payload io.Reader
		if body != nil {
			raw, _ := json.Marshal(body)
			payload = bytes.NewReader(raw)
		}
		for {
			request, err := http.NewRequest(method, domain+path, payload)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Authorization", "Token "+fmt.Sprint(s.settings["token"]))
			request.Header.Set("Content-Type", "application/json")
			response, err := (&http.Client{Timeout: 30 * time.Second}).Do(request)
			if err != nil {
				t.Fatalf("%s %s: %v", method, path, withoutURL(err))
			}
			data, _ := io.ReadAll(response.Body)
			response.Body.Close()
			// deSEC limits the requests of a domain: as many as the test asks, it waits.
			if response.StatusCode == http.StatusTooManyRequests {
				time.Sleep(2 * time.Second)
				if body != nil {
					raw, _ := json.Marshal(body)
					payload = bytes.NewReader(raw)
				}
				continue
			}
			if response.StatusCode == http.StatusNotFound {
				return response.StatusCode
			}
			if response.StatusCode >= 300 {
				t.Fatalf("%s %s: %s: %s", method, path, response.Status, data)
			}
			if result != nil && len(data) > 0 {
				if err := json.Unmarshal(data, result); err != nil {
					t.Fatalf("%s %s: %v", method, path, err)
				}
			}
			return response.StatusCode
		}
	}
	s.records = func(t *testing.T, name, rrType string) []liveRecord {
		t.Helper()
		var set deSECRRset
		if call(t, http.MethodGet, "/rrsets/"+url.PathEscape(RelativeName(name, s.zone))+"/"+rrType+"/", nil, &set) == http.StatusNotFound {
			return nil
		}
		var records []liveRecord
		for _, r := range set.Records {
			records = append(records, liveRecord{strings.Trim(r, `"`), set.TTL})
		}
		return records
	}

	// The TXT record of the name, which no update is to touch.
	keep := []deSECRRset{{Subname: subname, Type: "TXT", TTL: 3600, Records: []string{quoteTXT(liveKeep)}}}
	call(t, http.MethodPatch, "/rrsets/", keep, nil)
	t.Cleanup(func() {
		call(t, http.MethodPatch, "/rrsets/", []deSECRRset{{Subname: subname, Type: "TXT", Records: []string{}}}, nil)
	})
	s.fixtures = func(t *testing.T) {
		t.Helper()
		if got := s.records(t, fqdn, "TXT"); len(got) != 1 || got[0].data != liveKeep {
			t.Errorf("%s has the TXT records %v, want its %q untouched", fqdn, got, liveKeep)
		}
	}
	s.service = func(t *testing.T, raw json.RawMessage) (Service, func() int) {
		t.Helper()
		service, err := NewService("desec", raw)
		if err != nil {
			t.Fatal(err)
		}
		proxied, writes := countingProxy(t, api, func(r *http.Request) bool { return r.Method != http.MethodGet })
		service.(*DeSEC).apiBaseURL = proxied
		return service, writes
	}

	s.run(t, fqdn, spellings...)
}

// Hetzner: IPV6DDNS_LIVE_HETZNER has the settings, with a token of the project of the zone, and
// IPV6DDNS_LIVE_HETZNER_NAME the name to use in it. The records are read with the Cloud API, asked
// as its documentation says and not through the provider's client.
func TestLiveHetzner(t *testing.T) {
	const api = "https://api.hetzner.cloud/v1"
	s := &liveServer{provider: "hetzner", settings: liveSettings(t, "IPV6DDNS_LIVE_HETZNER"), ttls: []string{"5m", "10m"}}
	s.zone = strings.ToLower(strings.Trim(fmt.Sprint(s.settings["zone"]), "."))
	fqdn, spellings := cloudName(t, "IPV6DDNS_LIVE_HETZNER_NAME", s.zone)
	sub := RelativeName(fqdn, s.zone)

	call := func(t *testing.T, method, path string, body any, result any) {
		t.Helper()
		for {
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
			data, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode == http.StatusTooManyRequests {
				time.Sleep(2 * time.Second)
				continue
			}
			if response.StatusCode >= 300 {
				t.Fatalf("%s %s: %s: %s", method, path, response.Status, data)
			}
			if result != nil {
				if err := json.Unmarshal(data, result); err != nil {
					t.Fatalf("%s %s: %v", method, path, err)
				}
			}
			return
		}
	}
	var zones struct {
		Zones []struct {
			ID json.Number `json:"id"`
		} `json:"zones"`
	}
	call(t, http.MethodGet, "/zones?name="+url.QueryEscape(s.zone), nil, &zones)
	if len(zones.Zones) != 1 {
		t.Fatalf("%d zones of the name %s", len(zones.Zones), s.zone)
	}
	zone := "/zones/" + zones.Zones[0].ID.String()
	set := func(t *testing.T, rrType string) *hetznerRRset {
		t.Helper()
		var answer struct {
			RRsets []hetznerRRset `json:"rrsets"`
		}
		call(t, http.MethodGet, zone+"/rrsets?name="+url.QueryEscape(sub)+"&type="+rrType, nil, &answer)
		for _, r := range answer.RRsets {
			if strings.EqualFold(r.Name, sub) && r.Type == rrType {
				return &r
			}
		}
		return nil
	}
	s.records = func(t *testing.T, name, rrType string) []liveRecord {
		t.Helper()
		if !strings.EqualFold(name, fqdn) {
			t.Fatalf("asked for %s, the test's name is %s", name, fqdn)
		}
		r := set(t, rrType)
		if r == nil {
			return nil
		}
		ttl := 0
		if r.TTL != nil {
			ttl = *r.TTL
		}
		var records []liveRecord
		for _, v := range r.Records {
			records = append(records, liveRecord{strings.Trim(v.Value, `"`), ttl})
		}
		return records
	}

	// The TXT record of the name, which no update is to touch.
	if set(t, "TXT") == nil {
		ttl := 300
		call(t, http.MethodPost, zone+"/rrsets", hetznerRRset{Name: sub, Type: "TXT", TTL: &ttl, Records: []hetznerRecord{{Value: quoteTXT(liveKeep)}}}, nil)
	}
	t.Cleanup(func() {
		if r := set(t, "TXT"); r != nil && len(r.Records) == 1 && strings.Trim(r.Records[0].Value, `"`) == liveKeep {
			call(t, http.MethodDelete, zone+"/rrsets/"+url.PathEscape(sub)+"/TXT", nil, nil)
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
		service, err := NewService("hetzner", raw)
		if err != nil {
			t.Fatal(err)
		}
		proxied, writes := countingProxy(t, api, func(r *http.Request) bool { return r.Method != http.MethodGet })
		service.(*Hetzner).apiBaseURL = proxied
		return service, writes
	}

	s.run(t, fqdn, spellings...)
}

// Porkbun: IPV6DDNS_LIVE_PORKBUN has the settings, with the keys of the account and a domain whose
// API access is on, and IPV6DDNS_LIVE_PORKBUN_NAME the name to use in it. The records are read
// with the API, asked as its documentation says and not through the provider's client. Its TTLs
// are 10 minutes at the least.
func TestLivePorkbun(t *testing.T) {
	const api = "https://api.porkbun.com/api/json/v3"
	s := &liveServer{provider: "porkbun", settings: liveSettings(t, "IPV6DDNS_LIVE_PORKBUN"), ttls: []string{"10m", "20m"}}
	s.zone = strings.ToLower(strings.Trim(fmt.Sprint(s.settings["zone"]), "."))
	fqdn, spellings := cloudName(t, "IPV6DDNS_LIVE_PORKBUN_NAME", s.zone)
	sub := RelativeName(fqdn, s.zone)

	call := func(t *testing.T, path string, fields map[string]string, result any) {
		t.Helper()
		body := map[string]string{"apikey": fmt.Sprint(s.settings["api_key"]), "secretapikey": fmt.Sprint(s.settings["secret_api_key"])}
		for k, v := range fields {
			body[k] = v
		}
		for {
			raw, _ := json.Marshal(body)
			response, err := (&http.Client{Timeout: 30 * time.Second}).Post(api+path, "application/json", bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("%s: %v", path, withoutURL(err))
			}
			data, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode == http.StatusServiceUnavailable || response.StatusCode == http.StatusTooManyRequests {
				time.Sleep(2 * time.Second)
				continue
			}
			var status struct {
				Status string `json:"status"`
			}
			if json.Unmarshal(data, &status) != nil || status.Status != "SUCCESS" {
				t.Fatalf("%s: %s: %s", path, response.Status, data)
			}
			if result != nil {
				if err := json.Unmarshal(data, result); err != nil {
					t.Fatalf("%s: %v", path, err)
				}
			}
			return
		}
	}
	list := func(t *testing.T, rrType string) []porkbunRecord {
		t.Helper()
		var answer struct {
			Records []porkbunRecord `json:"records"`
		}
		call(t, "/dns/retrieveByNameType/"+url.PathEscape(s.zone)+"/"+rrType+"/"+url.PathEscape(sub), nil, &answer)
		return answer.Records
	}
	s.records = func(t *testing.T, name, rrType string) []liveRecord {
		t.Helper()
		if !strings.EqualFold(name, fqdn) {
			t.Fatalf("asked for %s, the test's name is %s", name, fqdn)
		}
		var records []liveRecord
		for _, r := range list(t, rrType) {
			ttl, _ := strconv.Atoi(r.TTL)
			records = append(records, liveRecord{strings.Trim(r.Content, `"`), ttl})
		}
		return records
	}

	// The TXT record of the name, which no update is to touch.
	if len(list(t, "TXT")) == 0 {
		call(t, "/dns/create/"+url.PathEscape(s.zone), map[string]string{"name": sub, "type": "TXT", "content": liveKeep, "ttl": "600"}, nil)
	}
	t.Cleanup(func() {
		for _, r := range list(t, "TXT") {
			if strings.Trim(r.Content, `"`) == liveKeep {
				call(t, "/dns/delete/"+url.PathEscape(s.zone)+"/"+url.PathEscape(r.ID), nil, nil)
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
		service, err := NewService("porkbun", raw)
		if err != nil {
			t.Fatal(err)
		}
		// Every request is a POST: those that change are counted by their path.
		proxied, writes := countingProxy(t, api, func(r *http.Request) bool { return !strings.Contains(r.URL.Path, "/retrieve") })
		service.(*Porkbun).apiBaseURL = proxied
		return service, writes
	}

	s.run(t, fqdn, spellings...)
}

// DigitalOcean: IPV6DDNS_LIVE_DIGITALOCEAN has the settings, with a token of the write scope, and
// IPV6DDNS_LIVE_DIGITALOCEAN_NAME the name to use in its domain. The records are read with the
// API, asked as its documentation says and not through the provider's client.
func TestLiveDigitalOcean(t *testing.T) {
	const api = "https://api.digitalocean.com/v2"
	s := &liveServer{provider: "digitalocean", settings: liveSettings(t, "IPV6DDNS_LIVE_DIGITALOCEAN"), ttls: []string{"5m", "10m"}}
	s.zone = strings.ToLower(strings.Trim(fmt.Sprint(s.settings["zone"]), "."))
	fqdn, spellings := cloudName(t, "IPV6DDNS_LIVE_DIGITALOCEAN_NAME", s.zone)
	records := api + "/domains/" + url.PathEscape(s.zone) + "/records"

	call := func(t *testing.T, method, target string, body any, result any) {
		t.Helper()
		for {
			var payload io.Reader
			if body != nil {
				raw, _ := json.Marshal(body)
				payload = bytes.NewReader(raw)
			}
			request, err := http.NewRequest(method, target, payload)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Authorization", "Bearer "+fmt.Sprint(s.settings["api_token"]))
			request.Header.Set("Content-Type", "application/json")
			response, err := (&http.Client{Timeout: 30 * time.Second}).Do(request)
			if err != nil {
				t.Fatalf("%s: %v", method, withoutURL(err))
			}
			data, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode == http.StatusTooManyRequests {
				time.Sleep(2 * time.Second)
				continue
			}
			if response.StatusCode >= 300 {
				t.Fatalf("%s: %s: %s", method, response.Status, data)
			}
			if result != nil && len(data) > 0 {
				if err := json.Unmarshal(data, result); err != nil {
					t.Fatalf("%s: %v", method, err)
				}
			}
			return
		}
	}
	list := func(t *testing.T, rrType string) []digitalOceanRecord {
		t.Helper()
		var answer struct {
			Records []digitalOceanRecord `json:"domain_records"`
		}
		call(t, http.MethodGet, records+"?per_page=200&name="+url.QueryEscape(fqdn)+"&type="+rrType, nil, &answer)
		return answer.Records
	}
	s.records = func(t *testing.T, name, rrType string) []liveRecord {
		t.Helper()
		if !strings.EqualFold(name, fqdn) {
			t.Fatalf("asked for %s, the test's name is %s", name, fqdn)
		}
		var out []liveRecord
		for _, r := range list(t, rrType) {
			out = append(out, liveRecord{strings.Trim(r.Data, `"`), r.TTL})
		}
		return out
	}

	// The TXT record of the name, which no update is to touch.
	if len(list(t, "TXT")) == 0 {
		call(t, http.MethodPost, records, digitalOceanRecord{Type: "TXT", Name: RelativeName(fqdn, s.zone), Data: liveKeep, TTL: 300}, nil)
	}
	t.Cleanup(func() {
		for _, r := range list(t, "TXT") {
			if strings.Trim(r.Data, `"`) == liveKeep {
				call(t, http.MethodDelete, records+"/"+strconv.FormatInt(r.ID, 10), nil, nil)
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
		service, err := NewService("digitalocean", raw)
		if err != nil {
			t.Fatal(err)
		}
		proxied, writes := countingProxy(t, api, func(r *http.Request) bool { return r.Method != http.MethodGet })
		service.(*DigitalOcean).apiBaseURL = proxied
		return service, writes
	}

	s.run(t, fqdn, spellings...)
}

// Gandi: IPV6DDNS_LIVE_GANDI has the settings, with a personal access token, and
// IPV6DDNS_LIVE_GANDI_NAME the name to use in its domain. The records are read with the LiveDNS
// API, asked as its documentation says and not through the provider's client. Its TTLs are 5
// minutes at the least.
func TestLiveGandi(t *testing.T) {
	const api = "https://api.gandi.net/v5/livedns"
	s := &liveServer{provider: "gandi", settings: liveSettings(t, "IPV6DDNS_LIVE_GANDI"), ttls: []string{"5m", "10m"}}
	s.zone = strings.ToLower(strings.Trim(fmt.Sprint(s.settings["zone"]), "."))
	fqdn, spellings := cloudName(t, "IPV6DDNS_LIVE_GANDI_NAME", s.zone)
	set := api + "/domains/" + url.PathEscape(s.zone) + "/records/" + url.PathEscape(RelativeName(fqdn, s.zone)) + "/"

	call := func(t *testing.T, method, target string, body any, result any) bool {
		t.Helper()
		for {
			var payload io.Reader
			if body != nil {
				raw, _ := json.Marshal(body)
				payload = bytes.NewReader(raw)
			}
			request, err := http.NewRequest(method, target, payload)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Authorization", "Bearer "+fmt.Sprint(s.settings["token"]))
			request.Header.Set("Content-Type", "application/json")
			response, err := (&http.Client{Timeout: 30 * time.Second}).Do(request)
			if err != nil {
				t.Fatalf("%s: %v", method, withoutURL(err))
			}
			data, _ := io.ReadAll(response.Body)
			response.Body.Close()
			switch {
			case response.StatusCode == http.StatusTooManyRequests:
				time.Sleep(2 * time.Second)
				continue
			case response.StatusCode == http.StatusNotFound && method == http.MethodGet:
				return false
			case response.StatusCode >= 300:
				t.Fatalf("%s: %s: %s", method, response.Status, data)
			}
			if result != nil && len(data) > 0 {
				if err := json.Unmarshal(data, result); err != nil {
					t.Fatalf("%s: %v", method, err)
				}
			}
			return true
		}
	}
	s.records = func(t *testing.T, name, rrType string) []liveRecord {
		t.Helper()
		if !strings.EqualFold(name, fqdn) {
			t.Fatalf("asked for %s, the test's name is %s", name, fqdn)
		}
		var r gandiRRset
		if !call(t, http.MethodGet, set+rrType, nil, &r) {
			return nil
		}
		var out []liveRecord
		for _, v := range r.Values {
			out = append(out, liveRecord{strings.Trim(v, `"`), r.TTL})
		}
		return out
	}

	// The TXT record of the name, which no update is to touch.
	if !call(t, http.MethodGet, set+"TXT", nil, nil) {
		call(t, http.MethodPut, set+"TXT", gandiRRset{TTL: 300, Values: []string{quoteTXT(liveKeep)}}, nil)
	}
	t.Cleanup(func() {
		if got := s.records(t, fqdn, "TXT"); len(got) == 1 && got[0].data == liveKeep {
			call(t, http.MethodDelete, set+"TXT", nil, nil)
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
		service, err := NewService("gandi", raw)
		if err != nil {
			t.Fatal(err)
		}
		proxied, writes := countingProxy(t, api, func(r *http.Request) bool { return r.Method != http.MethodGet })
		service.(*Gandi).apiBaseURL = proxied
		return service, writes
	}

	s.run(t, fqdn, spellings...)
}

// OVH: IPV6DDNS_LIVE_OVH has the settings, with the application's keys and a consumer key of the
// zone, and IPV6DDNS_LIVE_OVH_NAME the name to use in it. The records are read with the API,
// signed as its documentation says, and not through the provider's client.
func TestLiveOVH(t *testing.T) {
	s := &liveServer{provider: "ovh", settings: liveSettings(t, "IPV6DDNS_LIVE_OVH"), ttls: []string{"5m", "10m"}}
	s.zone = strings.ToLower(strings.Trim(fmt.Sprint(s.settings["zone"]), "."))
	fqdn, spellings := cloudName(t, "IPV6DDNS_LIVE_OVH_NAME", s.zone)
	sub := RelativeName(fqdn, s.zone)
	endpoint, _ := s.settings["endpoint"].(string)
	if endpoint == "" {
		endpoint = "ovh-eu"
	}
	api := ovhEndpoints[endpoint]
	if api == "" {
		api = strings.TrimSuffix(endpoint, "/")
	}
	key, secret, consumer := fmt.Sprint(s.settings["application_key"]), fmt.Sprint(s.settings["application_secret"]), fmt.Sprint(s.settings["consumer_key"])

	var delta time.Duration
	{
		response, err := http.Get(api + "/auth/time")
		if err != nil {
			t.Fatal(withoutURL(err))
		}
		data, _ := io.ReadAll(response.Body)
		response.Body.Close()
		server, _ := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		delta = time.Until(time.Unix(server, 0))
	}
	zone := api + "/domain/zone/" + url.PathEscape(s.zone)
	call := func(t *testing.T, method, target string, body any, result any) {
		t.Helper()
		var data []byte
		if body != nil {
			data, _ = json.Marshal(body)
		}
		for {
			timestamp := strconv.FormatInt(time.Now().Add(delta).Unix(), 10)
			sum := sha1.Sum([]byte(strings.Join([]string{secret, consumer, method, target, string(data), timestamp}, "+")))
			request, err := http.NewRequest(method, target, bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("X-Ovh-Application", key)
			request.Header.Set("X-Ovh-Consumer", consumer)
			request.Header.Set("X-Ovh-Timestamp", timestamp)
			request.Header.Set("X-Ovh-Signature", "$1$"+hex.EncodeToString(sum[:]))
			request.Header.Set("Content-Type", "application/json")
			response, err := (&http.Client{Timeout: 30 * time.Second}).Do(request)
			if err != nil {
				t.Fatalf("%s: %v", method, withoutURL(err))
			}
			answer, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode == http.StatusTooManyRequests {
				time.Sleep(2 * time.Second)
				continue
			}
			if response.StatusCode >= 300 {
				t.Fatalf("%s: %s: %s", method, response.Status, answer)
			}
			if result != nil && len(answer) > 0 {
				if err := json.Unmarshal(answer, result); err != nil {
					t.Fatalf("%s: %v", method, err)
				}
			}
			return
		}
	}
	list := func(t *testing.T, rrType string) []ovhRecord {
		t.Helper()
		var ids []int64
		call(t, http.MethodGet, zone+"/record?fieldType="+rrType+"&subDomain="+url.QueryEscape(sub), nil, &ids)
		var out []ovhRecord
		for _, id := range ids {
			var r ovhRecord
			call(t, http.MethodGet, zone+"/record/"+strconv.FormatInt(id, 10), nil, &r)
			out = append(out, r)
		}
		return out
	}
	s.records = func(t *testing.T, name, rrType string) []liveRecord {
		t.Helper()
		if !strings.EqualFold(name, fqdn) {
			t.Fatalf("asked for %s, the test's name is %s", name, fqdn)
		}
		var out []liveRecord
		for _, r := range list(t, rrType) {
			out = append(out, liveRecord{strings.Trim(r.Target, `"`), r.TTL})
		}
		return out
	}

	// The TXT record of the name, which no update is to touch.
	if len(list(t, "TXT")) == 0 {
		call(t, http.MethodPost, zone+"/record", ovhRecord{FieldType: "TXT", SubDomain: sub, Target: liveKeep, TTL: 300}, nil)
		call(t, http.MethodPost, zone+"/refresh", nil, nil)
	}
	t.Cleanup(func() {
		for _, r := range list(t, "TXT") {
			if strings.Trim(r.Target, `"`) == liveKeep {
				call(t, http.MethodDelete, zone+"/record/"+strconv.FormatInt(r.ID, 10), nil, nil)
			}
		}
		call(t, http.MethodPost, zone+"/refresh", nil, nil)
	})
	s.fixtures = func(t *testing.T) {
		t.Helper()
		if got := s.records(t, fqdn, "TXT"); len(got) != 1 || got[0].data != liveKeep {
			t.Errorf("%s has the TXT records %v, want its %q untouched", fqdn, got, liveKeep)
		}
	}
	// The requests are signed of their URL: no proxy can stand between, so the changes aren't
	// counted.
	s.service = func(t *testing.T, raw json.RawMessage) (Service, func() int) {
		t.Helper()
		service, err := NewService("ovh", raw)
		if err != nil {
			t.Fatal(err)
		}
		return service, nil
	}

	s.run(t, fqdn, spellings...)
}
