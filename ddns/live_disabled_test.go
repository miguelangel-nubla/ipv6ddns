//go:build live

package ddns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"testing"
)

// A disabled record is the server's: an update leaves it as it is, of an address the name has or
// not, and adds none beside it, so its address stays unanswered. Each server is asked its records
// by its own API, as DNS answers no disabled one.

// liveDisabled runs the check on a name with two disabled records, one of an address it is
// updated with and one of another: disabled lists the disabled records' addresses at the server.
func liveDisabled(t *testing.T, s *liveServer, host string, disabled func() []string) {
	t.Helper()
	fqdn := host + "." + s.zone
	// Of the server's TTL, or with none where its provider has none.
	ttl, settings := "", s.with("", nil)
	if len(s.ttls) > 0 {
		ttl, settings = s.ttls[0], s.with("ttl", s.ttls[0])
	}
	service, err := NewService(s.provider, settings)
	if err != nil {
		t.Fatal(err)
	}
	for i, ips := range [][]string{{"2001:db8::1", "2001:db8::2"}, nil} {
		if err := service.Update(host, collectionWith(ips...)); err != nil {
			t.Fatalf("update %d: %v", i+1, err)
		}
		want := []string{"AAAA 2001:db8::1"}
		if ips == nil {
			want = nil
		}
		s.expect(t, fmt.Sprintf("update %d", i+1), fqdn, ttl, want...)
		got := disabled()
		slices.Sort(got)
		if !slices.Equal(got, []string{"2001:db8::2", "2001:db8::bad"}) {
			t.Errorf("update %d: the disabled records are of %v, want both as they were", i+1, got)
		}
	}
}

func TestLiveMikrotikDisabled(t *testing.T) {
	s := &liveServer{provider: "mikrotik", settings: liveSettings(t, "IPV6DDNS_LIVE_MIKROTIK"), ttls: []string{"10m"}}
	s.zone = fmt.Sprint(s.settings["zone"])
	s.records = dnsRecords(liveEnv(t, "IPV6DDNS_LIVE_MIKROTIK_DNS"))
	service, err := NewService("mikrotik", s.with("ttl", "10m"))
	if err != nil {
		t.Fatal(err)
	}
	fqdn := "live-disabled." + s.zone
	run := func(command string, args ...string) []map[string]string {
		t.Helper()
		client, err := service.(*Mikrotik).connect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		reply, err := client.Run(append([]string{command}, args...)...)
		if err != nil {
			t.Fatalf("%s: %v", command, err)
		}
		var rows []map[string]string
		for _, re := range reply.Re {
			rows = append(rows, re.Map)
		}
		return rows
	}
	removeAll := func() {
		for _, row := range run("/ip/dns/static/print", "?name="+fqdn) {
			run("/ip/dns/static/remove", "=.id="+row[".id"])
		}
	}
	removeAll()
	t.Cleanup(removeAll)
	for _, ip := range []string{"2001:db8::2", "2001:db8::bad"} {
		run("/ip/dns/static/add", "=name="+fqdn, "=type=AAAA", "=address="+ip, "=ttl=5m", "=disabled=yes")
	}
	liveDisabled(t, s, "live-disabled", func() []string {
		var ips []string
		for _, row := range run("/ip/dns/static/print", "?name="+fqdn) {
			if row["disabled"] == "true" && row["ttl"] == "5m" {
				ips = append(ips, row["address"])
			}
		}
		return ips
	})
}

// AdGuard Home: a disabled rewrite, which its API makes by an update of one added.
func TestLiveAdGuardHomeDisabled(t *testing.T) {
	s := &liveServer{provider: "adguardhome", settings: liveSettings(t, "IPV6DDNS_LIVE_ADGUARDHOME")}
	s.zone = fmt.Sprint(s.settings["zone"])
	s.records = dnsRecords(liveEnv(t, "IPV6DDNS_LIVE_ADGUARDHOME_DNS"))
	service, err := NewService("adguardhome", s.with("", nil))
	if err != nil {
		t.Fatal(err)
	}
	a := service.(*AdGuardHome)
	client := newHTTPClient(nil)
	fqdn := "live-disabled." + s.zone
	list := func() []adGuardRewrite {
		t.Helper()
		var rewrites []adGuardRewrite
		if err := a.call(client, http.MethodGet, "list", nil, &rewrites); err != nil {
			t.Fatal(err)
		}
		return rewrites
	}
	removeAll := func() {
		for _, r := range list() {
			if r.Domain == fqdn {
				if err := a.call(client, http.MethodPost, "delete", adGuardRewrite{Domain: r.Domain, Answer: r.Answer}, nil); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	removeAll()
	t.Cleanup(removeAll)
	off := false
	for _, ip := range []string{"2001:db8::2", "2001:db8::bad"} {
		rewrite := adGuardRewrite{Domain: fqdn, Answer: ip}
		if err := a.call(client, http.MethodPost, "add", rewrite, nil); err != nil {
			t.Fatal(err)
		}
		update := map[string]any{"target": rewrite, "update": adGuardRewrite{Domain: fqdn, Answer: ip, Enabled: &off}}
		if err := a.call(client, http.MethodPut, "update", update, nil); err != nil {
			t.Fatal(err)
		}
	}
	liveDisabled(t, s, "live-disabled", func() []string {
		var ips []string
		for _, r := range list() {
			if r.Domain == fqdn && r.Enabled != nil && !*r.Enabled {
				ips = append(ips, r.Answer)
			}
		}
		return ips
	})
}

// Technitium, the exception: it enables the disabled records of a type when one of that type is
// added, so a disabled record is as any other. Of an address the name has, it is enabled and
// answered, even when nothing is added beside it; of one it no longer has, it is deleted.
func TestLiveTechnitiumDisabled(t *testing.T) {
	s := &liveServer{provider: "technitium", settings: liveSettings(t, "IPV6DDNS_LIVE_TECHNITIUM"), ttls: []string{"10m"}}
	s.zone = fmt.Sprint(s.settings["zone"])
	s.records = dnsRecords(liveEnv(t, "IPV6DDNS_LIVE_TECHNITIUM_DNS"))
	address, token := fmt.Sprint(s.settings["address"]), fmt.Sprint(s.settings["token"])
	fqdn := "live-disabled." + s.zone
	client := newHTTPClient(nil)
	api := func(action string, params map[string]string) technitiumResponse {
		t.Helper()
		u, err := url.Parse(address)
		if err != nil {
			t.Fatal(err)
		}
		u.Path, _ = url.JoinPath(u.Path, "/api/zones/records/"+action)
		q := url.Values{"token": {token}, "zone": {s.zone}, "domain": {fqdn}}
		for k, v := range params {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
		resp, err := technitiumCall(client, u)
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		return resp
	}
	removeAll := func() {
		for _, r := range api("get", nil).Response.Records {
			if r.Type == "AAAA" {
				var data technitiumRDataIP
				json.Unmarshal(r.RData, &data)
				api("delete", map[string]string{"type": "AAAA", "ipAddress": data.IPAddress})
			}
		}
	}
	removeAll()
	t.Cleanup(removeAll)
	for _, ip := range []string{"2001:db8::1", "2001:db8::bad"} {
		api("add", map[string]string{"type": "AAAA", "ipAddress": ip, "ttl": "300"})
		api("update", map[string]string{"type": "AAAA", "ipAddress": ip, "newIpAddress": ip, "ttl": "300", "disable": "true"})
	}
	service, err := NewService("technitium", s.with("", nil))
	if err != nil {
		t.Fatal(err)
	}
	// Nothing is added: the record wanted is enabled, of its TTL, and the other deleted.
	if err := service.Update("live-disabled", collectionWith("2001:db8::1")); err != nil {
		t.Fatal(err)
	}
	s.expect(t, "the address of a disabled record", fqdn, "5m", "AAAA 2001:db8::1")
	for _, r := range api("get", nil).Response.Records {
		if r.Type == "AAAA" && r.Disabled {
			t.Errorf("a record is still disabled: %s", r.RData)
		}
	}
}
