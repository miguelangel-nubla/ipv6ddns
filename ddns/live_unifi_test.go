//go:build live

package ddns

import (
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// The UniFi Network API, live: of a self-hosted Network Application, with a user,
// IPV6DDNS_LIVE_UNIFI, which tools/live-providers.sh runs; and of UniFi OS Server, with an API key
// and with its admin, IPV6DDNS_LIVE_UNIFI_OS and IPV6DDNS_LIVE_UNIFI_OS_USER, which
// tools/unifi-os-server.sh sets up. Neither has a gateway to serve the records, so they are read
// back through the API, with a client of the test's own.
//
// A real console with a gateway, given by the same variables, can be asked too: with
// IPV6DDNS_LIVE_UNIFI_OS_DNS, or IPV6DDNS_LIVE_UNIFI_DNS, the address of its DNS server, as
// 192.168.1.1:53, each step asks it for the name, and expects the records UniFi lists. The TTL it
// answers with is logged: that of a record without one is the gateway's.
func TestLiveUniFi(t *testing.T) {
	for _, variable := range []string{"IPV6DDNS_LIVE_UNIFI", "IPV6DDNS_LIVE_UNIFI_OS", "IPV6DDNS_LIVE_UNIFI_OS_USER"} {
		t.Run(variable, func(t *testing.T) {
			settings := liveSettings(t, variable)
			raw, _ := json.Marshal(settings)
			service, err := NewService("unifi", raw)
			if err != nil {
				t.Fatal(err)
			}
			// The test's own client, of the same credentials, to read and to set the scene.
			reader, err := NewUniFi(raw)
			if err != nil {
				t.Fatal(err)
			}
			u := reader.(*UniFi)
			zone := strings.Trim(u.Zone, ".")
			name, other := "live."+zone, "other."+zone
			// limited runs f until UniFi OS stops refusing logins that came too often, as the
			// clients of these tests do, each its own: HTTP 429, for a minute or so.
			limited := func(f func() error) error {
				for deadline := time.Now().Add(3 * time.Minute); ; time.Sleep(5 * time.Second) {
					err := f()
					if err == nil || !strings.Contains(err.Error(), "HTTP 429") || time.Now().After(deadline) {
						return err
					}
				}
			}
			list := func() []unifiRecord {
				t.Helper()
				var records []unifiRecord
				if err := limited(func() error { return u.call(http.MethodGet, "", nil, &records) }); err != nil {
					t.Fatal(err)
				}
				return records
			}
			// of are the enabled A and AAAA records of key, as "TYPE value ttl".
			of := func(key string) []string {
				t.Helper()
				var out []string
				for _, r := range list() {
					if r.Key == key && r.Enabled && (r.RecordType == "A" || r.RecordType == "AAAA") {
						out = append(out, r.RecordType+" "+r.Value+" "+itoa(r.TTL))
					}
				}
				slices.Sort(out)
				return out
			}
			clean := func() {
				for _, r := range list() {
					if r.Key == name || r.Key == other {
						if err := limited(func() error { return u.call(http.MethodDelete, "/"+r.ID, nil, nil) }); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			clean()
			t.Cleanup(clean)
			// The scene: another name, a disabled record and a CNAME of the name, the user's.
			for _, r := range []unifiRecord{
				{Enabled: true, Key: other, RecordType: "AAAA", Value: "2001:db8::f"},
				{Enabled: false, Key: name, RecordType: "AAAA", Value: "2001:db8::9"},
			} {
				if err := limited(func() error { return u.call(http.MethodPost, "", r, nil) }); err != nil {
					t.Fatal(err)
				}
			}

			// The gateway's DNS server, when given: of the console of the variable, with a user or a key.
			dnsServer := os.Getenv(strings.TrimSuffix(variable, "_USER") + "_DNS")
			// answered checks the gateway answers the name with the records wanted, as "A 192.0.2.5 0",
			// and the TTL, when one is given: it may take a moment to load a change.
			answered := func(what string, want []string, wantTTL int) {
				t.Helper()
				if dnsServer == "" {
					return
				}
				var wantAddrs []string
				for _, w := range want {
					f := strings.Fields(w)
					wantAddrs = append(wantAddrs, f[0]+" "+f[1])
				}
				slices.Sort(wantAddrs)
				var got []string
				var ttls []int
				for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(500 * time.Millisecond) {
					got, ttls = nil, nil
					for _, rrType := range []string{"A", "AAAA"} {
						for _, r := range queryDNS(t, dnsServer, name, rrType) {
							ip, _ := canonicalIP(r.data)
							got = append(got, rrType+" "+ip)
							ttls = append(ttls, r.ttl)
						}
					}
					slices.Sort(got)
					ttlOK := wantTTL == 0 || len(want) == 0 || !slices.ContainsFunc(ttls, func(t int) bool { return t != wantTTL })
					if (slices.Equal(got, wantAddrs) && ttlOK) || time.Now().After(deadline) {
						break
					}
				}
				t.Logf("%s: the gateway answers %v, with the TTLs %v", what, got, ttls)
				if !slices.Equal(got, wantAddrs) {
					t.Errorf("%s: the gateway answers %v, want %v", what, got, wantAddrs)
				}
				if wantTTL != 0 && len(want) > 0 && slices.ContainsFunc(ttls, func(t int) bool { return t != wantTTL }) {
					t.Errorf("%s: the gateway answers with the TTLs %v, want %d", what, ttls, wantTTL)
				}
			}

			step := func(what string, want []string, ips ...string) {
				t.Helper()
				if err := limited(func() error { return service.Update("live", unifiAddrs(ips...)) }); err != nil {
					t.Fatalf("%s: %v", what, err)
				}
				if got := of(name); !slices.Equal(got, want) {
					t.Errorf("%s: %v, want %v", what, got, want)
				}
				answered(what, want, 0)
			}
			step("added", []string{"A 192.0.2.5 0", "AAAA 2001:db8::5 0"}, "192.0.2.5", "2001:db8::5", "2001:db8::9")
			step("again, the same", []string{"A 192.0.2.5 0", "AAAA 2001:db8::5 0"}, "192.0.2.5", "2001:db8::5", "2001:db8::9")
			step("changed", []string{"AAAA 2001:db8::6 0", "AAAA 2001:db8::7 0"}, "2001:db8::6", "2001:db8::7")
			step("none", nil)

			var disabled bool
			for _, r := range list() {
				disabled = disabled || (r.Key == name && !r.Enabled && r.Value == "2001:db8::9")
			}
			if got := of(other); !disabled || !slices.Equal(got, []string{"AAAA 2001:db8::f 0"}) {
				t.Errorf("the user's records: disabled one kept %v, the other name %v", disabled, got)
			}

			// A TTL, set on the records there.
			settings["ttl"] = "5m"
			raw, _ = json.Marshal(settings)
			withTTL, err := NewService("unifi", raw)
			if err != nil {
				t.Fatal(err)
			}
			if err := limited(func() error { return withTTL.Update("live", unifiAddrs("192.0.2.5")) }); err != nil {
				t.Fatal(err)
			}
			if got := of(name); !slices.Equal(got, []string{"A 192.0.2.5 300"}) {
				t.Errorf("with a TTL: %v", got)
			}
			answered("with a TTL", []string{"A 192.0.2.5 300"}, 300)
		})
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
