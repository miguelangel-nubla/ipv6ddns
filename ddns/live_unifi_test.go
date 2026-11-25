//go:build live

package ddns

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// The UniFi Network API, live: of a self-hosted Network Application, with a user,
// IPV6DDNS_LIVE_UNIFI, which tools/live-providers.sh runs; and of UniFi OS Server, with an API key
// and with its admin, IPV6DDNS_LIVE_UNIFI_OS and IPV6DDNS_LIVE_UNIFI_OS_USER, which
// tools/unifi-os-server.sh sets up. Neither has a gateway to serve the records, so they are read
// back through the API, with a client of the test's own: what the gateway answers isn't checked.
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
			list := func() []unifiRecord {
				t.Helper()
				var records []unifiRecord
				if err := u.call(http.MethodGet, "", nil, &records); err != nil {
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
						if err := u.call(http.MethodDelete, "/"+r.ID, nil, nil); err != nil {
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
				if err := u.call(http.MethodPost, "", r, nil); err != nil {
					t.Fatal(err)
				}
			}

			step := func(what string, want []string, ips ...string) {
				t.Helper()
				if err := service.Update("live", unifiAddrs(ips...)); err != nil {
					t.Fatalf("%s: %v", what, err)
				}
				if got := of(name); !slices.Equal(got, want) {
					t.Errorf("%s: %v, want %v", what, got, want)
				}
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
			if err := withTTL.Update("live", unifiAddrs("192.0.2.5")); err != nil {
				t.Fatal(err)
			}
			if got := of(name); !slices.Equal(got, []string{"A 192.0.2.5 300"}) {
				t.Errorf("with a TTL: %v", got)
			}
		})
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
