package config

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/duration"
	"github.com/miguelangel-nubla/ipv6disc/pkg/pretty"
)

// The Config section has each filter's self, family and prefix source; each credential's retry
// and the settings that tell no secret; the servers, the certificates, Home Assistant's device,
// the state folder, the log level and the warnings: the secrets hidden.
func TestPrettyPrintServers(t *testing.T) {
	announce := false
	cache := 100
	c := &Config{
		StateFolder: "/var/lib/ipv6ddns",
		Tasks: map[string]Task{"self": {
			Filters:   []Filters{{Self: true, IP: IPFilters{Family: []int{4, 6}, PrefixSource: "fritz"}}},
			Endpoints: map[string][]string{"cf": {"host"}},
		}},
		Credentials: map[string]Credential{
			"cf": {Provider: "cloudflare", Debounce: duration.Duration{}, Retry: duration.Duration{Duration: 90e9},
				RawSettings: json.RawMessage(`{"api_token": "TOKEN-SECRET", "zone": "example.com", "ttl": "5m"}`)},
			"lan": {Provider: "resolver",
				RawSettings: json.RawMessage(`{"resolver": "lan", "zone": "home.arpa", "records": ["a 60 IN A 192.0.2.1", "b 60 IN A 192.0.2.2"]}`)},
			"office": {Provider: "resolver",
				RawSettings: json.RawMessage(`{"resolvers": ["lan", "kids"], "zone": "office.test"}`)},
			"pi": {Provider: "pihole",
				RawSettings: json.RawMessage(`{"address": "http://admin:PASS-SECRET@pi.lan/admin", "password": "PASS-SECRET", "zone": "lan"}`)},
		},
		Resolvers: map[string]Resolver{"lan": {
			Listeners: StringList{"lan"}, Upstream: StringList{"192.0.2.53"}, CacheSize: &cache,
			Updates: &Updates{Keys: map[string]UpdateKey{"nas": {Secret: "TSIG-SECRET", Permissions: []Permission{
				{Names: &NamesPermission{Zone: "home.arpa"}},
				{Challenges: &ChallengesPermission{Credential: "cf", Names: StringList{"nas.lan"}}},
			}}}},
		}},
		Listeners:     map[string]Listener{"lan": {Listen: StringList{"192.0.2.2"}, TLS: "home", Allow: StringList{"192.0.2.0/24"}}},
		Webservers:    map[string]Webserver{"main": {Listeners: StringList{"lan"}}},
		Certificates:  map[string]*TLS{"home": {Certificate: "/etc/KEY-PATH.pem", Key: "/etc/KEY-PATH.key", ACME: &ACME{Names: StringList{"dns.lan"}, Credential: "cf", Email: "EMAIL-SECRET@example.com"}}},
		HomeAssistant: &HomeAssistant{Key: "HA-KEY-SECRET", Name: "ipv6ddns", Port: 6053, Listen: StringList{"192.0.2.0/24"}, Announce: &announce},
		Warnings:      []string{"discovery.ipv4 has settings but is off"},
	}

	hidden := c.PrettyPrint("", true)
	for _, want := range []string{
		"            - Filter Set:\n                Self: true\n                IP:\n                    Family: IPv4, IPv6\n                    Prefix source: fritz\n",
		"            Retry: 1m30s\n            Settings: ttl 5m, zone example.com, <sensible data hidden>\n",
		"            Settings: records 2, resolver lan, zone home.arpa\n",
		"            Settings: resolvers lan, kids, zone office.test\n",
		"            Settings: address http://pi.lan, zone lan, <sensible data hidden>\n",
		"    Resolvers:\n        lan:\n            Listeners: lan\n            Allow: none\n            Upstream: 192.0.2.53\n            Bootstrap: none\n            Cache size: 100\n",
		"                Key nas:\n                    Algorithm: hmac-sha256\n                    Allow: none\n                    - names: zone home.arpa\n                    - challenges: credential cf, names nas.lan\n                    Secret: <sensible data hidden>\n",
		"    Listeners:\n        lan:\n            Listen: 192.0.2.2\n            TLS: home\n            Allow: 192.0.2.0/24\n",
		"    Webservers:\n        main:\n            Listeners: lan\n            Allow: none\n",
		"        home:\n            Files: <sensible data hidden>\n            ACME:\n                Names: dns.lan\n                Credential: cf\n                Email: <sensible data hidden>\n",
		"    Home Assistant:\n        Name: ipv6ddns\n        Port: 6053\n        Listen: 192.0.2.0/24\n        Announce: false\n        Key: <sensible data hidden>\n",
		"    State dir: /var/lib/ipv6ddns\n    Log level: info\n    Warnings:\n        - discovery.ipv4 has settings but is off\n",
	} {
		if !strings.Contains(hidden, want) {
			t.Errorf("no\n%s\nin:\n%s", want, hidden)
		}
	}
	if strings.Contains(hidden, "SECRET") || strings.Contains(hidden, "KEY-PATH") {
		t.Errorf("a secret shows:\n%s", hidden)
	}
	if shown := c.PrettyPrint("", false); !strings.Contains(shown, "Secret: TSIG-SECRET") || !strings.Contains(shown, "Key: HA-KEY-SECRET") {
		t.Errorf("unhidden, the secrets show:\n%s", shown)
	}

	// The warnings are warnings of the page.
	roles := map[string]pretty.Role{}
	for _, line := range c.Page("", true) {
		for _, span := range line {
			roles[strings.TrimSpace(span.Text)] = span.Role
		}
	}
	if roles["- discovery.ipv4 has settings but is off"] != pretty.Warn || roles["Warnings:"] != pretty.Heading {
		t.Errorf("the warnings' roles: %v", roles)
	}
}

// The hidden view, which the web server shows to anyone, has no user, path nor query of a URL:
// of the ACME directory, and of a credential's endpoint, as of its address. A provider's own
// name for its endpoint shows.
func TestHiddenURLs(t *testing.T) {
	cfg, err := loadConfig(t, `
tasks: {}
credentials:
  public:
    provider: cloudflare
    settings:
      api_token: x
      zone: example.com
certificates:
  dns:
    acme:
      names:
        - dns.lan
      credential: public
      directory: "https://user:SECRET-1@acme.example/directory?key=SECRET-2"
listeners:
  web:
    listen:
      - https://127.0.0.1:8443
    tls: dns
webservers:
  main:
    listeners:
      - web
`)
	if err != nil {
		t.Fatal(err)
	}
	page := cfg.PrettyPrint("", true)
	if strings.Contains(page, "SECRET") || !strings.Contains(page, "                Directory: https://acme.example\n") {
		t.Errorf("the ACME directory, hidden:\n%s", page[strings.Index(page, "    Certificates:"):])
	}
	if page := cfg.PrettyPrint("", false); !strings.Contains(page, "Directory: https://user:SECRET-1@acme.example/directory?key=SECRET-2\n") {
		t.Errorf("the ACME directory, shown:\n%s", page[strings.Index(page, "    Certificates:"):])
	}
	for settings, want := range map[string]string{
		`{"endpoint": "https://user:SECRET-3@eu.api.ovh.com/1.0?token=SECRET-4", "zone": "example.com"}`: "endpoint https://eu.api.ovh.com, zone example.com",
		`{"endpoint": "ovh-eu", "zone": "example.com"}`:                                                  "endpoint ovh-eu, zone example.com",
		`{"endpoint": "user:SECRET-5@host", "zone": "example.com"}`:                                      "zone example.com, <sensible data hidden>",
		`{"server": "ns.example.com:53", "zone": "example.com"}`:                                         "server ns.example.com:53, zone example.com",
	} {
		if got := shownSettings(json.RawMessage(settings)); got != want {
			t.Errorf("%s: %q, want %q", settings, got, want)
		}
	}
}
