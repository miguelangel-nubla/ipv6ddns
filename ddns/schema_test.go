package ddns

import (
	"encoding/json"
	"testing"

	"github.com/miguelangel-nubla/ipv6ddns/internal/schematest"
)

func TestSettingsSchemasMatchProviders(t *testing.T) {
	schemas := make(map[string]struct {
		schema string
		value  any
	})
	for name, v := range providerTypes() {
		schemas[name] = struct {
			schema string
			value  any
		}{name, v}
	}
	for provider := range providers {
		s, ok := schemas[provider]
		if !ok {
			t.Errorf("%s: no schema to check", provider)
			continue
		}
		schema, err := SettingsSchema(s.schema)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(provider, func(t *testing.T) {
			schematest.Check(t, string(schema), s.value)
			// The providers reference is made of the descriptions.
			var described struct {
				Description string `json:"description"`
				Properties  map[string]struct {
					Description string `json:"description"`
				} `json:"properties"`
			}
			if err := json.Unmarshal(schema, &described); err != nil {
				t.Fatal(err)
			}
			if described.Description == "" {
				t.Error("no description")
			}
			for name, p := range described.Properties {
				if p.Description == "" {
					t.Errorf("%s: no description", name)
				}
			}
		})
	}
}

// providerTypes are the type of each provider's service, by its name: a new provider is added
// here, for its schema and its TXT records to be checked.
func providerTypes() map[string]any {
	return map[string]any{
		"adguardhome":             AdGuardHome{},
		"cloudflare":              Cloudflare{},
		"desec":                   DeSEC{},
		"pihole":                  PiHole{},
		"duckdns":                 DuckDNS{},
		"hetzner":                 Hetzner{},
		"porkbun":                 Porkbun{},
		"gravity":                 Gravity{},
		"mikrotik":                Mikrotik{},
		"openwrt":                 OpenWrt{},
		"opnsense_unbound":        OpnsenseUnbound{},
		"pfsense_restapi_unbound": PfsenseRestapiUnbound{},
		"route53":                 Route53{},
		"resolver":                Resolver{},
		"rfc2136":                 RFC2136{},
		"technitium":              Technitium{},
		"unifi":                   UniFi{},
		"windows":                 WindowsDNS{},
	}
}
