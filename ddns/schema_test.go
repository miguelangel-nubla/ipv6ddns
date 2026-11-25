package ddns

import (
	"encoding/json"
	"testing"

	"github.com/miguelangel-nubla/ipv6ddns/internal/schematest"
)

func TestSettingsSchemasMatchProviders(t *testing.T) {
	schemas := map[string]struct {
		schema string
		value  any
	}{
		"adguardhome":             {"adguardhome", AdGuardHome{}},
		"cloudflare":              {"cloudflare", Cloudflare{}},
		"pihole":                  {"pihole", PiHole{}},
		"duckdns":                 {"duckdns", DuckDNS{}},
		"gravity":                 {"gravity", Gravity{}},
		"mikrotik":                {"mikrotik", Mikrotik{}},
		"openwrt":                 {"openwrt", OpenWrt{}},
		"opnsense_unbound":        {"opnsense_unbound", OpnsenseUnbound{}},
		"pfsense_restapi_unbound": {"pfsense_restapi_unbound", PfsenseRestapiUnbound{}},
		"route53":                 {"route53", Route53{}},
		"resolver":                {"resolver", Resolver{}},
		"rfc2136":                 {"rfc2136", RFC2136{}},
		"technitium":              {"technitium", Technitium{}},
		"unifi":                   {"unifi", UniFi{}},
		"windows":                 {"windows", WindowsDNS{}},
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
