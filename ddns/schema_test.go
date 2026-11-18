package ddns

import (
	"testing"

	"github.com/miguelangel-nubla/ipv6ddns/internal/schematest"
)

func TestSettingsSchemasMatchProviders(t *testing.T) {
	schemas := map[string]struct {
		schema string
		value  any
	}{
		"cloudflare":              {cloudflareSettingsSchema, Cloudflare{}},
		"duckdns":                 {duckDNSSettingsSchema, DuckDNS{}},
		"gravity":                 {gravitySettingsSchema, Gravity{}},
		"mikrotik":                {mikrotikSettingsSchema, Mikrotik{}},
		"openwrt":                 {openwrtSettingsSchema, OpenWrt{}},
		"opnsense_unbound":        {opnsenseUnboundSettingsSchema, OpnsenseUnbound{}},
		"pfsense_restapi_unbound": {pfsenseRestapiUnboundSettingsSchema, PfsenseRestapiUnbound{}},
		"route53":                 {route53SettingsSchema, Route53{}},
		"technitium":              {technitiumSettingsSchema, Technitium{}},
		"windows":                 {windowsSettingsSchema, WindowsDNS{}},
	}
	for provider := range providers {
		s, ok := schemas[provider]
		if !ok {
			t.Errorf("%s: no schema to check", provider)
			continue
		}
		t.Run(provider, func(t *testing.T) { schematest.Check(t, s.schema, s.value) })
	}
}
