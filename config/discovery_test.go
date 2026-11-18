package config

import (
	"strings"
	"testing"
)

func TestDiscoveryFamilies(t *testing.T) {
	on := Family{Enabled: true, Listen: true, Active: true}
	for name, tt := range map[string]struct {
		discovery  string
		ipv6, ipv4 Family
		warnings   int
	}{
		"the default":   {"", on, Family{}, 0},
		"ipv4 true":     {"discovery:\n  ipv4: true\n", on, on, 0},
		"ipv6 false":    {"discovery:\n  ipv6: false\n  plugins: {r: {type: linux, params: '60s,a,b,c'}}\n", Family{}, Family{}, 0},
		"some ways":     {"discovery:\n  ipv4:\n    active: false\n    solicit: true\n", on, Family{Enabled: true, Listen: true, Solicit: true}, 0},
		"ipv4 disabled": {"discovery:\n  ipv4:\n    enabled: false\n    solicit: true\n", on, Family{Solicit: true, Listen: true, Active: true}, 0},
		"ipv6 solicit":  {"discovery:\n  ipv6:\n    solicit: true\n", Family{Enabled: true, Listen: true, Active: true, Solicit: true}, Family{}, 0},
		"the old keys":  {"discovery:\n  listen: true\n  active: false\n  solicit_eui64: true\n", Family{Enabled: true, Listen: true, Solicit: true}, Family{}, 3},
	} {
		cfg, err := loadConfig(t, tt.discovery+"tasks: {}\n"+duckCredential)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		got6, got4 := cfg.Discovery.IPv6, cfg.Discovery.IPv4
		got6.set, got4.set = false, false
		if got6 != tt.ipv6 || got4 != tt.ipv4 {
			t.Errorf("%s: got IPv6 %+v, IPv4 %+v, want %+v, %+v", name, got6, got4, tt.ipv6, tt.ipv4)
		}
		if len(cfg.Warnings) != tt.warnings {
			t.Errorf("%s: warnings %v", name, cfg.Warnings)
		}
		if cfg.Discovery.Listen != nil || cfg.Discovery.Active != nil || cfg.Discovery.SolicitEUI64 != nil {
			t.Errorf("%s: the old keys stay: %+v", name, cfg.Discovery)
		}
	}

	for name, tt := range map[string]struct{ discovery, want string }{
		"old and new":                {"discovery:\n  active: false\n  ipv6: {listen: true}\n", "deprecated form"},
		"active without listen":      {"discovery:\n  ipv4: {listen: false}\n", "active needs listen"},
		"an unknown way":             {"discovery:\n  ipv4: {sweep: false}\n", "sweep"},
		"neither a boolean nor ways": {"discovery:\n  ipv4: yes please\n", "ipv4"},
	} {
		if _, err := loadConfig(t, tt.discovery+"tasks: {}\n"+duckCredential); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: got %v, want an error with %q", name, err, tt.want)
		}
	}
}
