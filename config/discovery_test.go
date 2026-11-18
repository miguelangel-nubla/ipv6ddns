package config

import (
	"slices"
	"strings"
	"testing"
	"time"
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

func TestSettingsAndInterfaces(t *testing.T) {
	cfg, err := loadConfig(t, `
lifetime: 30m
log_level: debug
webserver_listen: [8053, "[::1]:8054"]
discovery:
  interfaces: [eth0, "br-*"]
  exclude_interfaces: "docker*,veth*"
  rediscover: 5m
  ipv4:
    lifetime: 3m
tasks: {}
`+duckCredential)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Lifetime.Duration != 30*time.Minute || cfg.LogLevel != "debug" || !slices.Equal(cfg.WebserverListen, []string{"8053", "[::1]:8054"}) {
		t.Errorf("settings: %s, %q, %v", cfg.Lifetime, cfg.LogLevel, cfg.WebserverListen)
	}
	d := cfg.Discovery
	if !slices.Equal(d.Interfaces, []string{"eth0", "br-*"}) || !slices.Equal(d.ExcludeInterfaces, []string{"docker*", "veth*"}) {
		t.Errorf("interfaces: %v, excluding %v", d.Interfaces, d.ExcludeInterfaces)
	}
	if d.Rediscover.Duration != 5*time.Minute {
		t.Errorf("rediscover: %s", d.Rediscover)
	}
	if d.IPv4.Lifetime.Duration != 3*time.Minute || !d.IPv4.Enabled || d.IPv6.Lifetime.Duration != 0 {
		t.Errorf("family lifetimes: IPv4 %+v, IPv6 %+v", d.IPv4, d.IPv6)
	}

	defaults, err := loadConfig(t, "tasks: {}\n"+duckCredential)
	if err != nil {
		t.Fatal(err)
	}
	if defaults.Lifetime.Duration != DefaultLifetime || defaults.LogLevel != "" || defaults.WebserverListen != nil {
		t.Errorf("defaults: %s, %q, %v", defaults.Lifetime, defaults.LogLevel, defaults.WebserverListen)
	}

	for name, bad := range map[string]string{
		"a log level":         "log_level: loud\n",
		"a lifetime":          "lifetime: soon\n",
		"an interface":        "discovery:\n  exclude_interfaces: ['docker[']\n",
		"a family lifetime":   "discovery:\n  ipv4: {lifetime: -3}\n",
		"a webserver listing": "webserver_listen: {port: 80}\n",
	} {
		if _, err := loadConfig(t, bad+"tasks: {}\n"+duckCredential); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}
