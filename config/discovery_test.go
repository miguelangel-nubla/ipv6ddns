package config

import (
	"fmt"
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
		"ipv6 false":    {"discovery:\n  ipv6: false\n  plugins: {r: {type: linux, interval: 60s, address: a, username: b, password: c}}\n", Family{}, Family{}, 0},
		"some ways":     {"discovery:\n  ipv4:\n    active: false\n    solicit: true\n", on, Family{Enabled: true, Listen: true, Solicit: true}, 0},
		"ipv4 disabled": {"discovery:\n  ipv4:\n    enabled: false\n    solicit: true\n", on, Family{Solicit: true, Listen: true, Active: true}, 0},
		"ipv6 solicit":  {"discovery:\n  ipv6:\n    solicit: true\n", Family{Enabled: true, Listen: true, Active: true, Solicit: true}, Family{}, 0},
		// Before the families, listen and active were IPv4's too.
		"the old keys":   {"discovery:\n  listen: true\n  active: false\n  solicit_eui64: true\n", Family{Enabled: true, Listen: true, Solicit: true}, Family{Listen: true}, 3},
		"old, ipv4":      {"discovery:\n  active: false\n  ipv4: true\n", Family{Enabled: true, Listen: true}, Family{Enabled: true, Listen: true}, 1},
		"old, ipv4 ways": {"discovery:\n  active: false\n  ipv4: {solicit: true}\n", Family{Enabled: true, Listen: true}, Family{Enabled: true, Listen: true, Active: true, Solicit: true}, 1},
		// Listening off alone, for the plugins only: nothing probes, as before.
		"old, listen off":    {"discovery:\n  listen: false\n", Family{Enabled: true, Active: true}, Family{}, 1},
		"solicit, no listen": {"discovery:\n  ipv6: {listen: false, solicit: true}\n", Family{Enabled: true, Active: true, Solicit: true}, Family{}, 1},
	} {
		cfg, err := loadConfig(t, tt.discovery+"tasks: {}\n"+duckCredential)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		got6, got4 := cfg.Discovery.IPv6, cfg.Discovery.IPv4
		got6.set, got4.set, got6.object, got4.object = false, false, false, false
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
webserver:
  listen: [8053, "[::1]:8054", 10.2.3.0/24]
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
	if cfg.Lifetime.Duration != 30*time.Minute || cfg.LogLevel != "debug" || !slices.Equal(cfg.Webserver.Listen, []string{"8053", "[::1]:8054", "10.2.3.0/24"}) {
		t.Errorf("settings: %s, %q, %v", cfg.Lifetime, cfg.LogLevel, cfg.Webserver.Listen)
	}
	if len(cfg.Warnings) != 0 {
		t.Errorf("warnings: %q", cfg.Warnings)
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
	if defaults.Lifetime.Duration != DefaultLifetime || defaults.LogLevel != "" || defaults.Webserver.Listen != nil {
		t.Errorf("defaults: %s, %q, %v", defaults.Lifetime, defaults.LogLevel, defaults.Webserver.Listen)
	}

	for name, bad := range map[string]string{
		"a log level":         "log_level: loud\n",
		"a lifetime":          "lifetime: soon\n",
		"an interface":        "discovery:\n  exclude_interfaces: ['docker[']\n",
		"a family lifetime":   "discovery:\n  ipv4: {lifetime: -3}\n",
		"a webserver listing": "webserver_listen: {port: 80}\n",
		"a webserver entry":   "webserver: {listen: ['a:b:c']}\n",
		"a webserver network": "webserver: {listen: ['10.2.3.0/24:80']}\n",
		"a webserver key":     "webserver: {port: 80}\n",
		"both webserver keys": "webserver: {listen: [8053]}\nwebserver_listen: 8053\n",
	} {
		if _, err := loadConfig(t, bad+"tasks: {}\n"+duckCredential); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestHomeAssistantConfig(t *testing.T) {
	const key = "q9b/BwP6Z3bLDXmeLY+bPQPDUcKV9FXLRJlTnmoLmLM="
	cfg, err := loadConfig(t, "homeassistant:\n  key: "+key+"\nsources:\n  wan:\n    type: homeassistant\n    entity: sensor.wan_ip\ntasks: {}\n"+duckCredential)
	if err != nil {
		t.Fatal(err)
	}
	if h := cfg.HomeAssistant; h == nil || h.Name != "ipv6ddns" || h.FriendlyName != "ipv6ddns" || h.Port != 6053 {
		t.Errorf("defaults: %+v", cfg.HomeAssistant)
	}
	if s := cfg.Sources["wan"]; s.Entity != "sensor.wan_ip" || s.Interval.Duration == 0 {
		t.Errorf("the source: %+v", s)
	}

	given, err := loadConfig(t, "homeassistant: {}\ntasks: {}\n"+duckCredential)
	if err != nil || given.HomeAssistant.Key != "" || given.HomeAssistant.StateFile != "homeassistant.state" {
		t.Errorf("without a key: %v, %+v", err, given.HomeAssistant)
	}

	listen, err := loadConfig(t, "homeassistant: {port: 6054, listen: [10.2.3.75, 10.2.3.9/24, '[fd00::1]:7000']}\ntasks: {}\n"+duckCredential)
	if err != nil || fmt.Sprint(listen.HomeAssistant.Entries) != "[10.2.3.75:6054 10.2.3.0/24 port 6054 [fd00::1]:7000]" {
		t.Errorf("listen: %v, %v", err, listen.HomeAssistant)
	}
	if fmt.Sprint(given.HomeAssistant.Entries) != "[:6053]" {
		t.Errorf("listen, by default: %v", given.HomeAssistant.Entries)
	}

	for name, c := range map[string]struct{ config, want string }{
		"a listen entry":             {"homeassistant: {listen: ['a:b:c']}\n", "homeassistant.listen"},
		"a listen network with port": {"homeassistant: {listen: ['10.2.3.0/24:6053']}\n", "homeassistant.listen"},
		"a source without the block": {"sources:\n  wan:\n    type: homeassistant\n    entity: sensor.wan_ip\n", "needs the homeassistant block"},
		"a source without an entity": {"homeassistant: {key: " + key + "}\nsources:\n  wan:\n    type: homeassistant\n", "entity"},
		"a short key":                {"homeassistant: {key: c2hvcnQ=}\n", "key"},
		"a key and a state file":     {"homeassistant: {key: " + key + ", state_file: x.state}\n", "not both"},
		"a name with capitals":       {"homeassistant: {key: " + key + ", name: IPv6DDNS}\n", "name"},
	} {
		if _, err := loadConfig(t, c.config+"tasks: {}\n"+duckCredential); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want an error with %q", name, err, c.want)
		}
	}
}

// The deprecated names: they work, and warn of their new ones.
func TestDeprecatedSettings(t *testing.T) {
	cfg, err := loadConfig(t, `
webserver_listen: 8053
tasks: {}
credentials:
  duck:
    provider: duckdns
    settings: {}
    debounce_time: 3s
    retry_time: 4m
`)
	if err != nil {
		t.Fatal(err)
	}
	c := cfg.Credentials["duck"]
	if !slices.Equal(cfg.Webserver.Listen, []string{"8053"}) || cfg.WebserverListen != nil || c.Debounce.Duration != 3*time.Second || c.Retry.Duration != 4*time.Minute {
		t.Errorf("moved: %v, %v, %s, %s", cfg.Webserver.Listen, cfg.WebserverListen, c.Debounce, c.Retry)
	}
	want := []string{
		"webserver_listen is deprecated, and goes in v1.0: it is webserver.listen",
		"credentials.duck.debounce_time is deprecated, and goes in v1.0: it is debounce",
		"credentials.duck.retry_time is deprecated, and goes in v1.0: it is retry",
	}
	if !slices.Equal(cfg.Warnings, want) {
		t.Errorf("warnings: %q, want %q", cfg.Warnings, want)
	}

	for _, both := range []string{"debounce: 5s\n    debounce_time: 5s", "retry: 5s\n    retry_time: 5s"} {
		if _, err := loadConfig(t, "tasks: {}\ncredentials:\n  duck:\n    provider: duckdns\n    settings: {}\n    "+both+"\n"); err == nil || !strings.Contains(err.Error(), "give one of them") {
			t.Errorf("%q: %v, want an error", both, err)
		}
	}

	given, err := loadConfig(t, "tasks: {}\ncredentials:\n  duck:\n    provider: duckdns\n    settings: {}\n    debounce: 2s\n    retry: 3m\n")
	if err != nil || given.Credentials["duck"].Debounce.Duration != 2*time.Second || given.Credentials["duck"].Retry.Duration != 3*time.Minute || len(given.Warnings) != 0 {
		t.Errorf("the new names: %v, %+v, %q", err, given.Credentials["duck"], given.Warnings)
	}
}
