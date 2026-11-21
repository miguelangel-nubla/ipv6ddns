package config

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/esphome"
	disc "github.com/miguelangel-nubla/ipv6disc/pkg/config"
	"sigs.k8s.io/yaml"
)

// The discovery block is ipv6disc's, with its defaults but the lifetime, and solicit beside it.
func TestDiscovery(t *testing.T) {
	on := disc.Family{Enabled: true, Listen: true, Active: true}
	off := disc.Family{Listen: true, Active: true}
	for name, tt := range map[string]struct {
		discovery  string
		ipv6, ipv4 disc.Family
		solicit    Solicit
		warnings   []string
	}{
		"the default":   {"", on, off, Solicit{}, nil},
		"ipv4 enabled":  {"discovery:\n  ipv4: {enabled: true}\n", on, on, Solicit{}, nil},
		"ipv6 disabled": {"discovery:\n  ipv6: {enabled: false}\n  plugins: {r: {type: linux, interval: 60s, address: a, username: b, password: c}}\n", off, off, Solicit{}, nil},
		"some ways":     {"discovery:\n  ipv4:\n    enabled: true\n    active: false\n  solicit:\n    ipv4: true\n", on, disc.Family{Enabled: true, Listen: true}, Solicit{IPv4: true}, nil},
		"a lifetime":    {"discovery:\n  ipv4:\n    enabled: true\n    lifetime: 3m\n", on, disc.Family{Enabled: true, Listen: true, Active: true, Lifetime: disc.Duration(3 * time.Minute)}, Solicit{}, nil},
		"ipv6 solicit":  {"discovery:\n  solicit:\n    ipv6: true\n", on, off, Solicit{IPv6: true}, nil},
		"both":          {"discovery:\n  ipv4: {enabled: true}\n  solicit: {ipv6: true, ipv4: true}\n", on, on, Solicit{IPv6: true, IPv4: true}, nil},
		// What is asked for and does nothing is said.
		"solicit, no listen": {"discovery:\n  ipv6: {listen: false}\n  solicit: {ipv6: true}\n", disc.Family{Enabled: true, Active: true}, off, Solicit{IPv6: true},
			[]string{"discovery.solicit.ipv6 does nothing without discovery.ipv6.listen, which reads the answers"}},
		// And so is an IPv4 block that doesn't say enabled, which turned IPv4 on up to v0.22.3.
		"ipv4, its ways alone": {"discovery:\n  ipv4: {active: false, lifetime: 10m}\n", on, disc.Family{Listen: true, Lifetime: disc.Duration(10 * time.Minute)}, Solicit{},
			[]string{"discovery.ipv4 has active, lifetime, and no enabled: IPv4 is off, and they do nothing, until it has enabled: true"}},
		"ipv4, off and said so": {"discovery:\n  ipv4: {enabled: false, active: false}\n", on, disc.Family{Listen: true}, Solicit{}, nil},
		"ipv4, empty":           {"discovery:\n  ipv4: {}\n", on, off, Solicit{}, nil},
		"solicit, a family off": {"discovery:\n  solicit: {ipv4: true}\n", on, off, Solicit{IPv4: true},
			[]string{"discovery.solicit.ipv4 does nothing without discovery.ipv4.enabled"}},
	} {
		cfg, err := loadConfig(t, tt.discovery+"tasks: {}\n"+duckCredential)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		d := cfg.Discovery
		if d.IPv6 != tt.ipv6 || d.IPv4 != tt.ipv4 || d.Solicit != tt.solicit {
			t.Errorf("%s: got IPv6 %+v, IPv4 %+v, solicit %+v, want %+v, %+v, %+v", name, d.IPv6, d.IPv4, d.Solicit, tt.ipv6, tt.ipv4, tt.solicit)
		}
		if !slices.Equal(cfg.Warnings, tt.warnings) {
			t.Errorf("%s: warnings %q, want %q", name, cfg.Warnings, tt.warnings)
		}
		// What the block doesn't say is ipv6disc's default, but the lifetime: an hour.
		if d.Lifetime != disc.Duration(DefaultLifetime) || d.Hostnames.Enabled || !reflect.DeepEqual(d.Protocols, disc.DefaultDiscovery().Protocols) {
			t.Errorf("%s: lifetime %s, hostnames %+v, protocols %+v", name, d.Lifetime, d.Hostnames, d.Protocols)
		}
	}
}

// The names and the protocols are ipv6disc's keys, read as its command reads them.
func TestDiscoveryProtocolsAndHostnames(t *testing.T) {
	cfg, err := loadConfig(t, `
discovery:
  lifetime: 30m
  rediscover: 5m
  interfaces: [eth0, "br-*"]
  exclude_interfaces: "docker*,veth*"
  ipv4: {enabled: true}
  hostnames:
    enabled: true
    lifetime: 2h
  protocols:
    ssdp: {enabled: false}
    mdns: {enabled: true, ask: false}
    arp-sweep: {max_prefix: 24}
    dns:
      enabled: true
      servers: [192.168.1.1, "[fd00::1]:5353"]
tasks: {}
`+duckCredential)
	if err != nil {
		t.Fatal(err)
	}
	d := cfg.Discovery
	if d.Lifetime != disc.Duration(30*time.Minute) || d.Rediscover != disc.Duration(5*time.Minute) {
		t.Errorf("lifetime %s, rediscover %s", d.Lifetime, d.Rediscover)
	}
	if !slices.Equal(d.Interfaces, []string{"eth0", "br-*"}) || !slices.Equal(d.ExcludeInterfaces, []string{"docker*", "veth*"}) {
		t.Errorf("interfaces: %v, excluding %v", d.Interfaces, d.ExcludeInterfaces)
	}
	if !d.Hostnames.Enabled || d.Hostnames.Lifetime != disc.Duration(2*time.Hour) {
		t.Errorf("hostnames: %+v", d.Hostnames)
	}
	want := disc.DefaultDiscovery().Protocols
	want.SSDP.Enabled = false
	want.MDNS = disc.MDNS{Enabled: true}
	want.ARPSweep.MaxPrefix = 24
	want.DNS = disc.DNS{Enabled: true, Servers: disc.Servers{netip.MustParseAddrPort("192.168.1.1:53"), netip.MustParseAddrPort("[fd00::1]:5353")}}
	if !reflect.DeepEqual(d.Protocols, want) {
		t.Errorf("protocols:\n%+v, want\n%+v", d.Protocols, want)
	}
	// And as the library's worker takes them.
	if c := d.Config(); c.Lifetime != 30*time.Minute || !c.Hostnames.Enabled || !c.Protocols.MDNS.Enabled || c.Protocols.SSDP.Enabled || !c.Protocols.NDP.Enabled {
		t.Errorf("the library's configuration: %+v", c)
	}
}

// What can't be read, or can't run, is an error with its path from the top of the configuration,
// in ipv6disc's words; what moved, one that says where it is now.
func TestDiscoveryErrors(t *testing.T) {
	keys := "lifetime, rediscover, interfaces, exclude_interfaces, ipv6, ipv4, hostnames, protocols, plugins, solicit"
	for name, tt := range map[string]struct{ config, want string }{
		// The keys that moved.
		"the lifetime of before":   {"lifetime: 30m\n", "lifetime is discovery.lifetime now: move it under discovery, beside the families"},
		"the web server of before": {"webserver_listen: 8053\n", "webserver_listen is webserver.listen now: write it as webserver: {listen: ...}"},
		"ipv6.solicit":             {"discovery:\n  ipv6: {solicit: true}\n", "discovery.ipv6.solicit is discovery.solicit.ipv6 now: the solicitation has its own block, solicit: {ipv6: true}, beside the families"},
		"ipv4.solicit":             {"discovery:\n  ipv4: {enabled: true, solicit: true}\n", "discovery.ipv4.solicit is discovery.solicit.ipv4 now: the solicitation has its own block, solicit: {ipv4: true}, beside the families"},
		"a plugin's params":        {"discovery:\n  plugins:\n    router: {type: linux, params: '60s,a,b,c'}\n", "discovery.plugins.router.params is the plugin's fields now, each a key of its own beside type, in the order the params had them: interval, address, username, password, identity_file, host_key"},
		"a mikrotik's params":      {"discovery:\n  plugins:\n    router: {type: mikrotik, params: '60s,a,b,c'}\n", "discovery.plugins.router.params is the plugin's fields now, each a key of its own beside type, in the order the params had them: interval, address, username, password, use_tls, tls_fingerprint"},
		"params of no type":        {"discovery:\n  plugins:\n    router: {params: '60s,a,b,c'}\n", "discovery.plugins.router.params is the plugin's fields now, each a key of its own beside type, in the order the params had them: interval, address, username and the others of its type"},
		// The keys that are gone: no such key, with those there are.
		"listen":        {"discovery:\n  listen: false\n", "discovery.listen: no such key: discovery has " + keys},
		"active":        {"discovery:\n  active: false\n", "discovery.active: no such key: discovery has " + keys},
		"solicit_eui64": {"discovery:\n  solicit_eui64: true\n", "discovery.solicit_eui64: no such key: discovery has " + keys},
		"ipv4: true":    {"discovery:\n  ipv4: true\n", "discovery.ipv4: true is not its settings: it is written ipv4: {enabled: true}"},
		"ipv6: false":   {"discovery:\n  ipv6: false\n", "discovery.ipv6: false is not its settings: it is written ipv6: {enabled: false}"},
		// ipv6disc's own.
		"an unknown way":        {"discovery:\n  ipv4: {sweep: false}\n", "discovery.ipv4.sweep: no such key: ipv4 has enabled, listen, active, lifetime"},
		"neither":               {"discovery:\n  ipv4: yes please\n", `discovery.ipv4: "yes please" is not a mapping of its keys`},
		"a protocol's switch":   {"discovery:\n  protocols: {mdns: true}\n", "discovery.protocols.mdns: true is not its settings: it is written mdns: {enabled: true}"},
		"no such protocol":      {"discovery:\n  protocols: {bonjour: {enabled: true}}\n", "discovery.protocols.bonjour: no such protocol: they are ndp, ping, ssdp, wsd, mdns, arp, arp-sweep, arp-listen, dhcp, lldp, netbios, llmnr, dns"},
		"no such option":        {"discovery:\n  protocols: {mdns: {query: true}}\n", "discovery.protocols.mdns.query: no such option of mdns: it has enabled, ask"},
		"a lifetime":            {"discovery:\n  lifetime: soon\n", `discovery.lifetime: "soon" is not a duration, as 90s or 4h, nor a number of seconds`},
		"no lifetime":           {"discovery:\n  lifetime: 0\n", "discovery: invalid lifetime 0s or rediscovery interval 0s: they must be positive"},
		"a family's lifetime":   {"discovery:\n  ipv4: {lifetime: -3}\n", "discovery: invalid family lifetime: IPv6 1h0m0s, IPv4 -3s"},
		"an interface":          {"discovery:\n  exclude_interfaces: ['docker[']\n", `discovery: invalid interface pattern "docker[": syntax error in pattern`},
		"ping without ndp":      {"discovery:\n  protocols: {ndp: {enabled: false}, ssdp: {enabled: false}, wsd: {enabled: false}}\n", "discovery: the ping protocol is enabled without ndp, which tells the MAC of the hosts it hears: it would find none"},
		"names not kept":        {"discovery:\n  protocols: {llmnr: {enabled: true}}\n", "discovery: the llmnr protocol is enabled, and it only learns names, which hostnames, off, doesn't keep: enable hostnames, or disable llmnr"},
		"dns without servers":   {"discovery:\n  hostnames: {enabled: true}\n  protocols: {dns: {enabled: true}}\n", "discovery: the dns protocol is enabled without servers: it asks only those it is given"},
		"a sweep too large":     {"discovery:\n  protocols: {arp-sweep: {max_prefix: 8}}\n", "discovery: invalid max_prefix of the arp-sweep protocol, 8: it is from 16 to 30"},
		"a block that is none":  {"discovery: all\n", `discovery: "all" is not a mapping of its keys`},
		"a plugin of no type":   {"discovery:\n  plugins: {router: {interval: 60s}}\n", "discovery.plugins.router: a plugin has a type: one of freebsd, linux, mikrotik"},
		"a plugin's field":      {"discovery:\n  plugins: {router: {type: linux, interval: 60s, address: a, username: b, passwrd: c}}\n", "discovery.plugins.router.passwrd: no such field of a linux plugin: it has interval, address, username, password, identity_file, host_key"},
		"a plugin that can't":   {"discovery:\n  plugins: {router: {type: linux, interval: 60s, address: a, username: b}}\n", "discovery.plugins.router: "},
		"solicit, a switch":     {"discovery:\n  solicit: true\n", "discovery.solicit: true is not its settings: it is written solicit: {ipv6: true}, and ipv4 beside it for IPv4"},
		"solicit, another key":  {"discovery:\n  solicit: {eui64: true}\n", "discovery.solicit.eui64: no such key: discovery.solicit has ipv6, ipv4"},
		"solicit, not a switch": {"discovery:\n  solicit: {ipv6: 1}\n", "discovery.solicit.ipv6: 1 is not true or false"},
	} {
		_, err := loadConfig(t, tt.config+"tasks: {}\n"+duckCredential)
		if err == nil || !slices.Contains(strings.Split(err.Error(), "\n"), tt.want) && !(strings.HasSuffix(tt.want, ": ") && strings.HasPrefix(err.Error(), tt.want)) {
			t.Errorf("%s: got\n%v\nwant a line\n%s", name, err, tt.want)
		}
		if err != nil && strings.Contains(err.Error(), "Must validate") {
			t.Errorf("%s: the schema's combinations: %v", name, err)
		}
	}

	// Every error is told, not the first alone.
	_, err := loadConfig(t, "lifetime: 1h\ndiscovery:\n  listen: true\n  ipv4: true\n  ipv6: {solicit: true}\n  protocols: {mdns: true}\ntasks: {}\n"+duckCredential)
	if err == nil || len(strings.Split(err.Error(), "\n")) != 5 {
		t.Errorf("five errors: got\n%v", err)
	}
}

func TestSettings(t *testing.T) {
	cfg, err := loadConfig(t, `
log_level: debug
webserver:
  listen: [8053, "[::1]:8054", 10.2.3.0/24]
tasks: {}
`+duckCredential)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogLevel != "debug" || !slices.Equal(cfg.Webserver.Listen, []string{"8053", "[::1]:8054", "10.2.3.0/24"}) {
		t.Errorf("settings: %q, %v", cfg.LogLevel, cfg.Webserver.Listen)
	}
	if len(cfg.Warnings) != 0 {
		t.Errorf("warnings: %q", cfg.Warnings)
	}

	defaults, err := loadConfig(t, "tasks: {}\n"+duckCredential)
	if err != nil {
		t.Fatal(err)
	}
	if defaults.Discovery.Lifetime != disc.Duration(DefaultLifetime) || defaults.LogLevel != "" || defaults.Webserver.Listen != nil {
		t.Errorf("defaults: %s, %q, %v", defaults.Discovery.Lifetime, defaults.LogLevel, defaults.Webserver.Listen)
	}

	for name, bad := range map[string]string{
		"a log level":         "log_level: loud\n",
		"a webserver entry":   "webserver: {listen: ['a:b:c']}\n",
		"a webserver network": "webserver: {listen: ['10.2.3.0/24:80']}\n",
		"a webserver key":     "webserver: {port: 80}\n",
	} {
		if _, err := loadConfig(t, bad+"tasks: {}\n"+duckCredential); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestHomeAssistantConfig(t *testing.T) {
	const key = "q9b/BwP6Z3bLDXmeLY+bPQPDUcKV9FXLRJlTnmoLmLM="
	cfg, err := loadConfig(t, "homeassistant:\n  listen: 6053\n  key: "+key+"\nsources:\n  wan:\n    type: homeassistant\n    entity: sensor.wan_ip\ntasks: {}\n"+duckCredential)
	if err != nil {
		t.Fatal(err)
	}
	if h := cfg.HomeAssistant; h == nil || h.Name != "ipv6ddns" || h.FriendlyName != "ipv6ddns" || h.Port != 6053 {
		t.Errorf("defaults: %+v", cfg.HomeAssistant)
	}
	if s := cfg.Sources["wan"]; s.Entity != "sensor.wan_ip" || s.Interval.Duration == 0 {
		t.Errorf("the source: %+v", s)
	}

	// A key of its own: no state file, by default or otherwise.
	if h := cfg.HomeAssistant; h.KeyProvisioning || h.KeyProvisioningStateFile != "" {
		t.Errorf("with a key: %+v", h)
	}
	if off, err := loadConfig(t, "homeassistant: {listen: 6053, key: "+key+", key_provisioning: false}\ntasks: {}\n"+duckCredential); err != nil || off.HomeAssistant.KeyProvisioningStateFile != "" {
		t.Errorf("with a key, and key provisioning off: %v, %+v", err, off.HomeAssistant)
	}

	given, err := loadConfig(t, "homeassistant: {listen: 6053, key_provisioning: true}\ntasks: {}\n"+duckCredential)
	if err != nil || given.HomeAssistant.Key != "" || given.HomeAssistant.KeyProvisioningStateFile != "homeassistant.state" {
		t.Errorf("key provisioning: %v, %+v", err, given.HomeAssistant)
	}
	if named, err := loadConfig(t, "homeassistant: {listen: 6053, key_provisioning: true, key_provisioning_state_file: guests.state}\ntasks: {}\n"+duckCredential); err != nil || named.HomeAssistant.KeyProvisioningStateFile != "guests.state" {
		t.Errorf("key provisioning, its state file named: %v, %+v", err, named.HomeAssistant)
	}

	// The ports of the entries may differ when the device announces none.
	listen, err := loadConfig(t, "homeassistant: {key_provisioning: true, port: 6054, announce: false, listen: [10.2.3.75, 10.2.3.9/24, '[fd00::1]:7000']}\ntasks: {}\n"+duckCredential)
	if err != nil || fmt.Sprint(listen.HomeAssistant.Entries) != "[10.2.3.75:6054 10.2.3.0/24 port 6054 [fd00::1]:7000]" {
		t.Errorf("listen: %v, %v", err, listen.HomeAssistant)
	}
	if fmt.Sprint(given.HomeAssistant.Entries) != "[:6053]" {
		t.Errorf("listen, a port alone: %v", given.HomeAssistant.Entries)
	}

	// One port, another than port: the one announced.
	if one, err := loadConfig(t, "homeassistant: {key_provisioning: true, listen: ['10.2.3.4:7000', '[fd00::1]:7000']}\ntasks: {}\n"+duckCredential); err != nil || one.HomeAssistant.Entries[0].Port != "7000" {
		t.Errorf("listen, at one port of its own: %v, %v", err, one.HomeAssistant)
	}

	// A key in a file ends in a new line, as openssl rand -base64 32 writes it.
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "homeassistant.key"), []byte(key+"\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("homeassistant:\n  listen: 6053\n  key: ${file:homeassistant.key}\ntasks: {}\n"+duckCredential), 0o600)
	if fromFile, err := NewConfig(filepath.Join(dir, "config.yaml")); err != nil {
		t.Errorf("a key in a file, with its new line: %v", err)
	} else if parsed, err := esphome.ParseKey(fromFile.HomeAssistant.Key); err != nil || len(parsed) != 32 {
		t.Errorf("a key in a file, with its new line: %q, %v", fromFile.HomeAssistant.Key, err)
	}

	for name, c := range map[string]struct{ config, want string }{
		"a listen entry":             {"homeassistant: {key_provisioning: true, listen: ['a:b:c']}\n", "homeassistant.listen"},
		"two ports, announced":       {"homeassistant: {key_provisioning: true, listen: [10.2.3.75, '[fd00::1]:7000']}\n", "announces one port"},
		"a listen network with port": {"homeassistant: {key_provisioning: true, listen: ['10.2.3.0/24:6053']}\n", "homeassistant.listen"},
		"a source without the block": {"sources:\n  wan:\n    type: homeassistant\n    entity: sensor.wan_ip\n", "needs the homeassistant block"},
		"a source without an entity": {"homeassistant: {listen: 6053, key: " + key + "}\nsources:\n  wan:\n    type: homeassistant\n", "entity"},
		"a short key":                {"homeassistant: {listen: 6053, key: c2hvcnQ=}\n", "key"},
		// How the device has its key: each says what to do.
		"neither a key nor key provisioning":  {"homeassistant: {listen: 6053}\n", `needs its encryption key, one way or the other: key, your own, made with "openssl rand -base64 32"`},
		"neither, the choices":                {"homeassistant: {listen: 6053, name: guests}\n", "${file:homeassistant.key}; or key_provisioning: true, for Home Assistant to give it when it adds the device, kept in key_provisioning_state_file"},
		"key provisioning off, and no key":    {"homeassistant: {listen: 6053, key_provisioning: false}\n", "needs its encryption key"},
		"a key and key provisioning":          {"homeassistant: {listen: 6053, key: " + key + ", key_provisioning: true}\n", "a key, or key_provisioning: true for Home Assistant to give it: one or the other"},
		"a state file alone":                  {"homeassistant: {listen: 6053, key_provisioning_state_file: x.state}\n", "homeassistant.key_provisioning_state_file is where the key Home Assistant gives is kept: it needs key_provisioning: true"},
		"a state file and a key":              {"homeassistant: {listen: 6053, key: " + key + ", key_provisioning_state_file: x.state}\n", "homeassistant.key_provisioning_state_file is where the key Home Assistant gives is kept, with key_provisioning: true: with a key of your own nothing is kept, so leave it out"},
		"a state file, key provisioning off":  {"homeassistant: {listen: 6053, key_provisioning: false, key_provisioning_state_file: x.state}\n", "it needs key_provisioning: true"},
		"the state file's key from before":    {"homeassistant: {listen: 6053, state_file: x.state}\n", "homeassistant.state_file is key_provisioning_state_file now, and needs key_provisioning: true beside it: with both, the device and its key stay as they were"},
		"it, with a key":                      {"homeassistant: {listen: 6053, key: " + key + ", state_file: x.state}\n", "homeassistant.state_file is key_provisioning_state_file now"},
		"it, with key provisioning":           {"homeassistant: {listen: 6053, key_provisioning: true, state_file: x.state}\n", "homeassistant.state_file is key_provisioning_state_file now"},
		"key provisioning that is no boolean": {"homeassistant: {listen: 6053, key_provisioning: 'yes'}\n", "homeassistant.key_provisioning: Invalid type. Expected: boolean"},
		// Where it listens: never by default, which would be every address, the internet's too on a router.
		"no listen":            {"homeassistant: {key: " + key + "}\n", "homeassistant.listen: where the device listens, for Home Assistant to connect, is to be given: the network Home Assistant is on, as 192.168.1.0/24"},
		"no listen, the port":  {"homeassistant: {key_provisioning: true}\n", "or a port alone, 6053, for every address of the machine"},
		"a name with capitals": {"homeassistant: {listen: 6053, key: " + key + ", name: IPv6DDNS}\n", "name"},
	} {
		if _, err := loadConfig(t, c.config+"tasks: {}\n"+duckCredential); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want an error with %q", name, err, c.want)
		}
	}
}

// The schema has the rules of the device's key too, for an editor that checks the configuration
// against it: what checkHomeAssistant refuses, it refuses, and it takes what that takes.
func TestHomeAssistantSchema(t *testing.T) {
	const key = `"key": "q9b/BwP6Z3bLDXmeLY+bPQPDUcKV9FXLRJlTnmoLmLM="`
	const listen = `"listen": 6053, `
	for block, valid := range map[string]bool{
		`{` + listen + key + `}`:                                                             true,
		`{` + listen + key + `, "key_provisioning": false}`:                                  true,
		`{` + listen + `"key_provisioning": true}`:                                           true,
		`{` + listen + `"key_provisioning": true, "key_provisioning_state_file": "x.state"}`: true,
		`{"listen": 6053}`:                                                                    false,
		`{` + listen + `"name": "guests"}`:                                                    false,
		`{` + listen + `"key_provisioning": false}`:                                           false,
		`{` + listen + key + `, "key_provisioning": true}`:                                    false,
		`{` + listen + `"key_provisioning_state_file": "x.state"}`:                            false,
		`{` + listen + key + `, "key_provisioning_state_file": "x.state"}`:                    false,
		`{` + listen + `"key_provisioning": false, "key_provisioning_state_file": "x.state"}`: false,
		`{` + listen + `"key_provisioning": true, "state_file": "x.state"}`:                   false,
		// Without listen.
		`{` + key + `}`:              false,
		`{"key_provisioning": true}`: false,
	} {
		configData := []byte(`{"tasks": {}, "credentials": {}, "homeassistant": ` + block + `}`)
		if err := validateConfig(configData); (err == nil) != valid {
			t.Errorf("%s: the schema says %v, want valid %v", block, err, valid)
		}
		if err := checkHomeAssistant(configData); (err == nil) != valid {
			t.Errorf("%s: the check says %v, want valid %v", block, err, valid)
		}
	}
}

// The deprecated names: they work, and warn of their new ones.
func TestDeprecatedSettings(t *testing.T) {
	cfg, err := loadConfig(t, `
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
	if c.Debounce.Duration != 3*time.Second || c.Retry.Duration != 4*time.Minute {
		t.Errorf("moved: %s, %s", c.Debounce, c.Retry)
	}
	want := []string{
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

// The schema and the reading of the discovery say the same of a document: what one takes the
// other takes, and what one refuses the other refuses, so that an editor that has the schema says
// what the start will. But for two kinds, each said here: what can't run, which only the reading
// knows, as a protocol without what it needs; and a key left null, which ipv6disc reads as left
// out and the schema refuses, so the start does.
func TestSchemaAndDiscoveryAgree(t *testing.T) {
	const (
		valid   = "valid"
		invalid = "invalid"
		// Read, and valid to the schema: it can't run.
		cannotRun = "can't run"
		// Read as left out: the schema wants its type.
		null = "null"
	)
	linux := "type: linux, interval: 60s, address: a, username: b"
	for document, want := range map[string]string{
		`{}`: valid, `null`: null, `[]`: invalid, `""`: invalid, `3`: invalid, `true`: invalid,

		`{lifetime: 30m}`: valid, `{lifetime: 90}`: valid, `{lifetime: 1.5}`: valid, `{lifetime: 1h30m}`: valid,
		`{lifetime: "90"}`: invalid, `{lifetime: 1d}`: invalid, `{lifetime: true}`: invalid, `{lifetime: [1h]}`: invalid,
		`{lifetime: -1}`: invalid, `{lifetime: -5m}`: invalid, `{lifetime: null}`: null,
		`{lifetime: 0}`: cannotRun, `{lifetime: 0s}`: cannotRun,
		`{rediscover: 5m}`: valid, `{rediscover: 0}`: valid, `{rediscover: soon}`: invalid,

		`{interfaces: eth0}`: valid, `{interfaces: "eth0, en*"}`: valid, `{interfaces: [eth0, "br-*"]}`: valid, `{interfaces: []}`: valid,
		`{exclude_interfaces: [docker0]}`: valid,
		`{interfaces: 3}`:                 invalid, `{interfaces: [eth0, 3]}`: invalid, `{interfaces: {a: b}}`: invalid, `{interfaces: null}`: null,
		`{interfaces: ["eth["]}`: cannotRun,

		`{ipv6: {}}`: valid, `{ipv4: {enabled: true}}`: valid, `{ipv4: {enabled: true, listen: false, active: false, lifetime: 10m}}`: valid,
		`{ipv6: {enabled: false}, ipv4: {enabled: false}}`: valid,
		`{ipv4: true}`: invalid, `{ipv6: false}`: invalid, `{ipv6: []}`: invalid, `{ipv6: {enabled: "true"}}`: invalid, `{ipv6: {enabled: 1}}`: invalid,
		`{ipv6: {solicit: true}}`: invalid, `{ipv4: {sweep: true}}`: invalid, `{ipv4: {lifetime: soon}}`: invalid,
		`{ipv6: null}`: null, `{ipv6: {enabled: null}}`: null,

		`{hostnames: {}}`: valid, `{hostnames: {enabled: true, lifetime: 2h}}`: valid,
		`{hostnames: true}`: invalid, `{hostnames: {names: true}}`: invalid, `{hostnames: {enabled: yes please}}`: invalid,

		`{protocols: {}}`: valid, `{protocols: {mdns: {}}}`: valid, `{protocols: {ssdp: {enabled: false}, wsd: {enabled: false}}}`: valid,
		`{hostnames: {enabled: true}, protocols: {mdns: {enabled: true, ask: false}, ssdp: {names: true}, wsd: {names: true}, llmnr: {enabled: true}, netbios: {enabled: true}}}`: valid,
		`{hostnames: {enabled: true}, protocols: {dns: {enabled: true, servers: 192.168.1.1}}}`:                                                                                   valid,
		`{hostnames: {enabled: true}, protocols: {dns: {enabled: true, servers: [192.168.1.1, "[fd00::1]:5353"]}}}`:                                                               valid,
		`{ipv4: {enabled: true}, protocols: {arp-sweep: {max_prefix: 24}, arp-listen: {enabled: false}}}`:                                                                         valid,
		`{protocols: {mdns: true}}`: invalid, `{protocols: []}`: invalid, `{protocols: true}`: invalid,
		`{protocols: {bonjour: {enabled: true}}}`: invalid, `{protocols: {arp_sweep: {}}}`: invalid,
		`{protocols: {mdns: {query: true}}}`: invalid, `{protocols: {ndp: {names: true}}}`: invalid, `{protocols: {ssdp: {ask: true}}}`: invalid,
		`{protocols: {mdns: {enabled: "true"}}}`:       invalid,
		`{protocols: {arp-sweep: {max_prefix: "24"}}}`: invalid, `{protocols: {arp-sweep: {max_prefix: 24.5}}}`: invalid,
		`{protocols: {arp-sweep: {max_prefix: 31}}}`: invalid, `{protocols: {arp-sweep: {max_prefix: 15}}}`: invalid, `{protocols: {arp-sweep: {max_prefix: 0}}}`: invalid,
		`{protocols: {dns: {servers: [1]}}}`: invalid, `{protocols: {dns: {servers: {a: b}}}}`: invalid,
		`{protocols: null}`: null, `{protocols: {mdns: null}}`: null, `{protocols: {mdns: {enabled: null}}}`: null,
		`{protocols: {ndp: {enabled: false}}}`:                                            cannotRun,
		`{protocols: {llmnr: {enabled: true}}}`:                                           cannotRun,
		`{protocols: {ssdp: {names: true}}}`:                                              cannotRun,
		`{hostnames: {enabled: true}, protocols: {dns: {enabled: true}}}`:                 invalid,
		`{hostnames: {enabled: true}, protocols: {dns: {enabled: true, servers: "x y"}}}`: cannotRun,

		`{plugins: {}}`: valid,
		`{plugins: {r: {` + linux + `, password: c}}}`:                                                                                valid,
		`{plugins: {r: {` + linux + `, identity_file: /key}}}`:                                                                        valid,
		`{plugins: {r: {` + linux + `, identity_file: /key, host_key: "ssh-ed25519 AAAA"}}}`:                                          cannotRun,
		`{plugins: {r: {type: linux, interval: 60, address: a, username: b, password: c}}}`:                                           valid,
		`{plugins: {r: {type: freebsd, interval: 5m, address: "a:22", username: b, password: c}, s: {` + linux + `, password: c}}}`:   valid,
		`{plugins: {r: {type: mikrotik, interval: 60s, address: a, username: b, password: c, use_tls: true}}}`:                        valid,
		`{plugins: {r: {type: mikrotik, interval: 60s, address: a, username: b, password: c, use_tls: true, tls_fingerprint: "00"}}}`: cannotRun,
		`{plugins: []}`: invalid, `{plugins: true}`: invalid, `{plugins: {r: true}}`: invalid, `{plugins: {r: null}}`: invalid, `{plugins: {r: {}}}`: invalid,
		`{plugins: {r: {type: nope}}}`: invalid, `{plugins: {r: {type: 3}}}`: invalid,
		`{plugins: {r: {type: linux, params: "60s,a,b,c"}}}`:                                                     invalid,
		`{plugins: {r: {` + linux + `, password: c, params: "60s,a,b,c"}}}`:                                      invalid,
		`{plugins: {r: {type: linux, address: a, username: b, password: c}}}`:                                    invalid,
		`{plugins: {r: {` + linux + `, password: 123}}}`:                                                         invalid,
		`{plugins: {r: {` + linux + `, password: c, interval: soon}}}`:                                           invalid,
		`{plugins: {r: {` + linux + `, password: c, use_tls: true}}}`:                                            invalid,
		`{plugins: {r: {` + linux + `, passwrd: c}}}`:                                                            invalid,
		`{plugins: {r: {type: mikrotik, interval: 60s, address: a, username: b, password: c, use_tls: "true"}}}`: invalid,
		`{plugins: {r: {type: mikrotik, interval: 60s, address: a, username: b, password: c, host_key: k}}}`:     invalid,
		`{plugins: null}`: null, `{plugins: {r: {` + linux + `, password: c, host_key: null}}}`: null,

		`{solicit: {}}`: valid, `{solicit: {ipv6: true}}`: valid, `{ipv4: {enabled: true}, solicit: {ipv6: false, ipv4: true}}`: valid,
		`{solicit: true}`: invalid, `{solicit: []}`: invalid, `{solicit: {eui64: true}}`: invalid, `{solicit: {ipv6: "true"}}`: invalid, `{solicit: {ipv4: 1}}`: invalid,
		`{solicit: null}`: null, `{solicit: {ipv6: null}}`: null,

		`{listen: true}`: invalid, `{active: false}`: invalid, `{solicit_eui64: true}`: invalid, `{log_level: info}`: invalid, `{webserver: {}}`: invalid,
	} {
		configData, err := yaml.YAMLToJSON([]byte("tasks: {}\ncredentials: {}\ndiscovery: " + document + "\n"))
		if err != nil {
			t.Fatalf("%s: %v", document, err)
		}
		read, schema := checkDiscovery(configData), validateConfig(configData)
		wantRead, wantSchema := want == valid || want == null, want == valid || want == cannotRun
		if (read == nil) != wantRead || (schema == nil) != wantSchema {
			t.Errorf("discovery: %s is %s: read, %v; to the schema, %v", document, want, read, schema)
		}
		// And the start is both: it takes what is valid, and nothing else.
		_, err = loadConfig(t, "tasks: {}\ncredentials: {}\ndiscovery: "+document+"\n")
		if (err == nil) != (want == valid) {
			t.Errorf("discovery: %s is %s, and loading it says %v", document, want, err)
		}
	}
}
