package config

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/miguelangel-nubla/ipv6disc/pkg/plugins"
	"github.com/miguelangel-nubla/ipv6disc/pkg/plugins/linux"
	"github.com/miguelangel-nubla/ipv6disc/pkg/plugins/mikrotik"
)

const hostKey = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// A certificate's SHA-256, as the schema takes it: 64 hex digits, with colons or not.
const (
	fingerprint       = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	fingerprintColons = "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff"
)

func TestPluginConfigs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("IPV6DDNS_TEST_ROUTER_PASSWORD", "with,a comma")
	load := func(plugin string) (Config, error) {
		os.WriteFile(path, []byte("tasks: {}\ncredentials: {}\ndiscovery:\n  plugins:\n    router:\n"+plugin), 0o600)
		return NewConfig(path)
	}

	cfg, err := load(`
      type: mikrotik
      interval: 60s
      address: 192.0.2.1
      username: admin
      password: ${IPV6DDNS_TEST_ROUTER_PASSWORD}
      use_tls: true
`)
	if err != nil {
		t.Fatal(err)
	}
	params, _ := cfg.Discovery.Plugins["router"].Params()
	if mcfg, err := mikrotik.ParseConfig(params); err != nil || mcfg.Password != "with,a comma" || !mcfg.UseTLS {
		t.Errorf("got %q, read back as %+v, %v", params, mcfg, err)
	}

	for name, plugin := range map[string]string{
		"params":             "      type: linux\n      params: 60s,a,b,c\n",
		"params and fields":  "      type: linux\n      params: 60s,a,b,c\n      address: a\n",
		"fields missing":     "      type: linux\n      interval: 60s\n",
		"unknown type":       "      type: openbsd\n      interval: 60s\n",
		"unknown field":      "      type: linux\n      interval: 60s\n      address: a\n      username: b\n      passwrd: c\n",
		"wrong type's field": "      type: linux\n      interval: 60s\n      address: a\n      username: b\n      use_tls: true\n",
		"invalid host key":   "      type: linux\n      interval: 60s\n      address: a\n      username: b\n      host_key: abc\n",
	} {
		if _, err := load(plugin); err == nil {
			t.Errorf("%s: want an error", name)
		} else if strings.Contains(err.Error(), "panic") {
			t.Errorf("%s: %v", name, err)
		}
	}

	// What is wrong is said, in ipv6disc's words, without the schema's combinations around it.
	for plugin, want := range map[string]string{
		"      type: linux\n": "discovery.plugins.router: a linux plugin needs its interval",
		"      type: mikrotik\n      interval: 60s\n      address: a\n      username: 60\n":                                                  "discovery.plugins.router.username: 60 is not a string: write it in quotes",
		"      type: linux\n      interval: 60s\n      address: a\n      username: u\n":                                                      "needs a password or an identity file",
		"      type: linux\n      interval: 60s\n      address: a\n      username: u\n      identity_file: /k\n      use_tls: true\n":        "discovery.plugins.router.use_tls: no such field of a linux plugin",
		"      type: mikrotik\n      interval: 60s\n      address: a\n      username: u\n      password: p\n      tls_fingerprint: nothex\n": "tls_fingerprint",
		// What only the plugin type checks.
		"      type: mikrotik\n      interval: 60s\n      address: a\n      username: u\n      tls_fingerprint: " + fingerprint + "\n":                       "use_tls",
		"      type: mikrotik\n      interval: 60s\n      address: a\n      username: u\n      use_tls: false\n      tls_fingerprint: " + fingerprint + "\n": "use_tls",
		"      type: mikrotik\n      interval: 60s\n      address: a\n      username: u\n      use_tls: yes please\n":                                        "discovery.plugins.router.use_tls: \"yes please\" is not true or false",
		"      type: mikrotik\n      interval: \"0\"\n      address: a\n      username: u\n":                                                                 "interval",
	} {
		_, err := load(plugin)
		if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), "Must validate") || !strings.HasPrefix(err.Error(), "discovery.plugins.router") {
			t.Errorf("%q: got %v, want an error with %q only", plugin, err, want)
		}
	}

	// What the schema's patterns take of a fingerprint and a host key, the plugin types take too.
	for _, plugin := range []string{
		"      type: mikrotik\n      interval: 60s\n      address: a\n      username: u\n      use_tls: true\n      tls_fingerprint: " + fingerprint + "\n",
		"      type: mikrotik\n      interval: 60s\n      address: a\n      username: u\n      use_tls: true\n      tls_fingerprint: " + strings.ToUpper(fingerprintColons) + "\n",
		"      type: linux\n      interval: 60s\n      address: a\n      username: u\n      password: p\n      host_key: SHA256:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLM+/0A\n",
		"      type: freebsd\n      interval: 1h30m\n      address: a\n      username: u\n      identity_file: /k\n      host_key: " + hostKey + "\n",
	} {
		if _, err := load(plugin); err != nil {
			t.Errorf("%q: %v", plugin, err)
		}
	}

	// A password with all the params use, commas, backslashes, an equals sign and a space at its
	// end, arrives whole: the fields are escaped, and the first one, the interval, has no "=" for
	// the params to be taken as name=value.
	const password = `a=b,c\d `
	t.Setenv("IPV6DDNS_TEST_ROUTER_PASSWORD", password)
	for _, typeName := range []string{"mikrotik", "linux"} {
		cfg, err := load("      type: " + typeName + "\n      interval: 1m\n      address: 1.2.3.4\n      username: a\n      password: ${IPV6DDNS_TEST_ROUTER_PASSWORD}\n")
		if err != nil {
			t.Fatalf("%s: %v", typeName, err)
		}
		params, _ := cfg.Discovery.Plugins["router"].Params()
		if want := `1m0s,1.2.3.4,a,a=b\,c\\d `; params != want {
			t.Errorf("%s: params %q, want %q", typeName, params, want)
		}
		var got string
		if typeName == "mikrotik" {
			mcfg, _ := mikrotik.ParseConfig(params)
			got = mcfg.Password
		} else {
			lcfg, _ := linux.ParseConfig(params)
			got = lcfg.Password
		}
		if got != password {
			t.Errorf("%s: the password read back as %q", typeName, got)
		}
	}
}

// The schema's plugin fields are those the plugin types of ipv6disc register, and it requires the
// same of them: ipv6disc's own schema, which its tests hold to its types, under its names here.
func TestPluginSchemaMatchesTheTypes(t *testing.T) {
	var schema struct {
		Defs map[string]struct {
			Properties map[string]any `json:"properties"`
			Required   []string       `json:"required"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(configSchema, &schema); err != nil {
		t.Fatal(err)
	}
	defs := map[string]string{"linux": "discoverySshPlugin", "freebsd": "discoverySshPlugin", "mikrotik": "discoveryMikrotikPlugin", "unifi": "discoveryUnifiPlugin"}
	if !slices.Equal(slices.Sorted(maps.Keys(defs)), plugins.Types()) {
		t.Fatalf("the schema has %v, ipv6disc %v", slices.Sorted(maps.Keys(defs)), plugins.Types())
	}
	for typeName, def := range defs {
		fields, err := plugins.Fields(typeName)
		if err != nil {
			t.Fatal(err)
		}
		var names, required []string
		for _, f := range fields {
			names = append(names, f.Name)
			if f.Required {
				required = append(required, f.Name)
			}
		}
		d := schema.Defs[def]
		var properties []string
		for name := range d.Properties {
			if name != "type" {
				properties = append(properties, name)
			}
		}
		slices.Sort(names)
		slices.Sort(properties)
		if !slices.Equal(names, properties) {
			t.Errorf("%s: the schema's fields %v, ipv6disc's %v", typeName, properties, names)
		}
		schemaRequired := slices.Sorted(slices.Values(d.Required))
		slices.Sort(required)
		if !slices.Equal(schemaRequired, required) {
			t.Errorf("%s: the schema requires %v, ipv6disc %v", typeName, schemaRequired, required)
		}
	}
}
