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

func TestPluginParams(t *testing.T) {
	// A password with what the params use: commas, backslashes.
	const password = `p,a\s\,s`

	ssh, err := PluginConfig{Type: "linux", Interval: "60s", Address: "192.0.2.1", Username: "root", Password: password, HostKey: hostKey}.PluginParams()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := linux.ParseConfig(ssh)
	if err != nil || cfg.Password != password || cfg.HostKey != hostKey || cfg.IdentityFile != "" || cfg.Address != "192.0.2.1" {
		t.Errorf("linux: %q read back as %+v, %v", ssh, cfg, err)
	}

	minimal, _ := PluginConfig{Type: "freebsd", Interval: "60s", Address: "fw", Username: "root", IdentityFile: "/key"}.PluginParams()
	if minimal != "60s,fw,root,,/key" {
		t.Errorf("freebsd: got %q", minimal)
	}

	routeros, err := PluginConfig{Type: "mikrotik", Interval: "1m", Address: "192.0.2.1", Username: "admin", Password: password, UseTLS: true}.PluginParams()
	if err != nil {
		t.Fatal(err)
	}
	mcfg, err := mikrotik.ParseConfig(routeros)
	if err != nil || mcfg.Password != password || !mcfg.UseTLS || mcfg.TLSFingerprint != "" {
		t.Errorf("mikrotik: %q read back as %+v, %v", routeros, mcfg, err)
	}

	if got, _ := (PluginConfig{Type: "linux", Params: "60s,a,b,c"}).PluginParams(); got != "60s,a,b,c" {
		t.Errorf("params: got %q", got)
	}

	for _, wrong := range []PluginConfig{
		{Type: "linux", Interval: "60s", Address: "a", Username: "b", UseTLS: true},
		{Type: "mikrotik", Interval: "60s", Address: "a", Username: "b", HostKey: hostKey},
		{Type: "nope", Interval: "60s", Address: "a", Username: "b"},
		{Type: "linux", Params: "60s,a,b,c", Address: "a"},
	} {
		if _, err := wrong.PluginParams(); err == nil {
			t.Errorf("%+v: want an error", wrong)
		}
	}
}

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
	params, _ := cfg.Discovery.Plugins["router"].PluginParams()
	if mcfg, err := mikrotik.ParseConfig(params); err != nil || mcfg.Password != "with,a comma" || !mcfg.UseTLS {
		t.Errorf("got %q, read back as %+v, %v", params, mcfg, err)
	}

	for name, plugin := range map[string]string{
		"params and fields":  "      type: linux\n      params: 60s,a,b,c\n      address: a\n",
		"fields missing":     "      type: linux\n      interval: 60s\n",
		"unknown type":       "      type: openbsd\n      params: 60s,a,b,c\n",
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

	// What is wrong is said, without the schema's combinations around it.
	for plugin, want := range map[string]string{
		"      type: linux\n": "interval is required",
		"      type: linux\n      params: 60s,a,b,c\n      address: a\n":                                                                     "not both",
		"      type: mikrotik\n      interval: 60\n      address: a\n      username: u\n":                                                    "interval",
		"      type: linux\n      interval: 60s\n      address: a\n      username: u\n":                                                      "needs a password or an identity file",
		"      type: linux\n      interval: 60s\n      address: a\n      username: u\n      identity_file: /k\n      use_tls: true\n":        "use_tls is not allowed",
		"      type: mikrotik\n      interval: 60s\n      address: a\n      username: u\n      password: p\n      tls_fingerprint: nothex\n": "tls_fingerprint",
		"      type: mikrotik\n      params: 60s\n":                                                                                          "invalid mikrotik config",
	} {
		_, err := load(plugin)
		if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), "Must validate") {
			t.Errorf("%q: got %v, want an error with %q only", plugin, err, want)
		}
	}

	// The params in one string still work, with a warning.
	cfg, err = load("      type: linux\n      params: 60s,a,b,c\n")
	if err != nil || len(cfg.Warnings) != 1 || !strings.Contains(cfg.Warnings[0], "params is deprecated") {
		t.Errorf("params: %v, warnings %v", err, cfg.Warnings)
	}
}

// The schema's plugin fields are those the plugin types of ipv6disc register, and requires the
// same of them.
func TestPluginSchemaMatchesTheTypes(t *testing.T) {
	var schema struct {
		Defs map[string]struct {
			Properties map[string]any `json:"properties"`
			Else       struct {
				Required []string `json:"required"`
			} `json:"else"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(configSchema, &schema); err != nil {
		t.Fatal(err)
	}
	defs := map[string]string{"linux": "sshPlugin", "freebsd": "sshPlugin", "mikrotik": "mikrotikPlugin"}
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
			if name != "type" && name != "params" {
				properties = append(properties, name)
			}
		}
		slices.Sort(names)
		slices.Sort(properties)
		if !slices.Equal(names, properties) {
			t.Errorf("%s: the schema's fields %v, ipv6disc's %v", typeName, properties, names)
		}
		// Without params, by fields, it requires what the type does.
		schemaRequired := slices.Sorted(slices.Values(d.Else.Required))
		slices.Sort(required)
		if !slices.Equal(schemaRequired, required) {
			t.Errorf("%s: the schema requires %v, ipv6disc %v", typeName, schemaRequired, required)
		}
	}
}
