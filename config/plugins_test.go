package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
}
