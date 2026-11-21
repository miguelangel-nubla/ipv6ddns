package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The configurations that v0.22.3 came with, as they were: its example, and the add-on's starting
// one. Each is told what to change, every key that moved at once, by where it is now; and with
// those changes, which are the ones docs/configuration.md lists for an upgrade, it loads.
func TestUpgradeFromV0223(t *testing.T) {
	t.Setenv("ROUTER_PASSWORD", "secret")
	read := func(name string) string {
		t.Helper()
		content, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(content)
	}
	load := func(content string) (Config, error) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return NewConfig(path)
	}
	// change replaces old, which must be there, once.
	change := func(content, old, new string) string {
		t.Helper()
		if strings.Count(content, old) != 1 {
			t.Fatalf("the configuration of v0.22.3 has %q %d times, not once", old, strings.Count(content, old))
		}
		return strings.Replace(content, old, new, 1)
	}

	t.Run("the example", func(t *testing.T) {
		example := read("v0.22.3.example.config.yaml")
		_, err := load(example)
		if err == nil {
			t.Fatal("it loads, as it is")
		}
		want := []string{
			"lifetime is discovery.lifetime now: move it under discovery, beside the families",
			"webserver_listen is webserver.listen now: listen, under webserver",
			"discovery.ipv6.solicit is discovery.solicit.ipv6 now: the solicitation has its own block, solicit, beside the families, with ipv6: true under it",
			"discovery.ipv4.solicit is discovery.solicit.ipv4 now: the solicitation has its own block, solicit, beside the families, with ipv4: true under it",
		}
		if got := strings.Split(err.Error(), "\n"); strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("it is told:\n%s\nwant:\n%s", err, strings.Join(want, "\n"))
		}

		// What the errors say, done.
		upgraded := change(example, "lifetime: 1h                  #", "#")
		upgraded = change(upgraded, "webserver_listen: [8053]", "webserver:\n  listen:\n    - 8053\n#")
		upgraded = change(upgraded, "    solicit: true     # the EUI-64 addresses eui64 filters want\n", "")
		upgraded = change(upgraded, "    solicit: true     # ARP to the MACs IPv4 filters name, alone, on the subnets of their ip.prefix\n", "")
		upgraded = change(upgraded, "discovery:\n", "discovery:\n  lifetime: 1h\n  solicit:\n    ipv6: true\n    ipv4: true\n")
		cfg, err := load(upgraded)
		if err != nil {
			t.Fatalf("with what it was told to change: %v", err)
		}
		if time.Duration(cfg.Discovery.Lifetime) != time.Hour || !cfg.Discovery.Solicit.IPv6 || !cfg.Discovery.Solicit.IPv4 || len(cfg.Webserver.Listen) != 1 {
			t.Errorf("as loaded: lifetime %s, solicit %+v, webserver %v", time.Duration(cfg.Discovery.Lifetime), cfg.Discovery.Solicit, cfg.Webserver.Listen)
		}
		// The one change no error tells of: its ipv4 block was IPv4 on, by being there, and now
		// says nothing of it. It is warned of, and off, until enabled is there.
		if cfg.Discovery.IPv4.Enabled {
			t.Error("IPv4 is on, with no enabled")
		}
		warned := strings.Join(cfg.Warnings, "\n")
		if !strings.Contains(warned, "discovery.ipv4 has") || !strings.Contains(warned, "no enabled: IPv4 is off") {
			t.Errorf("the ipv4 block without enabled isn't warned of: %q", cfg.Warnings)
		}
		cfg, err = load(change(upgraded, "  ipv4:\n", "  ipv4:\n    enabled: true\n"))
		if err != nil || !cfg.Discovery.IPv4.Enabled {
			t.Fatalf("with enabled: %v, IPv4 %t", err, cfg.Discovery.IPv4.Enabled)
		}
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "discovery.") {
				t.Errorf("still warned of: %s", w)
			}
		}
	})

	t.Run("the add-on's starting configuration", func(t *testing.T) {
		starter := read("v0.22.3.starter.config.yaml")
		// One thing at a time here: the device's key, then where it listens.
		_, err := load(starter)
		if err == nil || !strings.Contains(err.Error(), "homeassistant: the device needs its encryption key") || !strings.Contains(err.Error(), "key_provisioning: true") {
			t.Fatalf("as it is: %v", err)
		}
		keyed := change(starter, "homeassistant: {}", "homeassistant:\n  key_provisioning: true")
		_, err = load(keyed)
		if err == nil || !strings.Contains(err.Error(), "homeassistant.listen: where the device listens") {
			t.Fatalf("with the key's provisioning: %v", err)
		}
		cfg, err := load(change(keyed, "  key_provisioning: true", "  key_provisioning: true\n  listen: 6053"))
		if err != nil {
			t.Fatalf("with both, as the add-on's page says: %v", err)
		}
		// The state file it had is the one it reads: the device stays the same.
		if h := cfg.HomeAssistant; h == nil || !h.KeyProvisioning || h.KeyProvisioningStateFile != "homeassistant.state" {
			t.Errorf("the device: %+v", h)
		}
		// Nothing says the report's address is missing: the add-on's page has none until it is
		// added, which its documentation tells.
		if len(cfg.Webserver.Listen) != 0 {
			t.Errorf("the web server listens at %v, unasked", cfg.Webserver.Listen)
		}
	})
}
