package config

import (
	"net"
	"strings"
	"testing"
)

func TestTemplate(t *testing.T) {
	mac, _ := net.ParseMAC("00:1A:2b:3c:4d:5e")
	for name, c := range map[string]struct {
		perHost bool
		want    string
	}{
		"{hostname}":            {false, "printer"},
		"{hostname}.lan":        {false, "printer.lan"},
		"{n}.{hostname}":        {true, "2.printer"},
		"{hostname}-{n}":        {true, "printer-2"},
		"{mac}":                 {true, "001a2b3c4d5e"},
		"{mac}.{hostname}.lan":  {true, "001a2b3c4d5e.printer.lan"},
		"*.{hostname}":          {false, "*.printer"},
		"{hostname}.{hostname}": {false, "printer.printer"},
	} {
		if !IsTemplate(name) {
			t.Errorf("%s: not a template", name)
		}
		template, err := ParseTemplate(name)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got := template.Expand("printer", 2, mac); got != c.want || template.PerHost() != c.perHost {
			t.Errorf("%s: %q, of one host %t; want %q, %t", name, got, template.PerHost(), c.want, c.perHost)
		}
	}
	for _, name := range []string{"nas", "", "*.nas", "nas.example.com"} {
		if IsTemplate(name) {
			t.Errorf("%q: a template", name)
		}
	}
	for name, want := range map[string]string{
		"{host}":         "{host} isn't a placeholder: use {hostname}, {n} or {mac}",
		"{Hostname}":     "{Hostname} isn't a placeholder",
		"{}":             "{} isn't a placeholder",
		"{n}":            "{n} numbers the hosts that share a name, so it needs {hostname} too, as {n}.{hostname}",
		"{n}.{mac}":      "so it needs {hostname} too",
		"{hostname":      "a brace that isn't part of a placeholder",
		"hostname}":      "a brace that isn't part of a placeholder",
		"{{hostname}}":   "a brace that isn't part of a placeholder",
		"{hostname}.{x}": "{x} isn't a placeholder",
	} {
		if !IsTemplate(name) {
			t.Errorf("%s: not seen as a template, and so not refused", name)
		}
		if _, err := ParseTemplate(name); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want an error with %q", name, err, want)
		}
	}
}

// noNames turns off, under discovery.protocols, every protocol that learns names.
const noNames = "    mdns:\n      enabled: false\n    dhcp:\n      enabled: false\n    lldp:\n      enabled: false\n    netbios:\n      enabled: false\n    llmnr:\n      enabled: false\n    ssdp:\n      names: false\n    wsd:\n      names: false\n"

// A task's name that is a template is checked as the configuration loads: its placeholders, and
// that the hosts' names are learned when it takes them.
func TestTemplatesOfTheConfiguration(t *testing.T) {
	task := func(names ...string) string {
		return "tasks:\n  lan:\n    filter:\n      - ip:\n          type:\n            - ula\n    endpoints:\n      duck:\n        - " + strings.Join(names, "\n        - ") + "\n" + duckCredential
	}
	const named = ""
	cfg, err := loadConfig(t, named+task(`"{hostname}"`, `"{n}.{hostname}"`, `"{mac}"`, "nas"))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Tasks["lan"].Endpoints["duck"]; len(got) != 4 || got[0] != "{hostname}" {
		t.Errorf("the names: %q", got)
	}
	// The host's MAC is no name of its: it needs no names learned.
	if _, err := loadConfig(t, task(`"{mac}.lan"`)); err != nil {
		t.Errorf("{mac} alone, without the names: %v", err)
	}
	for name, c := range map[string]struct{ config, want string }{
		"the names not learned": {"discovery:\n  protocols:\n" + noNames + task(`"{hostname}"`),
			`task lan: endpoint duck: the name "{hostname}" uses the hosts' names, but nothing learns them: turn on a protocol under discovery.protocols that does, as mdns, or add a plugin`},
		"no placeholder":           {named + task(`"{host}"`), `task lan: endpoint duck: the name "{host}": {host} isn't a placeholder: use {hostname}, {n} or {mac}`},
		"a place without the name": {named + task(`"{n}.lan"`), `the name "{n}.lan": {n} numbers the hosts that share a name`},
		"a brace alone":            {named + task(`"nas}"`), `the name "nas}": a brace that isn't part of a placeholder`},
	} {
		if _, err := loadConfig(t, c.config); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want an error with %q", name, err, c.want)
		}
	}
}

// A resolver's zone doesn't have a template among the names its tasks publish: its names are
// given as the hosts are.
func TestTemplateIsNoNameOfAZone(t *testing.T) {
	cfg, err := loadConfig(t, `
listeners:
  lan:
    listen:
      - dns://192.168.1.0/24
resolvers:
  lan:
    listeners:
      - lan
    upstream: 192.168.1.1
credentials:
  home:
    provider: resolver
    settings:
      zone: home.arpa
      records:
        - printer A 192.168.1.20
tasks:
  lan:
    filter:
      - ip:
          type:
            - ula
    endpoints:
      home:
        - "{hostname}"
        - "{n}.{hostname}"
        - nas
`)
	if err != nil {
		t.Fatal(err)
	}
	tasks := cfg.Resolvers["lan"].Spec.Zones[0].Tasks
	if len(tasks) != 1 || tasks["nas.home.arpa."] != "lan" {
		t.Errorf("the zone's names of the tasks: %v", tasks)
	}
}
