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
		"{host}":         "{host} is no placeholder: they are {hostname}, {n} and {mac}",
		"{Hostname}":     "{Hostname} is no placeholder",
		"{}":             "{} is no placeholder",
		"{n}":            "{n} is the place of a host among those of one name: it needs {hostname} beside it, as {n}.{hostname}",
		"{n}.{mac}":      "it needs {hostname} beside it",
		"{hostname":      "a brace that is of no placeholder",
		"hostname}":      "a brace that is of no placeholder",
		"{{hostname}}":   "a brace that is of no placeholder",
		"{hostname}.{x}": "{x} is no placeholder",
	} {
		if !IsTemplate(name) {
			t.Errorf("%s: not seen as a template, and so not refused", name)
		}
		if _, err := ParseTemplate(name); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want an error with %q", name, err, want)
		}
	}
}

// A task's name that is a template is checked as the configuration loads: its placeholders, and
// that the hosts' names are learned when it takes them.
func TestTemplatesOfTheConfiguration(t *testing.T) {
	task := func(names ...string) string {
		return "tasks:\n  lan:\n    filter:\n      - ip:\n          type:\n            - ula\n    endpoints:\n      duck:\n        - " + strings.Join(names, "\n        - ") + "\n" + duckCredential
	}
	const named = "discovery:\n  hostnames:\n    enabled: true\n"
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
		"the names not learned":    {task(`"{hostname}"`), `task lan: endpoint duck: the name "{hostname}" is of the hosts' names, which aren't learned: it needs enabled: true under discovery.hostnames, and a protocol that learns them, as mdns`},
		"the names switched off":   {"discovery:\n  hostnames:\n    enabled: false\n" + task(`"{n}.{hostname}"`), "which aren't learned"},
		"no placeholder":           {named + task(`"{host}"`), `task lan: endpoint duck: the name "{host}": {host} is no placeholder: they are {hostname}, {n} and {mac}`},
		"a place without the name": {named + task(`"{n}.lan"`), `the name "{n}.lan": {n} is the place of a host among those of one name`},
		"a brace alone":            {named + task(`"nas}"`), `the name "nas}": a brace that is of no placeholder`},
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
discovery:
  hostnames:
    enabled: true
resolvers:
  lan:
    listen: 192.168.1.0/24
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
