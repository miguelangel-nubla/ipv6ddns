package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func loadConfig(t *testing.T, content string) (Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return NewConfig(path)
}

const duckCredential = `
credentials:
  duck:
    provider: duckdns
    settings: {}
`

// webServer is a web server, main, on a listener of its own, web.
const webServer = `
listeners:
  web:
    listen:
      - http://127.0.0.1:8053
webservers:
  main:
    listeners:
      - web
`

func TestSources(t *testing.T) {
	cfg, err := loadConfig(t, `
sources:
  wan:
    type: dns
  both:
    type: http
    family:
      - 4
      - 6
    interval: 1m
  fixed:
    type: static
    addresses:
      - 2001:db8::1
      - 192.0.2.1
tasks:
  web:
    sources:
      - wan
      - fixed
    endpoints:
      duck:
        - www
`+duckCredential)
	if err != nil {
		t.Fatal(err)
	}
	wan := cfg.Sources["wan"]
	if !slices.Equal(wan.Family, []int{4}) || wan.Interval.Duration != 5*time.Minute || wan.Lifetime.Duration != 15*time.Minute {
		t.Errorf("wan defaults: %+v", wan)
	}
	if both := cfg.Sources["both"]; both.Lifetime.Duration != 3*time.Minute {
		t.Errorf("both: lifetime %s, want 3 intervals", both.Lifetime)
	}
	if fixed := cfg.Sources["fixed"]; fixed.Lifetime.Duration < fixed.Interval.Duration {
		t.Errorf("fixed: %+v", fixed)
	}
	if got := cfg.Tasks["web"].Sources; !slices.Equal(got, []string{"wan", "fixed"}) {
		t.Errorf("task sources: %v", got)
	}
	if len(cfg.Warnings) != 0 {
		t.Errorf("warnings: %v", cfg.Warnings)
	}
}

func TestInvalidSources(t *testing.T) {
	for name, tt := range map[string]struct{ config, want string }{
		"unknown type":             {"sources:\n  s:\n    type: ftp\n", "type"},
		"invalid family":           {"sources:\n  s:\n    type: dns\n    family:\n      - 5\n", "family"},
		"family of a command":      {"sources:\n  s:\n    type: command\n    command: x\n    family:\n      - 4\n", "family"},
		"urls of a dns source":     {"sources:\n  s:\n    type: dns\n    urls:\n      - https://example.com\n", "urls"},
		"command without command":  {"sources:\n  s:\n    type: command\n", "command"},
		"static without addresses": {"sources:\n  s:\n    type: static\n", "addresses"},
		"static invalid address":   {"sources:\n  s:\n    type: static\n    addresses:\n      - nope\n", "nope"},
		"lifetime under interval":  {"sources:\n  s:\n    type: dns\n    interval: 10m\n    lifetime: 1m\n", "lifetime"},
		"unknown setting":          {"sources:\n  s:\n    type: dns\n    intreval: 1m\n", "intreval"},
		"no such source":           {"tasks:\n  web:\n    sources:\n      - nope\n    endpoints:\n      duck:\n        - www\n", "no source nope"},
		// A key of another type of source would be ignored without a word.
		"addresses of an http source":  {"sources:\n  s:\n    type: http\n    addresses:\n      - 192.0.2.1\n", "source s: addresses is only for static sources, and this one's type is http, which doesn't read it: leave it out, or make the type static"},
		"command of a dns source":      {"sources:\n  s:\n    type: dns\n    command: ./wan.sh\n", "source s: command is only for command sources"},
		"entity of an http source":     {"sources:\n  s:\n    type: http\n    entity: sensor.wan_ip\n", "source s: entity is only for homeassistant sources"},
		"urls of a command source":     {"sources:\n  s:\n    type: command\n    command: x\n    urls:\n      - https://example.com\n", "source s: urls is only for http sources, and this one's type is command"},
		"args of a static source":      {"sources:\n  s:\n    type: static\n    addresses:\n      - 192.0.2.1\n    args:\n      - x\n", "source s: args is only for command sources"},
		"attribute of a static source": {"sources:\n  s:\n    type: static\n    addresses:\n      - 192.0.2.1\n    attribute: x\n", "source s: attribute is only for homeassistant sources"},
		"interval of a static source":  {"sources:\n  s:\n    type: static\n    addresses:\n      - 192.0.2.1\n    interval: 10s\n", "source s: a static source has no interval nor lifetime"},
		"lifetime of a static source":  {"sources:\n  s:\n    type: static\n    addresses:\n      - 192.0.2.1\n    lifetime: 20s\n", "source s: a static source has no interval nor lifetime"},
		"addresses of a push source":   {"sources:\n  s:\n    type: push\n    password: x\n    addresses:\n      - 192.0.2.1\n" + webServer, "source s: addresses is only for static sources, and this one's type is push"},
		"urls of a push source":        {"sources:\n  s:\n    type: push\n    password: x\n    urls:\n      - https://example.com\n" + webServer, "source s: urls is only for http sources"},
		"command of a push source":     {"sources:\n  s:\n    type: push\n    password: x\n    command: x\n" + webServer, "source s: command is only for command sources"},
		"interval of a push source":    {"sources:\n  s:\n    type: push\n    password: x\n    interval: 1m\n" + webServer, "source s: a push source has no family nor interval"},
		"password of a dns source":     {"sources:\n  s:\n    type: dns\n    password: x\n", "source s: password and state_file are only for push sources"},
		// A lifetime has the least the other types' has.
		"a push lifetime under 1s": {"sources:\n  s:\n    type: push\n    password: x\n    lifetime: 1ns\n" + webServer, "source s: lifetime 1ns is too short: the least is 1s"},
		"an interval under 1s":     {"sources:\n  s:\n    type: dns\n    interval: 0.5\n", "source s: interval 500ms is too short: the least is 1s"},
	} {
		content := tt.config
		if !strings.Contains(content, "tasks:") {
			content += "tasks: {}\n"
		}
		_, err := loadConfig(t, content+duckCredential)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: got %v, want an error with %q", name, err, tt.want)
		}
	}
}

func TestFamilyFilter(t *testing.T) {
	cfg, err := loadConfig(t, `
tasks:
  lan:
    filter:
      - ip:
          family:
            - 4
          type:
            - private
    endpoints:
      duck:
        - nas
`+duckCredential)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Tasks["lan"].Filters[0].IP.Family; !slices.Equal(got, []int{4}) {
		t.Errorf("family: %v", got)
	}
	if _, err := loadConfig(t, "tasks:\n  lan:\n    filter:\n      - ip:\n          family:\n            - 5\n    endpoints:\n      duck:\n        - nas\n"+duckCredential); err == nil {
		t.Error("family 5: want an error")
	}
}

// The report hides what of a source can hold a token: a command's arguments, and all of an http
// source's urls but their scheme and host.
func TestSourceDescribeHides(t *testing.T) {
	http := Source{Type: SourceHTTP, Family: []int{4}, URLs: []string{"https://user:pw@echo.example:8443/ip/SECRETPATH?token=SECRETTOKEN#f", "http://[2001:db8::1]/x", "https:///nohost?token=SECRETTOKEN"}}
	http.Interval.Duration, http.Lifetime.Duration = 5*time.Minute, 15*time.Minute

	if got, want := http.describe(true), "http, IPv4, from https://echo.example:8443, http://[2001:db8::1], <sensible data hidden>, every 5m0s, kept 15m0s"; got != want {
		t.Errorf("hidden: got %q, want %q", got, want)
	}
	if got := http.describe(false); !strings.Contains(got, "from "+strings.Join(http.URLs, ", ")) {
		t.Errorf("shown: got %q", got)
	}

	command := Source{Type: SourceCommand, Command: "curl", Args: []string{"https://example.com/ip?key=SECRETTOKEN"}}
	if got := command.describe(true); strings.Contains(got, "SECRETTOKEN") || !strings.Contains(got, "curl") {
		t.Errorf("command, hidden: got %q", got)
	}
	if got := command.describe(false); !strings.Contains(got, "SECRETTOKEN") {
		t.Errorf("command, shown: got %q", got)
	}
}

// Each type of source loads with every key that is its own.
func TestSourceKeysOfItsType(t *testing.T) {
	cfg, err := loadConfig(t, "tasks: {}\n"+duckCredential+webServer+`
homeassistant:
  key: MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=
  listen:
    - 127.0.0.1
sources:
  http:
    type: http
    family:
      - 6
    interval: 1m
    lifetime: 2m
    urls:
      - https://echo.example
  dns:
    type: dns
    family:
      - 4
    interval: 1m
    lifetime: 2m
  command:
    type: command
    command: ./wan.sh
    args:
      - x
    interval: 1m
    lifetime: 2m
  static:
    type: static
    addresses:
      - 192.0.2.1
  homeassistant:
    type: homeassistant
    entity: sensor.wan_ip
    attribute: ip
    interval: 1m
    lifetime: 2m
  push:
    type: push
    password: secret
    state_file: wan.json
    lifetime: 1h
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Sources) != len(sourceKeys) {
		t.Errorf("%d sources, of %d types", len(cfg.Sources), len(sourceKeys))
	}
}

// A push source's name is the hostname a router sends, where a comma separates several and the
// spaces around each are left out, and in the name of its file: one that can be neither is an
// error, and the names of the pages are none.
func TestPushSourceNames(t *testing.T) {
	for _, name := range []string{`"a,b"`, `"../../etc/x"`, `" wan"`, `"wan "`, `"a/b"`, `'a\b'`, `"."`, `".."`} {
		_, err := loadConfig(t, "tasks: {}\ncredentials: {}\n"+webServer+"sources:\n  "+name+":\n    type: push\n    password: one\n")
		if err == nil || !strings.HasPrefix(err.Error(), "sources: the name ") || !strings.Contains(err.Error(), "use one without a comma, a slash or a space around it, as wan") {
			t.Errorf("the push source %s: %v", name, err)
		}
	}
	for _, name := range []string{"wan", "vps", "WAN-2", "wan_fiber", "wan.example.com", "home router", "casa-ñ"} {
		if _, err := loadConfig(t, "tasks: {}\ncredentials: {}\n"+webServer+"sources:\n  "+name+":\n    type: push\n    password: one\n"); err != nil {
			t.Errorf("the push source %s: %v", name, err)
		}
	}
	// A source of another type has no file, and no router names it.
	if _, err := loadConfig(t, "tasks: {}\ncredentials: {}\nsources:\n  \"a,b\":\n    type: dns\n"); err != nil {
		t.Errorf("a dns source a,b: %v", err)
	}
}

// Two push sources with one file would each read the other's addresses at a restart: by their
// state_file, by one's and the other's default, however written, and by names of one file where
// the file system doesn't tell their case apart.
func TestPushSourcesOneStateFile(t *testing.T) {
	push := func(name, stateFile string) string {
		s := "  " + name + ":\n    type: push\n    password: " + name + "\n"
		if stateFile != "" {
			s += "    state_file: " + stateFile + "\n"
		}
		return s
	}
	for name, c := range map[string]struct{ sources, want string }{
		"one state_file":            {push("a", "push.json") + push("b", "push.json"), "sources.b.state_file: push.json is the file of the push source a too"},
		"the default of another":    {push("a", "") + push("b", "push-a.json"), "sources.b.state_file: push-a.json is the file of the push source a too"},
		"written another way":       {push("a", "state/../push.json") + push("b", "./push.json"), "sources.b.state_file: ./push.json is the file of the push source a too"},
		"names that differ by case": {push("WAN", "") + push("wan", ""), "sources.wan: its file, push-wan.json, is the file of the push source WAN too"},
	} {
		_, err := loadConfig(t, "tasks: {}\ncredentials: {}\n"+webServer+"sources:\n"+c.sources)
		if err == nil || !strings.HasPrefix(err.Error(), c.want) || !strings.Contains(err.Error(), "give one of them a file of its own, as state_file: ") {
			t.Errorf("%s: got %v\nwant %s", name, err, c.want)
		}
	}
	// With state_dir, relative to it; and a file each is fine.
	if _, err := loadConfig(t, "tasks: {}\ncredentials: {}\nstate_dir: state\n"+webServer+"sources:\n"+push("a", "push.json")+push("b", "../push.json")+push("c", "")); err != nil {
		t.Errorf("a file each: %v", err)
	}
	if _, err := loadConfig(t, "tasks: {}\ncredentials: {}\nstate_dir: state\n"+webServer+"sources:\n"+push("a", "push.json")+push("b", "../state/push.json")); err == nil {
		t.Error("one file, relative to state_dir: accepted")
	}
}
