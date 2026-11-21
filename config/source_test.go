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

// The ipv4 block of a task, from before sources, becomes a command source.
func TestIPv4BlockBecomesASource(t *testing.T) {
	cfg, err := loadConfig(t, `
tasks:
  web:
    ipv4:
      interval: 3m
      lifetime: 10m
      command: curl
      args:
        - -s
        - --ipv4
        - ifconfig.me
    endpoints:
      duck:
        - www
`+duckCredential)
	if err != nil {
		t.Fatal(err)
	}
	source, ok := cfg.Sources["web.ipv4"]
	if !ok || source.Type != SourceCommand || source.Command != "curl" || source.Interval.Duration != 3*time.Minute || source.Lifetime.Duration != 10*time.Minute || len(source.Args) != 3 {
		t.Errorf("source: %+v", source)
	}
	task := cfg.Tasks["web"]
	if task.IPv4 != nil || !slices.Equal(task.Sources, []string{"web.ipv4"}) {
		t.Errorf("task: %+v", task)
	}
	if len(cfg.Warnings) != 1 || !strings.Contains(cfg.Warnings[0], "deprecated") {
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
		// The ipv4 block is a source as any other, with its checks.
		"ipv4 block, lifetime under interval": {"tasks:\n  web:\n    ipv4:\n      interval: 5m\n      lifetime: 1m\n      command: x\n    endpoints:\n      duck:\n        - www\n", "source web.ipv4: invalid lifetime 1m0s: at least the interval"},
		"ipv4 block clashes":                  {"sources:\n  web.ipv4:\n    type: dns\ntasks:\n  web:\n    ipv4:\n      interval: 1m\n      lifetime: 3m\n      command: x\n    endpoints:\n      duck:\n        - www\n", "web.ipv4"},
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
