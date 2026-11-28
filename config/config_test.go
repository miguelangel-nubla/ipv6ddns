package config

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestNewConfig(t *testing.T) {
	// 1. Setup temporary directory
	tempDir := t.TempDir()

	// 2. Define a sample valid configuration content usage for verification

	// We need to match the schema requirements.
	// Let's create a minimal valid JSON string first to ensure we adhere to schema.json

	// Based on typical usage, let's construct a raw JSON that we know is valid
	// and serves as our source of truth.
	jsonContent := `{
  "tasks": {
    "my_task": {
      "filter": [
        {
          "ip": {
            "prefix": "2001:db8::/64"
          },
          "mac": {
            "address": "00:11:22:33:44:55"
          }
        }
      ],
      "endpoints": {
        "my_credential": [
          "sub.domain.com"
        ]
      }
    }
  },
  "credentials": {
    "my_credential": {
      "provider": "cloudflare",
      "debounce": "1s",
      "settings": {
        "api_token": "1234567890"
      }
    }
  }
}`

	yamlContent := `
tasks:
  my_task:
    filter:
      - ip:
          prefix: "2001:db8::/64"
        mac:
          address: "00:11:22:33:44:55"
    endpoints:
      my_credential:
        - sub.domain.com
credentials:
  my_credential:
    provider: cloudflare
    debounce: 1s
    settings:
      api_token: "1234567890"
`

	t.Run("Load JSON Config", func(t *testing.T) {
		jsonPath := filepath.Join(tempDir, "config.json")
		err := os.WriteFile(jsonPath, []byte(jsonContent), 0644)
		if err != nil {
			t.Fatalf("Failed to write json config: %v", err)
		}

		loadedConfig, err := NewConfig(jsonPath)
		if err != nil {
			t.Fatalf("NewConfig failed for JSON: %v", err)
		}

		if len(loadedConfig.Tasks) != 1 {
			t.Errorf("Expected 1 task, got %d", len(loadedConfig.Tasks))
		}
	})

	t.Run("Load YAML Config", func(t *testing.T) {
		yamlPath := filepath.Join(tempDir, "config.yaml")
		err := os.WriteFile(yamlPath, []byte(yamlContent), 0644)
		if err != nil {
			t.Fatalf("Failed to write yaml config: %v", err)
		}

		loadedConfig, err := NewConfig(yamlPath)
		if err != nil {
			t.Fatalf("NewConfig failed for YAML: %v", err)
		}

		if len(loadedConfig.Tasks) != 1 {
			t.Errorf("Expected 1 task, got %d", len(loadedConfig.Tasks))
		}

		if _, ok := loadedConfig.Tasks["my_task"]; !ok {
			t.Error("Expected 'my_task' to exist")
		}
	})

	t.Run("Load Config Plugins Map", func(t *testing.T) {
		yamlContent := `
tasks: {}
credentials: {}
discovery:
  plugins:
    mikrotik-lan:
      type: mikrotik
      interval: 60s
      address: 192.0.2.1
      username: admin
      password: secret
`
		path := filepath.Join(tempDir, "config_plugins.yaml")
		_ = os.WriteFile(path, []byte(yamlContent), 0644)

		cfg, err := NewConfig(path)
		if err != nil {
			t.Fatalf("NewConfig failed: %v", err)
		}

		if len(cfg.Discovery.Plugins) != 1 {
			t.Errorf("Expected 1 plugin, got %d", len(cfg.Discovery.Plugins))
		}
		if _, ok := cfg.Discovery.Plugins["mikrotik-lan"]; !ok {
			t.Error("Expected plugin 'mikrotik-lan'")
		}
	})

	t.Run("Load Config Nested Filters", func(t *testing.T) {
		yamlContent := `
tasks:
  new_task:
    filter:
      - mac:
          address: "00:11:22:33:44:66"
        ip:
          type:
            - "global"
            - "eui64"
          seen:
            - reported:
                by:
                  - "mikrotik"
    endpoints:
      creds:
        - "host"
credentials:
  creds:
    provider: test
    settings: {}
`
		path := filepath.Join(tempDir, "config_filters.yaml")
		_ = os.WriteFile(path, []byte(yamlContent), 0644)

		cfg, err := NewConfig(path)
		if err != nil {
			t.Fatalf("NewConfig failed: %v", err)
		}

		// Check filters
		task := cfg.Tasks["new_task"]
		if len(task.Filters) == 0 {
			t.Fatal("No filters found")
		}
		f := task.Filters[0]
		if f.MAC.Address != "00:11:22:33:44:66" {
			t.Error("Filter MAC mismatch")
		}
		if len(f.IP.Type) != 2 {
			t.Error("Filter IPType mismatch")
		}
		if len(f.IP.Seen) != 1 || f.IP.Seen[0].Reported == nil || f.IP.Seen[0].Reported.By[0] != "mikrotik" {
			t.Errorf("Filter Seen mismatch: %+v", f.IP.Seen)
		}
	})
}

func TestDurationPattern(t *testing.T) {
	config := func(d string) []byte {
		return []byte(`{"tasks": {}, "credentials": {"c": {"provider": "duckdns", "settings": {}, "debounce": "` + d + `"}}}`)
	}
	for _, d := range []string{"10s", "0", ".5s", "1h30m", "1.5m"} {
		if err := validateConfig(config(d)); err != nil {
			t.Errorf("%q: %v", d, err)
		}
	}
	for _, d := range []string{"10", "soon", "1d", "s", ".s", "ms"} {
		if err := validateConfig(config(d)); err == nil || !strings.Contains(err.Error(), "not a duration: write it as 90s") {
			t.Errorf("%q: want an error", d)
		}
	}
}

// A number of seconds is one written as a number: in quotes, or read from the environment, it
// is text, which needs its unit, as the reference says.
func TestDurationNumberOfSeconds(t *testing.T) {
	t.Setenv("IPV6DDNS_TEST_INTERVAL", "300")
	for interval, want := range map[string]string{
		"300":                        "",
		"300s":                       "",
		`"300"`:                      "sources.wan.interval: not a duration: write it as 90s, 1m30s or 1h",
		"${IPV6DDNS_TEST_INTERVAL}":  "sources.wan.interval: not a duration: write it as 90s, 1m30s or 1h",
		"${IPV6DDNS_TEST_INTERVAL}s": "",
	} {
		cfg, err := loadConfig(t, "tasks: {}\ncredentials: {}\nsources:\n  wan:\n    type: dns\n    interval: "+interval+"\n")
		switch {
		case want == "" && (err != nil || cfg.Sources["wan"].Interval.Duration != 5*time.Minute):
			t.Errorf("%s: %v, %v", interval, cfg.Sources["wan"].Interval, err)
		case want != "" && (err == nil || !strings.Contains(err.Error(), want)):
			t.Errorf("%s: got %v\nwant %s", interval, err, want)
		}
	}
	if !strings.Contains(string(configSchema), "or a number of seconds, written as a number: in quotes, or read from ${VAR}, it is text, and needs its unit, as 300s.") {
		t.Error("the schema's duration doesn't say that a number in quotes needs its unit")
	}
}

func TestNewConfigChecks(t *testing.T) {
	dir := t.TempDir()
	write := func(content string) string {
		path := filepath.Join(dir, "config.json")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	cfg, err := NewConfig(write(`{"tasks": {"web": {"endpoints": {"duck": ["www"]}}}, "credentials": {"duck": {"provider": "duckdns", "settings": {}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Tasks["web"].Name != "web" {
		t.Errorf("task name: got %q", cfg.Tasks["web"].Name)
	}
	if c := cfg.Credentials["duck"]; c.Debounce.Duration != 10*time.Second || c.Retry.Duration != time.Minute {
		t.Errorf("default times: %+v", c)
	}
	if d := cfg.Discovery; !d.IPv6.Enabled || !d.IPv6.Listen || !d.IPv6.Active || d.Solicit != (Solicit{}) || d.IPv4.Enabled {
		t.Errorf("discovery defaults: %+v", cfg.Discovery)
	}

	if _, err := NewConfig(write(`{"tasks": {"web": {"endpoints": {"nope": ["www"]}}}, "credentials": {}}`)); err == nil {
		t.Error("an endpoint with no credential: want an error")
	}
	if _, err := NewConfig(write(`{"tasks": {}, "credentials": {}, "unknown": 1}`)); err == nil {
		t.Error("an unknown key: want an error")
	}

	// A retry of nothing would try a failing provider again without a pause.
	credential := func(times string) string {
		return `{"tasks": {}, "credentials": {"duck": {"provider": "duckdns", "settings": {}, ` + times + `}}}`
	}
	for _, times := range []string{`"retry": 0`, `"retry": "0s"`, `"retry": "500ms"`, `"retry": "-1m"`, `"debounce": "-1s"`} {
		if _, err := NewConfig(write(credential(times))); err == nil {
			t.Errorf("%s: want an error", times)
		}
	}
	for _, times := range []string{`"retry": "1s"`, `"debounce": 0`, `"debounce": 0, "retry": 1`} {
		if _, err := NewConfig(write(credential(times))); err != nil {
			t.Errorf("%s: %v", times, err)
		}
	}
}

// Every setting of the schema says what it is: the configuration reference is made of them.
func TestSchemaDescribesEverything(t *testing.T) {
	var schema map[string]any
	if err := json.Unmarshal(configSchema, &schema); err != nil {
		t.Fatal(err)
	}
	var walk func(node any, path string)
	walk = func(node any, path string) {
		o, ok := node.(map[string]any)
		if !ok {
			return
		}
		if props, ok := o["properties"].(map[string]any); ok {
			for name, prop := range props {
				p, _ := prop.(map[string]any)
				// A plugin's params are described where they are defined: in ipv6disc.
				pluginParam := strings.HasSuffix(path, "Plugin") && name != "type" && name != "params"
				if _, ok := p["description"]; !ok && !pluginParam {
					t.Errorf("%s.%s: no description", path, name)
				}
				walk(prop, path+"."+name)
			}
		}
		for _, key := range []string{"additionalProperties", "items"} {
			walk(o[key], path+"[]")
		}
		for _, key := range []string{"oneOf", "anyOf", "allOf"} {
			alts, _ := o[key].([]any)
			for _, alt := range alts {
				walk(alt, path)
			}
		}
		if defs, ok := o["$defs"].(map[string]any); ok {
			for name, def := range defs {
				walk(def, "$defs."+name)
			}
		}
	}
	walk(schema, "")
}

// The defaults the schema's descriptions say are the code's: the reference is made of them.
func TestSchemaSaysTheDefaults(t *testing.T) {
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(configSchema, &schema); err != nil {
		t.Fatal(err)
	}
	description := func(path ...string) string {
		raw := schema.Properties[path[0]]
		for _, p := range path[1:] {
			var node map[string]json.RawMessage
			json.Unmarshal(raw, &node)
			raw = node[p]
		}
		var node struct {
			Description string `json:"description"`
		}
		json.Unmarshal(raw, &node)
		return node.Description
	}
	short := func(d time.Duration) string {
		switch {
		case d%time.Hour == 0:
			return fmt.Sprintf("%dh", d/time.Hour)
		case d%time.Minute == 0:
			return fmt.Sprintf("%dm", d/time.Minute)
		}
		return d.String()
	}

	var credential Credential
	if err := json.Unmarshal([]byte(`{"provider": "x", "settings": {}}`), &credential); err != nil {
		t.Fatal(err)
	}
	source, err := Source{Type: SourceDNS}.withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		path []string
		want string
	}{
		{[]string{"credentials", "additionalProperties", "properties", "debounce"}, "Default: " + short(credential.Debounce.Duration) + "."},
		{[]string{"credentials", "additionalProperties", "properties", "retry"}, "Default: " + short(credential.Retry.Duration) + "."},
		{[]string{"sources", "additionalProperties", "properties", "interval"}, "Default: " + short(source.Interval.Duration) + "."},
		{[]string{"sources", "additionalProperties", "properties", "lifetime"}, fmt.Sprintf("Default: %d intervals.", source.Lifetime.Duration/source.Interval.Duration)},
	} {
		if got := description(c.path...); !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, want it to say %q", strings.Join(c.path, "."), got, c.want)
		}
	}
}

// A key given twice in YAML is an error: the last one would win, and the first task's names, or
// credentials, be gone without a word.
func TestDuplicateKeysAreErrors(t *testing.T) {
	for name, content := range map[string]string{
		"two tasks of a name": "tasks:\n  web:\n    endpoints:\n      duck:\n        - www\n  web:\n    endpoints:\n      duck:\n        - other\n" + duckCredential,
		"two credentials":     "tasks: {}\n" + duckCredential + duckCredential,
		"a setting twice":     "tasks: {}\nlog_level: info\nlog_level: debug\n" + duckCredential,
	} {
		if _, err := loadConfig(t, content); err == nil || !strings.Contains(err.Error(), "already set in map") {
			t.Errorf("%s: got %v, want an error", name, err)
		}
	}
}

// A block with nothing under it, null in YAML, is an error by the schema: it would otherwise
// read as no block at all.
func TestEmptyBlocksAreErrors(t *testing.T) {
	for _, content := range []string{
		"tasks:\n" + duckCredential,
		"tasks: {}\nhomeassistant:\n" + duckCredential,
		"tasks: {}\ndiscovery:\n" + duckCredential,
		"tasks: {}\ndiscovery:\n  ipv6:\n" + duckCredential,
		"tasks: {}\ndiscovery:\n  ipv4:\n    lifetime:\n" + duckCredential,
		"tasks: {}\ndiscovery:\n  lifetime:\n" + duckCredential,
		"tasks: {}\ndiscovery:\n  protocols:\n    mdns:\n" + duckCredential,
		"tasks: {}\ndiscovery:\n  solicit:\n" + duckCredential,
	} {
		if _, err := loadConfig(t, content); err == nil || !strings.Contains(err.Error(), "not valid") {
			t.Errorf("%q: got %v, want an error", content, err)
		}
	}
}

// YAML is for .yaml and .yml: any other name is read as JSON.
func TestConfigFileNames(t *testing.T) {
	dir := t.TempDir()
	for name, yaml := range map[string]bool{"config.yaml": true, "config.yml": true, "config.json": false, "config.conf": false, "config.YAML": false} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("tasks: {}\ncredentials: {}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewConfig(path); (err == nil) != yaml {
			t.Errorf("%s: got %v, read as YAML: want %t", name, err, yaml)
		}
	}
}

// A name that YAML reads as a boolean, without quotes, is an error that says to quote it, and
// not the name true: a router sends hostname=y, a client signs with the key on. So is one read
// as another number than written. In quotes, or read as written, it is the name.
func TestNamesThatYAMLReadsAsSomethingElse(t *testing.T) {
	push := "    type: push\n    password: secret\n"
	for name, c := range map[string]struct{ config, want string }{
		"a source y":            {"sources:\n  y:\n" + push, `sources.y: YAML reads the name y, written without quotes, as the boolean true, and it would be named true: write it in quotes, as "y"`},
		"a source no":           {"sources:\n  no:\n" + push, `sources.no: YAML reads the name no, written without quotes, as the boolean false, and it would be named false: write it in quotes, as "no"`},
		"a source Off":          {"sources:\n  Off:\n" + push, `sources.Off: YAML reads the name Off, written without quotes, as the boolean false`},
		"a source 010":          {"sources:\n  010:\n" + push, `sources.010: YAML reads the name 010, written without quotes, as the number 8, and it would be named 8: write it in quotes, as "010"`},
		"a source 1.10":         {"sources:\n  1.10:\n" + push, `sources.1.10: YAML reads the name 1.10, written without quotes, as the number 1.1`},
		"a listener on":         {"listeners:\n  on:\n    listen:\n      - http://127.0.0.1:8054\nwebservers:\n  main:\n    listeners:\n      - on\n", `listeners.on: YAML reads the name on, written without quotes, as the boolean true`},
		"an endpoint of a task": {"tasks:\n  nas:\n    endpoints:\n      yes:\n        - nas\n", `tasks.nas.endpoints.yes: YAML reads the name yes, written without quotes, as the boolean true`},
		"a key under a list":    {"tasks:\n  nas:\n    filter:\n      - n: 1\n    endpoints:\n      duck:\n        - nas\n", `tasks.nas.filter.n: YAML reads the name n, written without quotes, as the boolean false`},
	} {
		content := c.config
		if !strings.Contains(content, "listeners:") {
			content += webServer
		}
		if !strings.Contains(content, "tasks:") {
			content += "tasks: {}\n"
		}
		if _, err := loadConfig(t, content+duckCredential); err == nil || !strings.HasPrefix(err.Error(), c.want) {
			t.Errorf("%s: got %v\nwant %s", name, err, c.want)
		}
	}

	cfg, err := loadConfig(t, "tasks: {}\n"+duckCredential+`
listeners:
  10:
    listen:
      - http://127.0.0.1:8053
  "on":
    listen:
      - http://127.0.0.1:8054
  2:
    listen:
      - http://127.0.0.1:8055
webservers:
  true:
    listeners:
      - 10
      - "on"
      - 2
sources:
  "y":
    type: push
    password: secret
  'no':
    type: push
    password: secret
  !!str yes:
    type: push
    password: secret
  7:
    type: push
    password: secret
  2001:
    type: dns
`)
	if err != nil {
		t.Fatal(err)
	}
	if got := slices.Sorted(maps.Keys(cfg.Sources)); !slices.Equal(got, []string{"2001", "7", "no", "y", "yes"}) {
		t.Errorf("the sources are %q", got)
	}
	if _, ok := cfg.Webservers["true"]; !ok {
		t.Errorf("the web server true, written so, is not: %v", cfg.Webservers)
	}
	// The order of the listeners, as written, with the names the reading has.
	if !slices.Equal(cfg.ListenerOrder, []string{"10", "on", "2"}) {
		t.Errorf("the listeners, in order: %q", cfg.ListenerOrder)
	}
	// JSON has no such reading: its names are text.
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"tasks": {}, "credentials": {}, "sources": {"y": {"type": "dns"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if cfg, err := NewConfig(path); err != nil || cfg.Sources["y"].Type != SourceDNS {
		t.Errorf("JSON's y: %v, %v", cfg.Sources, err)
	}
}
