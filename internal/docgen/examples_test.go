package docgen

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/ddns"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/esphome"
	"sigs.k8s.io/yaml"
)

var (
	yamlBlock = regexp.MustCompile("(?s)```yaml\n(.*?)```")
	envRef    = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)
)

// The add-on's starting configuration loads, and warns of nothing: its device is one
// Home Assistant gives the key, kept in the add-on's folder, which stays. And so does its example,
// uncommented.
func TestAddonStarterConfig(t *testing.T) {
	path := filepath.Join("..", "..", "homeassistant", "starter.config.yaml")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// As the add-on's start leaves it: alone in its folder.
	starter := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(starter, content, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.NewConfig(starter)
	if err != nil || len(cfg.Warnings) > 0 {
		t.Fatalf("%v, warnings %v", err, cfg.Warnings)
	}
	if h := cfg.HomeAssistant; h == nil || !h.KeyProvisioning || h.Key != "" || h.KeyProvisioningStateFile != "homeassistant.state" {
		t.Errorf("the device isn't one Home Assistant gives the key, kept in homeassistant.state: %+v", h)
	}

	// The add-on's page is served where Home Assistant's Supervisor asks for it, at the port the
	// add-on says is its ingress: the starting configuration says so, as nothing else does.
	if !slices.Equal(cfg.Webserver.Listen, []string{"172.30.32.1:8053"}) || cfg.LogLevel != "info" {
		t.Errorf("the starting configuration serves the report at %v, and logs at %q", cfg.Webserver.Listen, cfg.LogLevel)
	}
	addon, err := os.ReadFile(filepath.Join("..", "..", "homeassistant", "addon", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	// No option of its own, and so neither key: CI's linter of add-ons takes one that says its
	// default, as options: {}, for an error.
	var manifest map[string]any
	if err := yaml.Unmarshal(addon, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest["ingress"] != true || manifest["ingress_port"] != float64(8053) {
		t.Errorf("the add-on's page: ingress %v at %v, want it at 8053", manifest["ingress"], manifest["ingress_port"])
	}
	for _, key := range []string{"options", "schema"} {
		if value, ok := manifest[key]; ok {
			t.Errorf("the add-on has %s, %v: it has no option of its own, and an empty one fails the linter", key, value)
		}
	}
	if _, err := os.Stat(filepath.Join("..", "..", "homeassistant", "addon", "translations")); err == nil {
		t.Error("the add-on has translations, of options it doesn't have")
	}
	// And the add-on's start gives the program its file, and nothing else: no flag there is none of.
	run, err := os.ReadFile(filepath.Join("..", "..", "homeassistant", "run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(run), "\nexec ipv6ddns --config \"$config\"\n") {
		t.Errorf("the add-on starts the program otherwise than with its file:\n%s", run)
	}
	// And its documentation has the lines a configuration from before needs, as the starting one has them.
	docs, err := os.ReadFile(filepath.Join("..", "..", "homeassistant", "addon", "DOCS.md"))
	if err != nil {
		t.Fatal(err)
	}
	const lines = "webserver:\n  listen: 172.30.32.1:8053\n"
	if !strings.Contains(string(docs), "```yaml\n"+lines+"```") || !strings.Contains(string(content), "\n"+lines) {
		t.Errorf("the add-on's documentation, or its starting configuration, doesn't have the lines of its page:\n%s", lines)
	}

	// The example: the commented lines after the one that ends with "At Cloudflare:", up to the
	// end of the comment.
	var example []string
	in := false
	for _, line := range strings.Split(string(content), "\n") {
		switch {
		case strings.HasSuffix(line, "Cloudflare:"):
			in = true
		case in && strings.HasPrefix(line, "#"):
			example = append(example, strings.TrimPrefix(strings.TrimPrefix(line, "#"), " "))
		case in:
			in = false
		}
	}
	if len(example) < 10 {
		t.Fatalf("no example found: %q", example)
	}

	uncommented := filepath.Join(t.TempDir(), "config.yaml")
	text := strings.ReplaceAll(strings.Join(example, "\n"), "${file:/config/cloudflare_token}", "example")
	if err := os.WriteFile(uncommented, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = config.NewConfig(uncommented)
	if err != nil || len(cfg.Warnings) > 0 {
		t.Errorf("the example, uncommented: %v, warnings %v\n%s", err, cfg.Warnings, text)
	}
}

// Every configuration in the documentation loads: the examples stay true to the schema and the
// code. A block of a filter alone is taken as a task's; one of Docker Compose is left out; and one
// that starts with addedMark, as a guide adds a part to its configuration, is merged into the last
// whole one of its page, and loads with it.
func TestDocExamples(t *testing.T) {
	root := filepath.Join("..", "..")
	files := []string{"README.md", "CONTRIBUTING.md"}
	docs, _ := filepath.Glob(filepath.Join(root, "docs", "*.md"))
	guides, _ := filepath.Glob(filepath.Join(root, "docs", "guides", "*.md"))
	addonGuides, _ := filepath.Glob(filepath.Join(root, "docs", "guides", "*", "*.md"))
	docs = append(append(docs, guides...), addonGuides...)
	addon, _ := filepath.Glob(filepath.Join(root, "homeassistant", "addon", "*.md"))
	docs = append(docs, addon...)
	for _, d := range docs {
		rel, _ := filepath.Rel(root, d)
		files = append(files, rel)
	}
	checked := 0
	for _, file := range files {
		content, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			t.Fatal(err)
		}
		var whole string // the last whole configuration of the page
		for i, m := range yamlBlock.FindAllStringSubmatch(string(content), -1) {
			block := dedent(m[1])
			if strings.HasPrefix(block, addedMark) {
				if whole == "" {
					t.Errorf("%s, example %d: %s, and there is no configuration above it", file, i+1, addedMark)
					continue
				}
				merged, err := mergeYAML(whole, block)
				if err != nil {
					t.Errorf("%s, example %d: %v\n%s", file, i+1, err, block)
					continue
				}
				block = merged
			} else if regexp.MustCompile(`(?m)^(tasks|credentials):`).MatchString(block) {
				whole = block
			}
			if strings.HasPrefix(block, "services:") || strings.HasPrefix(block, "# compose.yaml") {
				continue
			}
			// Home Assistant's: YAML that reads, which Home Assistant checks itself.
			if strings.HasPrefix(block, "# Home Assistant") {
				var v any
				if err := yaml.Unmarshal([]byte(block), &v); err != nil {
					t.Errorf("%s, example %d, Home Assistant's: %v\n%s", file, i+1, err, block)
				}
				continue
			}
			if strings.HasPrefix(block, "filter:") {
				block = "tasks:\n  example:\n    endpoints: {}\n" + indent(block, "    ")
			}
			if !regexp.MustCompile(`(?m)^tasks:`).MatchString(block) {
				block += "\ntasks: {}\n"
			}
			if !regexp.MustCompile(`(?m)^credentials:`).MatchString(block) {
				block += "\ncredentials: {}\n"
			}
			// A variable of the environment: a value, or a key in a key's.
			for _, ref := range envRef.FindAllStringSubmatch(block, -1) {
				value := "example"
				if strings.HasSuffix(ref[1], "_KEY") {
					value = esphome.GenerateKey()
				}
				if ref[1] == "duckdns_token" {
					value = "01234567-89ab-cdef-0123-456789abcdef"
				}
				t.Setenv(ref[1], value)
			}
			// A file a ${file:...} names: beside the configuration when relative, with a key in a
			// key's, as the add-on makes it, and a token of DuckDNS's form in DuckDNS's; an absolute
			// one, a value.
			dir := t.TempDir()
			for _, ref := range regexp.MustCompile(`\$\{file:([^}]*)\}`).FindAllStringSubmatch(block, -1) {
				if filepath.IsAbs(ref[1]) {
					block = strings.ReplaceAll(block, ref[0], "example")
					continue
				}
				value := "example"
				if strings.HasSuffix(ref[1], ".key") {
					value = esphome.GenerateKey()
				}
				if ref[1] == "duckdns_token" {
					value = "01234567-89ab-cdef-0123-456789abcdef"
				}
				if err := os.WriteFile(filepath.Join(dir, ref[1]), []byte(value+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(path, []byte(block), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.NewConfig(path)
			if err != nil {
				t.Errorf("%s, example %d: %v\n%s", file, i+1, err, block)
				continue
			}
			// The providers check their settings themselves; what does nothing warns.
			for name, credential := range cfg.Credentials {
				if _, err := ddns.NewService(credential.Provider, credential.RawSettings); err != nil {
					t.Errorf("%s, example %d, credential %s: %v", file, i+1, name, err)
				}
			}
			if len(cfg.Warnings) > 0 {
				t.Errorf("%s, example %d: warnings: %v", file, i+1, cfg.Warnings)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Error("no example found")
	}
}

// addedMark starts an example that adds to the configuration above it, in a guide.
const addedMark = "# Added to the configuration above"

// mergeYAML is base with added's keys put in, a mapping's into the mapping of the same key, and
// anything else in place of base's.
func mergeYAML(base, added string) (string, error) {
	var b, a map[string]any
	if err := yaml.Unmarshal([]byte(base), &b); err != nil {
		return "", err
	}
	if err := yaml.Unmarshal([]byte(added), &a); err != nil {
		return "", err
	}
	out, err := yaml.Marshal(mergeMaps(b, a))
	return string(out), err
}

func mergeMaps(base, added map[string]any) map[string]any {
	if base == nil {
		base = map[string]any{}
	}
	for k, v := range added {
		if am, ok := v.(map[string]any); ok {
			if bm, ok := base[k].(map[string]any); ok {
				base[k] = mergeMaps(bm, am)
				continue
			}
		}
		base[k] = v
	}
	return base
}

func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		if l != "" {
			lines[i] = prefix + l
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

// dedent takes off the indentation all of a block's lines have, as a block in a list item's.
func dedent(block string) string {
	lines := strings.Split(block, "\n")
	common := -1
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		n := len(l) - len(strings.TrimLeft(l, " "))
		if common < 0 || n < common {
			common = n
		}
	}
	for i, l := range lines {
		if len(l) >= common && common > 0 {
			lines[i] = l[common:]
		}
	}
	return strings.Join(lines, "\n")
}
