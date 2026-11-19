package docgen

import (
	"os"
	"path/filepath"
	"regexp"
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

// The add-on's starting configuration loads, and says nothing deprecated; and so does its example,
// uncommented.
func TestAddonStarterConfig(t *testing.T) {
	path := filepath.Join("..", "..", "homeassistant", "starter.config.yaml")
	// As the add-on's start leaves it: the key beside the configuration.
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "homeassistant.key"), []byte(esphome.GenerateKey()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	starter := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(starter, content, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.NewConfig(starter)
	if err != nil || len(cfg.Warnings) > 0 {
		t.Errorf("%v, warnings %v", err, cfg.Warnings)
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
// code. A block of a filter alone is taken as a task's; one of Docker Compose is left out.
func TestDocExamples(t *testing.T) {
	root := filepath.Join("..", "..")
	files := []string{"README.md", "CONTRIBUTING.md"}
	docs, _ := filepath.Glob(filepath.Join(root, "docs", "*.md"))
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
		for i, m := range yamlBlock.FindAllStringSubmatch(string(content), -1) {
			block := dedent(m[1])
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
			for _, ref := range envRef.FindAllStringSubmatch(block, -1) {
				t.Setenv(ref[1], "example")
			}
			// A file a ${file:...} names: beside the configuration when relative, with a key in a
			// key's, as the add-on makes it; an absolute one, a value.
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
			// The providers check their settings themselves; a form from before warns.
			for name, credential := range cfg.Credentials {
				if _, err := ddns.NewService(credential.Provider, credential.RawSettings); err != nil {
					t.Errorf("%s, example %d, credential %s: %v", file, i+1, name, err)
				}
			}
			if len(cfg.Warnings) > 0 {
				t.Errorf("%s, example %d: a deprecated form: %v", file, i+1, cfg.Warnings)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Error("no example found")
	}
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
