package docgen

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/ddns"
)

var (
	yamlBlock = regexp.MustCompile("(?s)```yaml\n(.*?)```")
	envRef    = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)
)

// Every configuration in the documentation loads: the examples stay true to the schema and the
// code. A block of a filter alone is taken as a task's; one of Docker Compose is left out.
func TestDocExamples(t *testing.T) {
	root := filepath.Join("..", "..")
	files := []string{"README.md", "CONTRIBUTING.md"}
	docs, _ := filepath.Glob(filepath.Join(root, "docs", "*.md"))
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
			block := m[1]
			if strings.HasPrefix(block, "services:") || strings.HasPrefix(block, "# compose.yaml") {
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
			// A file a ${file:...} names: one with a value.
			block = regexp.MustCompile(`\$\{file:[^}]*\}`).ReplaceAllString(block, "example")
			path := filepath.Join(t.TempDir(), "config.yaml")
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
