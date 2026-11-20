package docgen

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "write the pages")

// The pages in the repository are those the schemas make: after changing a schema,
// go test ./internal/docgen -update.
func TestPagesUpToDate(t *testing.T) {
	pages, err := Pages()
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range pages {
		path = filepath.Join("..", "..", path)
		if *update {
			if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if got, err := os.ReadFile(path); err != nil || string(got) != want {
			t.Errorf("%s is behind the schemas: go test ./internal/docgen -update", path)
		}
	}
}

// The descriptions are ipv6disc's, read by the users of both: what is true of one program's image
// only, as ipv6disc's having no CAs, belongs in its documentation, not in them.
func TestPluginFieldDescriptionsAreOfNoImage(t *testing.T) {
	for _, def := range pluginDefs {
		described, err := PluginFieldDescriptions(def.pluginType)
		if err != nil {
			t.Fatal(err)
		}
		for name, description := range described {
			if strings.Contains(description, "Docker image") {
				t.Errorf("%s %s: %q is of ipv6disc's image", def.pluginType, name, description)
			}
		}
	}
}
