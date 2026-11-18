package docgen

import (
	"flag"
	"os"
	"path/filepath"
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
