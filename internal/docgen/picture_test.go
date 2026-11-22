package docgen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miguelangel-nubla/ipv6ddns/internal/reportpic"
	"github.com/miguelangel-nubla/ipv6disc/pkg/pretty"
)

// The pages show the report as pictures, with its colors, which a page of GitHub can't have in
// text. Each picture is drawn from a report kept as text beside it, in docs/images, for the light
// and the dark theme, and the page has both. After changing a report's text,
// go test ./internal/docgen -update.
func TestReportPicturesUpToDate(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, picture := range []struct {
		name, page, from string
		// The roles the picture has: one of a single color would say nothing.
		roles []pretty.Role
	}{
		{"report", "README.md", "docs/images/", []pretty.Role{pretty.Heading, pretty.Name, pretty.Warn, pretty.Error, pretty.Detail}},
		{"resolvers", "docs/resolver.md", "images/", []pretty.Role{pretty.Heading, pretty.Name, pretty.OK, pretty.Warn, pretty.Detail}},
	} {
		text, err := os.ReadFile(filepath.Join(root, "docs", "images", picture.name+".txt"))
		if err != nil {
			t.Fatal(err)
		}
		shown, err := os.ReadFile(filepath.Join(root, picture.page))
		if err != nil {
			t.Fatal(err)
		}
		page := reportpic.Roles(string(text))
		has := map[pretty.Role]bool{}
		for _, line := range page {
			for _, span := range line {
				has[span.Role] = true
			}
		}
		for _, role := range picture.roles {
			if !has[role] {
				t.Errorf("%s.txt has nothing of the role %q", picture.name, role.Class())
			}
		}
		for suffix, theme := range map[string]reportpic.Theme{"-light.svg": reportpic.Light, "-dark.svg": reportpic.Dark} {
			name := picture.name + suffix
			if !strings.Contains(string(shown), `"`+picture.from+name+`"`) {
				t.Errorf("%s doesn't show %s%s", picture.page, picture.from, name)
			}
			path, want := filepath.Join(root, "docs", "images", name), reportpic.SVG(page, theme)
			if *update {
				if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
					t.Fatal(err)
				}
				continue
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != want {
				t.Errorf("%s is behind %s.txt: go test ./internal/docgen -update", path, picture.name)
			}
		}
	}
}
