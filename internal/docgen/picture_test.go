package docgen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miguelangel-nubla/ipv6ddns/internal/reportpic"
	"github.com/miguelangel-nubla/ipv6disc/pkg/pretty"
)

// The README shows the report as a picture, with its colors, which a page of GitHub can't have
// in text: the picture is made of the report the README has as text, for the light and the dark
// theme. After changing that report, go test ./internal/docgen -update.
func TestReportPictureUpToDate(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, after, found := strings.Cut(string(readme), "<summary>The same report, as text</summary>\n\n```\n")
	report, _, closed := strings.Cut(after, "```\n")
	if !found || !closed {
		t.Fatal("the README has no report as text, under its picture")
	}
	page := reportpic.Roles(report)
	// A picture of one color would say nothing: the report of the README has every state.
	has := map[pretty.Role]bool{}
	for _, line := range page {
		for _, span := range line {
			has[span.Role] = true
		}
	}
	for _, role := range []pretty.Role{pretty.Heading, pretty.Name, pretty.Warn, pretty.Error, pretty.Detail} {
		if !has[role] {
			t.Errorf("the report of the README has nothing of the role %q", role.Class())
		}
	}
	for name, theme := range map[string]reportpic.Theme{"report-light.svg": reportpic.Light, "report-dark.svg": reportpic.Dark} {
		if !strings.Contains(string(readme), `"docs/images/`+name+`"`) {
			t.Errorf("the README doesn't show docs/images/%s", name)
		}
		path, want := filepath.Join("..", "..", "docs", "images", name), reportpic.SVG(page, theme)
		if *update {
			if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if got, err := os.ReadFile(path); err != nil || string(got) != want {
			t.Errorf("%s is behind the report of the README: go test ./internal/docgen -update", path)
		}
	}
}
