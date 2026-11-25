package docgen

import (
	"os"
	"path/filepath"
	"regexp"
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
		// The README shows a report where everything works: in green, not red.
		{"report", "README.md", "docs/images/", []pretty.Role{pretty.Heading, pretty.Name, pretty.OK, pretty.Detail}},
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

// The picture of how ipv6ddns works is a drawing, not a report: the light one is edited, and the
// dark one is it, each color of its style in its dark one, as the report's pictures have them
// where they have the same. Colors in the style alone, of plain values, which every viewer of SVG
// draws. Both are shown, on the README, on how-it-works and in the app's docs. After changing
// the light one, go test ./internal/docgen -update.
func TestArchitecturePicture(t *testing.T) {
	root := filepath.Join("..", "..")
	// Of the light picture: its ground, its boxes, the box of ipv6ddns, the borders, the text, the
	// headings, the names, the details, the arrows, and what an address loses and gains.
	dark := map[string]string{
		reportpic.Light.Ground: reportpic.Dark.Ground, "#f6f8fa": "#1a2029", "#eef4ff": "#16213a",
		reportpic.Light.Border: reportpic.Dark.Border, reportpic.Light.Text: reportpic.Dark.Text,
		"#0d1117": reportpic.Dark.Roles[pretty.Heading], reportpic.Light.Roles[pretty.Name]: reportpic.Dark.Roles[pretty.Name],
		reportpic.Light.Roles[pretty.Detail]: reportpic.Dark.Roles[pretty.Detail], "#8c97a6": "#5d6877",
		reportpic.Light.Roles[pretty.Error]: reportpic.Dark.Roles[pretty.Error], reportpic.Light.Roles[pretty.OK]: reportpic.Dark.Roles[pretty.OK],
	}
	light, err := os.ReadFile(filepath.Join(root, "docs", "images", "architecture-light.svg"))
	if err != nil {
		t.Fatal(err)
	}
	style, body, ok := strings.Cut(string(light), "</style>")
	if !ok {
		t.Fatal("architecture-light.svg has no style")
	}
	color := regexp.MustCompile(`#[0-9a-fA-F]{3,8}\b`)
	if c := color.FindString(body); c != "" {
		t.Errorf("architecture-light.svg has the color %s past its style, which the dark one wouldn't change", c)
	}
	want := color.ReplaceAllStringFunc(style, func(c string) string {
		d, ok := dark[c]
		if !ok {
			t.Errorf("architecture-light.svg has the color %s, which has no dark one here", c)
		}
		return d
	}) + "</style>" + body
	path := filepath.Join(root, "docs", "images", "architecture-dark.svg")
	if *update {
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
	} else if got, err := os.ReadFile(path); err != nil || string(got) != want {
		t.Errorf("architecture-dark.svg isn't the light one in the dark colors: go test ./internal/docgen -update")
	}
	// The app's docs are shown in Home Assistant, away from the repository: of its address.
	for page, from := range map[string]string{
		"README.md": "docs/images/", "docs/how-it-works.md": "images/",
		"homeassistant/addon/DOCS.md": "https://raw.githubusercontent.com/miguelangel-nubla/ipv6ddns/main/docs/images/",
	} {
		shown, err := os.ReadFile(filepath.Join(root, page))
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"architecture-light.svg", "architecture-dark.svg"} {
			if !strings.Contains(string(shown), `"`+from+name+`"`) {
				t.Errorf("%s doesn't show %s%s", page, from, name)
			}
		}
	}
}
