package docgen

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	mdLink   = regexp.MustCompile(`\]\(([^)\s]+)\)`)
	heading  = regexp.MustCompile(`(?m)^#+ (.*)$`)
	notInAnc = regexp.MustCompile(`[^\p{L}\p{N}\- _]`)
)

// anchor is GitHub's anchor of a heading.
func anchor(h string) string {
	h = notInAnc.ReplaceAllString(strings.ToLower(strings.TrimSpace(h)), "")
	return strings.ReplaceAll(h, " ", "-")
}

// Every link of the documentation to a file of the repository finds it, and its heading.
func TestDocLinks(t *testing.T) {
	root := filepath.Join("..", "..")
	var files []string
	for _, pattern := range []string{"*.md", "docs/*.md", "docs/*/*.md", "homeassistant/addon/*.md"} {
		found, _ := filepath.Glob(filepath.Join(root, pattern))
		files = append(files, found...)
	}
	anchors := make(map[string]map[string]bool)
	for _, f := range files {
		content, _ := os.ReadFile(f)
		anchors[filepath.Clean(f)] = make(map[string]bool)
		for _, m := range heading.FindAllStringSubmatch(string(content), -1) {
			anchors[filepath.Clean(f)][anchor(m[1])] = true
		}
	}
	for _, f := range files {
		content, _ := os.ReadFile(f)
		for _, m := range mdLink.FindAllStringSubmatch(string(content), -1) {
			link := m[1]
			if strings.Contains(link, "://") || strings.HasPrefix(link, "mailto:") {
				continue
			}
			path, fragment, _ := strings.Cut(link, "#")
			target := filepath.Clean(f)
			if path != "" {
				target = filepath.Clean(filepath.Join(filepath.Dir(f), path))
			}
			if _, err := os.Stat(target); err != nil {
				t.Errorf("%s: %s: no such file", f, link)
				continue
			}
			if fragment != "" && strings.HasSuffix(target, ".md") && !anchors[target][fragment] {
				t.Errorf("%s: %s: no such heading", f, link)
			}
		}
	}
}
