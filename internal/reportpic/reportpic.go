// Package reportpic draws the report as a picture, for the pages that can't show its colors: the
// roles of a report given as text, and the SVG of a page.
package reportpic

import (
	"fmt"
	"html"
	"regexp"
	"strconv"
	"strings"

	"github.com/miguelangel-nubla/ipv6disc/pkg/pretty"
)

var (
	section  = regexp.MustCompile(`^(DNS|Resolvers|Discovery|Config):`)
	counts   = regexp.MustCompile(`^ (\d+ names?, )(\d+) with addresses, (\d+) without; (\d+) failing$`)
	nameLine = regexp.MustCompile(`^( +[^ ]+)(:)(.*)$`)
	note     = regexp.MustCompile(` \([^()]*(\([^()]*\)[^()]*)*\)`)
	serving  = regexp.MustCompile(`^ (\d+), (\d+) serving$`)
	failed   = regexp.MustCompile(`\((\d+) failed\)`)
)

// Roles gives the names, the resolvers and the discovery of a report, as text, the roles the
// program gives them: a test holds it to what the program writes. The configuration is left as
// text.
func Roles(text string) pretty.Page {
	var page pretty.Page
	current, group := "", ""
	for line := range strings.SplitSeq(strings.TrimSuffix(text, "\n"), "\n") {
		body := strings.TrimLeft(line, " ")
		indent := len(line) - len(body)
		if m := section.FindString(line); m != "" {
			current = strings.TrimSuffix(m, ":")
			page = append(page, append(pretty.Line{pretty.As(pretty.Heading, m)}, summary(current, line[len(m):])...))
			continue
		}
		switch current {
		case "DNS":
			page = append(page, dnsLine(line, body, indent))
		case "Resolvers":
			page = append(page, resolverLine(line, body, indent))
		case "Discovery":
			switch {
			case indent == 8 && strings.HasSuffix(body, ":"):
				group = body
				page.Add(pretty.As(pretty.Detail, line))
			case indent == 12 && group == "names:":
				page = append(page, row(line, pretty.Name))
			case indent == 12:
				page = append(page, row(line, pretty.Plain))
			case indent > 12:
				page.Add(pretty.As(pretty.Detail, line))
			default:
				page.Add(pretty.Span{Text: line})
			}
		default:
			page.Add(pretty.Span{Text: line})
		}
	}
	return page
}

// summary is the rest of a section's first line: the counts of the names each with the role of
// its state, when there is something to it.
func summary(section, rest string) pretty.Line {
	if m := serving.FindStringSubmatch(rest); section == "Resolvers" && m != nil {
		role := pretty.OK
		if m[1] != m[2] {
			role = pretty.Error
		}
		return pretty.Line{{Text: " " + m[1] + ", "}, pretty.As(role, m[2]+" serving")}
	}
	m := counts.FindStringSubmatch(rest)
	if section != "DNS" || m == nil {
		return pretty.Line{{Text: rest}}
	}
	n := func(s string) int { v, _ := strconv.Atoi(s); return v }
	with, without, failing := n(m[2]), n(m[3]), n(m[4])
	as := func(role pretty.Role, is bool, text string) pretty.Span {
		if !is {
			role = pretty.Plain
		}
		return pretty.As(role, text)
	}
	return pretty.Line{
		{Text: " " + m[1]},
		as(pretty.OK, with > 0 && without == 0 && failing == 0, m[2]+" with addresses"),
		{Text: ", "},
		as(pretty.Warn, without > 0, m[3]+" without"),
		{Text: "; "},
		as(pretty.Error, failing > 0, m[4]+" failing"),
	}
}

func dnsLine(line, body string, indent int) pretty.Line {
	switch {
	case strings.HasPrefix(body, "Provider: "), strings.HasPrefix(body, "Endpoint: "):
		return pretty.Line{pretty.As(pretty.Heading, line)}
	case strings.HasPrefix(body, "(last update error: "):
		return pretty.Line{{Text: line[:indent]}, pretty.As(pretty.Error, body)}
	case strings.HasPrefix(body, "(no address"):
		return pretty.Line{{Text: line[:indent]}, pretty.As(pretty.Warn, body)}
	case indent == 12:
		m := nameLine.FindStringSubmatch(line)
		if m == nil {
			break
		}
		out := pretty.Line{pretty.As(pretty.Name, m[1]), {Text: m[2]}}
		for _, n := range note.FindAllString(m[3], -1) {
			role := pretty.Detail
			switch {
			case n == " (update running)":
				out = append(out, pretty.Span{Text: n})
				continue
			case strings.Contains(n, "retrying after the error"):
				role = pretty.Warn
			}
			out = append(out, pretty.Span{Text: " "}, pretty.As(role, n[1:]))
		}
		return out
	case indent > 12:
		return row(line, pretty.Plain)
	}
	return pretty.Line{{Text: line}}
}

// resolverLine is a line of a resolver: its name with whether it serves, what it is given as it
// is, an upstream that failed set apart, and its counters as details.
func resolverLine(line, body string, indent int) pretty.Line {
	switch {
	case indent == 4:
		name, state, _ := strings.Cut(line, ": ")
		role := pretty.Error
		if state == "serving" {
			role = pretty.OK
		}
		return pretty.Line{pretty.As(pretty.Name, name), {Text: ": "}, pretty.As(role, state)}
	case strings.HasPrefix(body, "Queries: "), strings.HasPrefix(body, "Cache: "):
		return pretty.Line{pretty.As(pretty.Detail, line)}
	case strings.HasPrefix(body, "Certificate: "):
		return certificateLine(line)
	case strings.HasPrefix(body, "Upstream: "):
		var out pretty.Line
		last := 0
		for _, m := range failed.FindAllStringSubmatchIndex(line, -1) {
			role := pretty.Detail
			if line[m[2]:m[3]] != "0" {
				role = pretty.Warn
			}
			out = append(out, pretty.Span{Text: line[last:m[0]]}, pretty.As(role, line[m[0]:m[1]]))
			last = m[1]
		}
		return append(out, pretty.Span{Text: line[last:]})
	}
	return pretty.Line{{Text: line}}
}

// row is a row of a table: its label, up to the columns, with its role, and the rest a detail.
func row(line string, label pretty.Role) pretty.Line {
	body := strings.TrimLeft(line, " ")
	cut := len(line)
	if i := strings.Index(body, "  "); i >= 0 {
		cut = len(line) - len(body) + i
	}
	out := pretty.Line{{Text: line[:cut], Role: label}}
	if cut < len(line) {
		out = append(out, pretty.As(pretty.Detail, line[cut:]))
	}
	return out
}

// Theme is the colors of a picture: those of the web page, on its light or its dark ground.
type Theme struct {
	Ground, Border, Text string
	Roles                map[pretty.Role]string
}

var (
	Light = Theme{"#ffffff", "#d0d7de", "#1d2530", map[pretty.Role]string{
		pretty.Heading: "#1d2530", pretty.Name: "#0f3a8a", pretty.OK: "#1d7a3e", pretty.Warn: "#8a5200", pretty.Error: "#c0262d", pretty.Detail: "#5d6877"}}
	Dark = Theme{"#12161c", "#30363d", "#dde3ea", map[pretty.Role]string{
		pretty.Heading: "#f1f4f8", pretty.Name: "#9cc0ff", pretty.OK: "#5fcf83", pretty.Warn: "#e7b04f", pretty.Error: "#ff7b7b", pretty.Detail: "#8c97a6"}}
)

// The size of the letters, of a monospaced font, in tenths of a pixel: each piece of text is
// given its width, so the columns line up whatever font the reader has. They are whole numbers:
// a float's last digit differs from one machine to another, and the picture must not.
const (
	size    = 130
	advance = 78
	leading = 190
	padX    = 160
	padY    = 140
	// From the top of a line to the foot of its letters.
	baseline = 140
)

var gap = regexp.MustCompile(` {2,}`)

// SVG is the page as a picture, in the colors of theme. A piece of text is placed at its column:
// the spaces between the columns are left out, as SVG would join them.
func SVG(page pretty.Page, theme Theme) string {
	cols := 0
	for _, line := range page {
		cols = max(cols, len([]rune(line.String())))
	}
	width, height := cols*advance+2*padX, len(page)*leading+2*padY
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %s %s" width="%s" height="%s" role="img" aria-label="The report of ipv6ddns, with its colors">`+"\n", num(width), num(height), num(width), num(height))
	fmt.Fprintf(&b, `<rect x="0.5" y="0.5" width="%s" height="%s" rx="6" fill="%s" stroke="%s"/>`+"\n", num(width-10), num(height-10), theme.Ground, theme.Border)
	fmt.Fprintf(&b, `<g font-family="ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, 'DejaVu Sans Mono', monospace" font-size="%s" fill="%s">`+"\n", num(size), theme.Text)
	for i, line := range page {
		y := padY + i*leading + baseline
		col := 0
		for _, span := range line {
			text := []rune(span.Text)
			at := 0
			for _, piece := range pieces(string(text)) {
				at = piece.at
				attrs := ""
				if fill, ok := theme.Roles[span.Role]; ok {
					attrs += ` fill="` + fill + `"`
				}
				if span.Role == pretty.Heading || span.Role == pretty.Error {
					attrs += ` font-weight="600"`
				}
				n := len([]rune(piece.text))
				fmt.Fprintf(&b, `<text x="%s" y="%s" textLength="%s" lengthAdjust="spacingAndGlyphs"%s>%s</text>`+"\n",
					num(padX+(col+at)*advance), num(y), num(n*advance), attrs, html.EscapeString(piece.text))
			}
			col += len(text)
		}
	}
	b.WriteString("</g>\n</svg>\n")
	return b.String()
}

type piece struct {
	at   int
	text string
}

// pieces are the runs of text of s that two spaces or more set apart, each with its column.
func pieces(s string) []piece {
	var out []piece
	at := 0
	for _, part := range gapSplit(s) {
		if strings.TrimSpace(part.text) != "" {
			lead := len(part.text) - len(strings.TrimLeft(part.text, " "))
			out = append(out, piece{at + part.at + lead, strings.TrimSpace(part.text)})
		}
	}
	return out
}

func gapSplit(s string) []piece {
	var out []piece
	last := 0
	for _, loc := range gap.FindAllStringIndex(s, -1) {
		out = append(out, piece{len([]rune(s[:last])), s[last:loc[0]]})
		last = loc[1]
	}
	return append(out, piece{len([]rune(s[:last])), s[last:]})
}

// num is tenths as a number of SVG: 1252 is 125.2, and 160 is 16.
func num(tenths int) string {
	if tenths%10 == 0 {
		return strconv.Itoa(tenths / 10)
	}
	return strconv.Itoa(tenths/10) + "." + strconv.Itoa(tenths%10)
}

// certificateLine is the certificate of a resolver: until when, in amber within two weeks of its
// end and in red after it, and its files in amber when they don't read again.
func certificateLine(line string) pretty.Line {
	var out pretty.Line
	rest, unread, hasUnread := strings.Cut(line, " (its files don't read again: ")
	switch {
	case strings.Contains(rest, ", expired on "):
		i := strings.LastIndex(rest, "expired on ")
		out = pretty.Line{{Text: rest[:i]}, pretty.As(pretty.Error, rest[i:])}
	case soon.MatchString(rest):
		i := strings.LastIndex(rest, "until ")
		out = pretty.Line{{Text: rest[:i]}, pretty.As(pretty.Warn, rest[i:])}
	default:
		out = pretty.Line{{Text: rest}}
	}
	if hasUnread {
		out = append(out, pretty.Span{Text: " "}, pretty.As(pretty.Warn, "(its files don't read again: "+unread))
	}
	return out
}

// soon is the end of a certificate within two weeks, as the report says it.
var soon = regexp.MustCompile(`until \d{4}-\d{2}-\d{2}, in \d+ days?$`)
