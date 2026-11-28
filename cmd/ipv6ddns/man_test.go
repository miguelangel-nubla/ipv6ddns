package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "write the manual page")

// roff is the text as a manual page has it: its dashes are the minus of a flag, not a hyphen
// that a terminal may show as another character, and a line can't start a request.
func roff(text string) string {
	text = strings.ReplaceAll(text, `\`, `\e`)
	text = strings.ReplaceAll(text, "-", `\-`)
	if strings.HasPrefix(text, ".") || strings.HasPrefix(text, "'") {
		text = `\&` + text
	}
	return text
}

// manPage is the manual page, ipv6ddns(1): the flags as the usage has them, and the files as
// findConfig looks for them.
func manPage() string {
	var synopsis, options strings.Builder
	flag.VisitAll(func(f *flag.Flag) {
		kind, text := flag.UnquoteUsage(f)
		name := `\fB` + roff("--"+f.Name) + `\fR`
		if kind != "" {
			name += ` \fI` + roff(kind) + `\fR`
		}
		synopsis.WriteString("\n[" + name + "]")
		fmt.Fprintf(&options, ".TP\n%s\n%s.\n", name, roff(text))
	})

	var b strings.Builder
	b.WriteString(`.\" Generated from the code by go test ./cmd/ipv6ddns \-update: edit it, not this page.` + "\n")
	b.WriteString(".TH IPV6DDNS 1 \"\" ipv6ddns \"User Commands\"\n")
	b.WriteString(".SH NAME\nipv6ddns \\- DNS names for every device on your network, on the LAN and on the internet, wherever its addresses move\n")
	b.WriteString(".SH SYNOPSIS\n.B ipv6ddns" + synopsis.String() + "\n")
	b.WriteString(".SH DESCRIPTION\n")
	b.WriteString(roff("ipv6ddns discovers the hosts of the network, with their addresses and names, and keeps the addresses of those its configuration chooses, IPv6 and IPv4, in the records of a DNS provider. It updates a name when its addresses change.") + "\n.PP\n")
	b.WriteString(roff("It runs until it is stopped. On SIGINT or SIGTERM the updates in progress get up to 30 seconds to finish, and a second signal stops it at once.") + "\n.PP\n")
	b.WriteString(roff("Local discovery needs raw sockets: root, or the CAP_NET_RAW capability.") + "\n")
	b.WriteString(".SH OPTIONS\n" + options.String())
	b.WriteString(".PP\n" + roff("Everything else is in the configuration file.") + "\n")
	b.WriteString(".SH FILES\n")
	for i, file := range configFiles {
		what := "The configuration, without \\fB\\-\\-config\\fR: the working directory's"
		if i > 0 {
			what = "The configuration, when the one before is not there: the system's, as a package installs it"
		}
		fmt.Fprintf(&b, ".TP\n.I %s\n%s.\n", roff(file), what)
	}
	b.WriteString(".SH EXIT STATUS\n")
	fmt.Fprintf(&b, ".TP\n0\n%s\n", roff("Stopped by SIGINT or SIGTERM, or after --version."))
	fmt.Fprintf(&b, ".TP\n1\n%s\n", roff("A failure, as an address it can't listen on."))
	fmt.Fprintf(&b, ".TP\n2\n%s\n", roff("An argument it doesn't take."))
	fmt.Fprintf(&b, ".TP\n%d\n%s\n", exitConfig, roff("A configuration it can't use, or none found. The same would fail again: systemd's unit of the packages doesn't restart it of this one."))
	b.WriteString(".SH SEE ALSO\n" + roff("The keys of the configuration file:") + "\n.UR " + reference + "\n.UE\n")
	return b.String()
}

// The manual page of the packages is the one the code makes: after changing a flag,
// go test ./cmd/ipv6ddns -update.
func TestManPageUpToDate(t *testing.T) {
	resetFlags(t)
	want := manPage()
	for _, name := range []string{"config", "live", "version"} {
		if !strings.Contains(want, `\fB\-\-`+name+`\fR`) {
			t.Errorf("the page has no --%s:\n%s", name, want)
		}
	}
	path := filepath.Join("..", "..", "packaging", "ipv6ddns.1")
	if *update {
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != want {
		t.Errorf("%s is behind the code: go test ./cmd/ipv6ddns -update", path)
	}
}
