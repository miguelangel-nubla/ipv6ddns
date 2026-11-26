//go:build linux && integration

package main

// The blocklists of two resolvers, as the command runs them, downloaded from a server of the
// test's, asked by dig, on machines of one link.

import (
	"fmt"
	"maps"
	"net/http"
	"os/exec"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/internal/livetest"
)

// A machine runs ipv6ddns with two resolvers, lan and kids, on two addresses of its own, whose
// blocks name two lists of a server of the test's on another machine: lan's, of malware, and the
// kids', of ads too, with a name of it in allow. A client asks each: kids answers NXDOMAIN to a
// name of its lists and to a name below it, which lan forwards, and answers the name of allow;
// both block the malware. The names blocked never reach the upstream server, and each list is
// downloaded once.
func TestLiveResolverBlocklists(t *testing.T) {
	if _, err := exec.LookPath("dig"); err != nil {
		t.Fatal("the live tests of the resolver ask it with dig, of bind9-dnsutils: not found")
	}
	lan := livetest.NewLAN(t, 33)
	srv := lan.Machine(t, "srv", 10)
	client := lan.Machine(t, "client", 30)
	up := lan.Machine(t, "up", 40)
	lists := lan.Machine(t, "lists", 50)
	kids := "198.18.33.11"
	srv.IP(t, "addr", "add", kids+"/24", "dev", srv.Interface)
	upstream := startUpstream(t, up, "192.0.2.53")

	var downloads atomic.Int64
	l, err := lists.Listen("tcp4", lists.IPv4.String()+":8080")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downloads.Add(1)
		switch r.URL.Path {
		case "/ads.txt":
			fmt.Fprint(w, "# ads, as hagezi's onlydomains\nads.example\nschool.ads.example\n")
		case "/malware.txt":
			fmt.Fprint(w, "0.0.0.0 malware.example\n")
		default:
			http.NotFound(w, r)
		}
	})}
	go server.Serve(l)
	t.Cleanup(func() { server.Close() })

	config := fmt.Sprintf(`
listeners:
  web:
    listen:
      - http://8053
  lan:
    listen:
      - dns://%[1]s
  kids:
    listen:
      - dns://%[2]s
webservers:
  main:
    listeners:
      - web
discovery:
  ipv6:
    enabled: false
blocklists:
  ads:
    url: http://%[3]s:8080/ads.txt
  malware:
    url: http://%[3]s:8080/malware.txt
resolvers:
  lan:
    listeners:
      - lan
    upstream: %[4]s
    block:
      lists: malware
  kids:
    listeners:
      - kids
    allow:
      - 198.18.33.0/24
    upstream: %[4]s
    block:
      lists:
        - ads
        - malware
      allow:
        - school.ads.example
credentials: {}
tasks: {}
`, srv.IPv4, kids, lists.IPv4, up.IPv4)
	one := configure(t, srv, lan.Router, "srv", 8053, config).start().serving()

	waitFor(t, 30*time.Second, "the lists, downloaded", func() bool {
		return dig(t, client, kids, "probe.ads.example", "A").status == "NXDOMAIN"
	}, one.tells)
	for _, c := range []struct {
		server, name, status string
		answers              []string
	}{
		{kids, "ads.example", "NXDOMAIN", nil},
		{kids, "www.ads.example", "NXDOMAIN", nil},
		{kids, "malware.example", "NXDOMAIN", nil},
		{kids, "school.ads.example", "NOERROR", []string{"school.ads.example. A 192.0.2.53"}},
		{kids, "x.school.ads.example", "NOERROR", []string{"x.school.ads.example. A 192.0.2.53"}},
		{srv.IPv4.String(), "ads.example", "NOERROR", []string{"ads.example. A 192.0.2.53"}},
		{srv.IPv4.String(), "www.ads.example", "NOERROR", []string{"www.ads.example. A 192.0.2.53"}},
		{srv.IPv4.String(), "malware.example", "NXDOMAIN", nil},
	} {
		d := dig(t, client, c.server, c.name, "A")
		if d.status != c.status || !slices.Equal(d.answers, c.answers) {
			t.Errorf("%s at %s: %s, want %s %q", c.name, c.server, d, c.status, c.answers)
		}
	}
	for name, want := range map[string]int{"malware.example.": 0, "www.ads.example.": 1, "ads.example.": 1, "school.ads.example.": 1, "x.school.ads.example.": 1} {
		if n := upstream.times(name); n != want {
			t.Errorf("%s asked upstream %d times, want %d", name, n, want)
		}
	}
	if n := downloads.Load(); n != 2 {
		t.Errorf("%d downloads, want one of each list", n)
	}

	// The reports: of each list, its names, of each resolver, its lists and what it blocked.
	metrics := one.page("/metrics")
	for _, want := range []string{
		`ipv6ddns_blocklist_names{blocklist="ads"} 2`,
		`ipv6ddns_blocklist_names{blocklist="malware"} 1`,
		`ipv6ddns_resolver_queries_total{resolver="lan",kind="blocked"} 1`,
		`ipv6ddns_blocklist_last_success_timestamp_seconds{blocklist="ads"} `,
	} {
		if !strings.Contains(metrics, want) {
			t.Errorf("metrics without %s:\n%s", want, metrics)
		}
	}
	status := one.status()
	names := map[string]int{}
	for _, l := range status.Blocklists {
		names[l.Name] = l.Names
		if l.LastSuccess == nil || l.LastError != "" {
			t.Errorf("blocklist %s: %+v", l.Name, l)
		}
	}
	if !maps.Equal(names, map[string]int{"ads": 2, "malware": 1}) {
		t.Errorf("/status.json: the blocklists have %v names", names)
	}
	for _, r := range status.Resolvers {
		// kids: the probes, ads.example, www.ads.example and malware.example; lan: malware.example.
		least, lists := uint64(4), []string{"ads", "malware"}
		if r.Name == "lan" {
			least, lists = 1, []string{"malware"}
		}
		if r.Block == nil || !slices.Equal(r.Block.Lists, lists) || r.Queries["blocked"] < least {
			t.Errorf("/status.json: resolver %s blocked %d, of %+v; want %d at least, of %q", r.Name, r.Queries["blocked"], r.Block, least, lists)
		}
	}
}
