package ipv6ddns

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/blocklist"
	"go.uber.org/zap"
)

// blocklistWorker is a worker of two resolvers, lan and kids, at ports of their own, whose blocks
// name the lists of the servers: lan tif, kids pro and tif, with an allow. The state folder is
// state; the upstream is down.
func blocklistWorker(t *testing.T, state, pro, tif string) (w *Worker, lan, kids string) {
	t.Helper()
	lanPort, kidsPort := freeDNSPort(t), freeDNSPort(t)
	text := fmt.Sprintf(`
state_dir: %[1]s
listeners:
  lan:
    listen:
      - dns://127.0.0.1:%[2]s
  kids:
    listen:
      - dns://127.0.0.1:%[3]s
blocklists:
  pro:
    url: %[4]s/pro.txt
  tif:
    url: %[5]s/tif.txt
    interval: 2h
resolvers:
  lan:
    listeners:
      - lan
    upstream: 127.0.0.1:%[6]s
    block:
      lists: tif
  kids:
    listeners:
      - kids
    upstream: 127.0.0.1:%[6]s
    block:
      lists:
        - pro
        - tif
      allow:
        - school.ads.test
credentials:
  home:
    provider: resolver
    settings:
      zone: home.arpa
      resolvers:
        - lan
        - kids
      records:
        - printer A 192.0.2.20
tasks: {}
discovery:
  ipv6:
    enabled: false
`, state, lanPort, kidsPort, pro, tif, freeDNSPort(t))
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.NewConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	w, err = NewWorker(zap.NewNop().Sugar(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return w, net.JoinHostPort("127.0.0.1", lanPort), net.JoinHostPort("127.0.0.1", kidsPort)
}

// Each list is downloaded once, for both resolvers, at the start; each resolver blocks the names of
// its own lists, but those of allow, and its zone never; the status, the metrics and the report
// tell of the lists. A worker started again with the server gone blocks the same, of the copies,
// and says the download failed. A list that never downloaded blocks nothing, and is in red.
func TestWorkerBlocklists(t *testing.T) {
	var downloads atomic.Int64
	lists := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downloads.Add(1)
		w.Header().Set("ETag", `"`+r.URL.Path+`"`)
		switch r.URL.Path {
		case "/pro.txt":
			fmt.Fprint(w, "# pro\nads.test\nschool.ads.test\nhome.arpa\n||not a rule\n")
		case "/tif.txt":
			fmt.Fprint(w, "0.0.0.0 malware.test\n")
		default:
			http.NotFound(w, r)
		}
	}))
	state := t.TempDir()
	w, lan, kids := blocklistWorker(t, state, lists.URL, lists.URL)
	ctx, cancel := context.WithCancel(context.Background())
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitNames := func(w *Worker) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			s := w.Status(false).Blocklists
			if len(s) == 2 && s[0].Names > 0 && s[1].Names > 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("the lists never downloaded: %+v", s)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	waitNames(w)
	if n := downloads.Load(); n != 2 {
		t.Errorf("%d downloads, want one of each list", n)
	}
	check := func(w *Worker) {
		t.Helper()
		for _, c := range []struct {
			address, name string
			rcode         int
		}{
			{kids, "ads.test.", dns.RcodeNameError},
			{kids, "x.ads.test.", dns.RcodeNameError},
			{kids, "malware.test.", dns.RcodeNameError},
			{kids, "school.ads.test.", dns.RcodeServerFailure},
			{kids, "a.school.ads.test.", dns.RcodeServerFailure},
			{kids, "printer.home.arpa.", dns.RcodeSuccess},
			{lan, "ads.test.", dns.RcodeServerFailure},
			{lan, "malware.test.", dns.RcodeNameError},
		} {
			if resp := ask(t, c.address, c.name, dns.TypeA); resp.Rcode != c.rcode {
				t.Errorf("%s at %s: %s, want %s", c.name, c.address, dns.RcodeToString[resp.Rcode], dns.RcodeToString[c.rcode])
			}
		}
	}
	check(w)

	status := w.Status(false)
	pro := status.Blocklists[0]
	if pro.Name != "pro" || pro.Names != 3 || pro.Unreadable != 1 || pro.LastSuccess == nil || pro.NextRefresh == nil || !slices.Equal(pro.Resolvers, []string{"kids"}) || pro.Interval != 86400 {
		t.Errorf("pro: %+v", pro)
	}
	if tif := status.Blocklists[1]; !slices.Equal(tif.Resolvers, []string{"kids", "lan"}) || tif.Interval != 7200 {
		t.Errorf("tif: %+v", tif)
	}
	b, _ := json.Marshal(status)
	for _, want := range []string{`"blocklists":[{"name":"pro"`, `"block":{"lists":["pro","tif"],"allow":["school.ads.test"],"answer":"nxdomain","ttl":60}`, `"blocked":3`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("status.json without %s", want)
		}
	}
	var metrics strings.Builder
	status.WriteMetrics(&metrics)
	for _, want := range []string{
		`ipv6ddns_resolver_queries_total{resolver="kids",kind="blocked"} 3`,
		`ipv6ddns_resolver_queries_total{resolver="lan",kind="blocked"} 1`,
		`ipv6ddns_blocklist_names{blocklist="pro"} 3`,
		`ipv6ddns_blocklist_names{blocklist="tif"} 1`,
		`ipv6ddns_blocklist_last_success_timestamp_seconds{blocklist="pro"} `,
		`ipv6ddns_blocklist_last_refresh_failed{blocklist="pro"} 0`,
	} {
		if !strings.Contains(metrics.String(), want) {
			t.Errorf("metrics without %s:\n%s", want, metrics.String())
		}
	}
	page := w.PrettyPrint("", false)
	for _, want := range []string{
		"Blocklists: 2\n    pro: 3 names, 0.0 MiB\n        URL: " + lists.URL + "/pro.txt\n        Resolvers: kids\n        Unreadable: 1 lines\n        Last success: ",
		"        Block: pro, tif, allow school.ads.test, answer nxdomain, TTL 60s\n",
		"        Block: tif, answer nxdomain, TTL 60s\n",
		"Queries: local 1, nodata 0, forwarded 0, cached 0, blocked 3, refused 0, servfail 2",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page without %q:\n%s", want, page)
		}
	}
	for _, f := range []string{"pro.txt", "pro.json", "tif.txt", "tif.json"} {
		if _, err := os.Stat(filepath.Join(state, blocklist.Folder, f)); err != nil {
			t.Error(err)
		}
	}
	cancel()
	if err := w.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Again, offline: of the copies, and a download that fails, of tif, whose interval is past.
	lists.Close()
	w, lan, kids = blocklistWorker(t, state, lists.URL, lists.URL)
	if s := w.Status(false).Blocklists; s[0].Names != 3 || s[1].Names != 1 {
		t.Fatalf("the copies weren't read: %+v", s)
	}
	copyOf := filepath.Join(state, blocklist.Folder, "tif.json")
	stale, _ := os.ReadFile(copyOf)
	stale = []byte(strings.Replace(string(stale), `"last_success": "`+time.Now().Format("2006"), `"last_success": "2001`, 1))
	if err := os.WriteFile(copyOf, stale, 0o600); err != nil {
		t.Fatal(err)
	}
	w, lan, kids = blocklistWorker(t, state, lists.URL, lists.URL)
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	check(w)
	deadline := time.Now().Add(5 * time.Second)
	for w.Status(false).Blocklists[1].LastError == "" {
		if time.Now().After(deadline) {
			t.Fatal("tif was never downloaded")
		}
		time.Sleep(20 * time.Millisecond)
	}
	status = w.Status(true)
	if pro, tif := status.Blocklists[0], status.Blocklists[1]; pro.LastError != "" || tif.LastError != "<sensible data hidden>" || tif.Names != 1 {
		t.Errorf("offline: %+v", status.Blocklists)
	}
	check(w)
	cancel()
	_ = w.Shutdown(context.Background())

	// No copy, and no server: it serves, without the lists.
	w, _, kids = blocklistWorker(t, t.TempDir(), lists.URL, lists.URL)
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if resp := ask(t, kids, "ads.test.", dns.TypeA); resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("of no list: %s", dns.RcodeToString[resp.Rcode])
	}
	deadline = time.Now().Add(5 * time.Second)
	for w.Status(false).Blocklists[0].LastError == "" {
		if time.Now().After(deadline) {
			t.Fatal("pro was never downloaded")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if page := w.PrettyPrint("", false); !strings.Contains(page, "    pro: no names: not downloaded yet, and no copy, 0.0 MiB\n") || !strings.Contains(page, "(failed: ") {
		t.Errorf("the page of no list:\n%s", page)
	}
	cancel()
	_ = w.Shutdown(context.Background())
}
