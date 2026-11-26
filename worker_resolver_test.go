package ipv6ddns

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/resolver"
	"go.uber.org/zap"
)

// freeDNSPort is a port nothing listens on at 127.0.0.1, over UDP and TCP, a moment ago.
func freeDNSPort(t *testing.T) string {
	t.Helper()
	for range 20 {
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		l, err := net.Listen("tcp4", pc.LocalAddr().String())
		pc.Close()
		if err == nil {
			l.Close()
			_, port, _ := net.SplitHostPort(pc.LocalAddr().String())
			return port
		}
	}
	t.Fatal("no free port")
	return ""
}

func resolverWorker(t *testing.T, port string) *Worker {
	t.Helper()
	text := fmt.Sprintf(`
listeners:
  lan:
    listen:
      - dns://127.0.0.1:%s
resolvers:
  lan:
    listeners:
      - lan
    upstream: 127.0.0.1:%s
    records:
      - dns.example.test. A 192.0.2.53
credentials:
  home:
    provider: resolver
    settings:
      zone: home.arpa
      records:
        - files CNAME nas
  office:
    provider: resolver
    settings:
      zone: office.test
      records:
        - printer A 192.0.2.20
sources:
  wan:
    type: static
    addresses:
      - 192.0.2.7
      - "2001:db8::7"
tasks:
  nas:
    sources:
      - wan
    endpoints:
      home:
        - nas
discovery:
  ipv6:
    enabled: false
`, port, freeDNSPort(t))
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.NewConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	w, err := NewWorker(zap.NewNop().Sugar(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func ask(t *testing.T, address, name string, qtype uint16) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	resp, _, err := (&dns.Client{Timeout: 3 * time.Second}).Exchange(m, address)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// A task's addresses reach the resolver through the provider's updates, with no debounce; a zone
// no task names answers its records. The status, the metrics, the report and the health tell of
// it; it stops with the worker; and another on its address doesn't start.
func TestWorkerResolver(t *testing.T) {
	port := freeDNSPort(t)
	w := resolverWorker(t, port)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := w.Healthy(); err == nil {
		t.Error("healthy before the start")
	}
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	address := net.JoinHostPort("127.0.0.1", port)

	deadline := time.Now().Add(5 * time.Second)
	for {
		resp := ask(t, address, "files.home.arpa.", dns.TypeA)
		if len(resp.Answer) == 2 && resp.Answer[1].(*dns.A).A.String() == "192.0.2.7" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("nas never answered: %v", resp)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if resp := ask(t, address, "nas.home.arpa.", dns.TypeAAAA); len(resp.Answer) != 1 || !resp.Authoritative {
		t.Errorf("AAAA: %v", resp)
	}
	if resp := ask(t, address, "printer.office.test.", dns.TypeA); len(resp.Answer) != 1 {
		t.Errorf("a zone with no task: %v", resp)
	}
	// Upstream is down.
	if resp := ask(t, address, "example.org.", dns.TypeA); resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("forwarded to nobody: %v", resp)
	}

	if err := w.Healthy(); err != nil {
		t.Error(err)
	}
	status := w.Status(true)
	if len(status.Resolvers) != 1 || !status.Resolvers[0].Serving || !slices.Equal(status.Resolvers[0].Listening, []string{address}) || !slices.Equal(status.Resolvers[0].Zones, []string{"home.arpa", "office.test"}) {
		t.Errorf("status: %+v", status.Resolvers)
	}
	var metrics strings.Builder
	status.WriteMetrics(&metrics)
	for _, want := range []string{
		`ipv6ddns_resolver_serving{resolver="lan"} 1`,
		`ipv6ddns_resolver_queries_total{resolver="lan",kind="local"} `,
		`ipv6ddns_resolver_queries_total{resolver="lan",kind="servfail"} 1`,
		`ipv6ddns_resolver_queries_total{resolver="lan",kind="cached"} 0`,
		`ipv6ddns_resolver_cache_entries{resolver="lan"} 0`,
		`ipv6ddns_resolver_zone_names{resolver="lan",zone="home.arpa"} 1`,
		`ipv6ddns_resolver_zone_records{resolver="lan",zone="office.test"} 1`,
		`ipv6ddns_resolver_upstream_failures_total{resolver="lan",upstream="127.0.0.1:`,
	} {
		if !strings.Contains(metrics.String(), want) {
			t.Errorf("metrics without %s:\n%s", want, metrics.String())
		}
	}
	if report := w.PrettyPrint("", true); !strings.Contains(report, "Resolvers: 1, 1 serving\n    lan: serving\n        Listening: "+address) {
		t.Errorf("report:\n%s", report)
	} else if !strings.Contains(report, "        Cache: 0 of 10000\n") || !strings.Contains(report, ", cached 0,") {
		t.Errorf("report, of the cache:\n%s", report)
	}
	// The written records: the zone's under its endpoint, the resolver's own under it, and counted
	// apart from the names of the tasks.
	report := w.PrettyPrint("", true)
	for _, want := range []string{
		"        Endpoint: office\n            printer.office.test. ",
		" IN A 192.0.2.20\n",
		"        Zones: home.arpa (1 name, 1 written record, TTL 60s), office.test (0 names, 1 written record, TTL 60s)\n",
		"        Allow: 127.0.0.0/8 (the networks it listens on)\n",
		"        Records:\n            dns.example.test. ",
		" IN A 192.0.2.53\n",
		"        Private reverse: the unknown answered here as no such name (RFC 6303)\n",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report without %q:\n%s", want, report)
		}
	}
	// Each name's task is in /status.json alone: the report has the names under their endpoints.
	if strings.Contains(report, ": task nas\n") {
		t.Errorf("report with a line of each name's task:\n%s", report)
	}
	if r := status.Resolvers[0]; len(r.Records) != 1 || len(r.ZoneRecords["office.test"]) != 1 || r.ZoneCredentials["office.test"] != "office" {
		t.Errorf("status, of the records: %+v", r)
	}
	if r := status.Resolvers[0]; r.AllowOwn || r.ZoneTTL["home.arpa"] != 60 || r.ZoneTasks["home.arpa"]["nas.home.arpa"] != "nas" {
		t.Errorf("status, of the allow and the zones' tasks: %+v", r)
	}
	if r := status.Resolvers[0]; r.CacheSize != 10000 || r.CacheEntries != 0 {
		t.Errorf("status, of the cache: %+v", r)
	}

	other := resolverWorker(t, port)
	otherCtx, otherCancel := context.WithCancel(context.Background())
	defer otherCancel()
	if err := other.Start(otherCtx); err == nil || !strings.Contains(err.Error(), "resolvers.lan: ") || !strings.Contains(err.Error(), "address already in use") {
		t.Errorf("a second on the address: %v", err)
	}

	cancel()
	stopping, done := context.WithTimeout(context.Background(), 10*time.Second)
	defer done()
	if err := w.Shutdown(stopping); err != nil {
		t.Fatal(err)
	}
	if err := w.Healthy(); err == nil {
		t.Error("healthy once stopped")
	}
	if _, _, err := (&dns.Client{Timeout: 300 * time.Millisecond}).Exchange(new(dns.Msg).SetQuestion("nas.home.arpa.", dns.TypeA), address); err == nil {
		t.Error("answering once stopped")
	}
}

// workerOf is a worker of a configuration.
func workerOf(t *testing.T, text string) *Worker {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.NewConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	w, err := NewWorker(zap.NewNop().Sugar(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// Two resolvers on one address and port, spelled two ways, which the configuration alone can't
// tell: the start does, before either listens, naming both and their entries.
func TestWorkerResolversCollide(t *testing.T) {
	port := freeDNSPort(t)
	for _, c := range []struct{ lab, lan, want string }{
		{"dns://127.0.0.0/8", "dns://127.0.0.1", "resolvers lab and lan both listen on 127.0.0.1:53: lab as dns://127.0.0.0/8, lan as dns://127.0.0.1: an address and port can belong to only one resolver"},
		{"dns://" + port, "dns://127.0.0.1:" + port, "resolvers lab and lan both listen on 127.0.0.1:" + port + ": lab as dns://" + port + ", lan as dns://127.0.0.1:" + port + ": an address and port can belong to only one resolver"},
		{"dns://0.0.0.0:" + port, `"dns://[::1]:` + port + `"` + "\n      - " + `"dns://127.0.0.1:` + port + `"`, "resolvers lab and lan both listen on 127.0.0.1:" + port + ": lab as dns://0.0.0.0:" + port + ", lan as dns://127.0.0.1:" + port + ": an address and port can belong to only one resolver"},
	} {
		w := workerOf(t, fmt.Sprintf(`
listeners:
  lab:
    listen:
      - %s
  lan:
    listen:
      - %s
resolvers:
  lab:
    listeners:
      - lab
    upstream: 192.0.2.1
  lan:
    listeners:
      - lan
    upstream: 192.0.2.1
credentials: {}
tasks: {}
discovery:
  ipv6:
    enabled: false
`, c.lab, c.lan))
		ctx, cancel := context.WithCancel(context.Background())
		err := w.Start(ctx)
		cancel()
		if err == nil || err.Error() != c.want {
			t.Errorf("got %v\nwant %s", err, c.want)
		}
		// Neither listens: the port is free.
		if lan, ok := strings.CutPrefix(c.lan, "dns://"); ok && strings.HasPrefix(lan, "127.0.0.1:") {
			l, err := net.Listen("tcp4", lan)
			if err != nil {
				t.Errorf("%s was left listening: %v", c.lan, err)
			} else {
				l.Close()
			}
		}
	}
}

// The resolvers stop in the time the worker's shutdown is given, the program's, with no shorter
// one of their own: a query whose upstream servers, three that never answer, take 6 seconds, is
// answered, that none did, while the worker stops.
func TestWorkerResolverShutdown(t *testing.T) {
	var upstreams []string
	for range 3 {
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		upstreams = append(upstreams, pc.LocalAddr().String())
	}
	port := freeDNSPort(t)
	w := workerOf(t, fmt.Sprintf(`
listeners:
  lan:
    listen:
      - "dns://127.0.0.1:%s"
resolvers:
  lan:
    listeners:
      - lan
    upstream:
      - %s
credentials: {}
tasks: {}
discovery:
  ipv6:
    enabled: false
`, port, strings.Join(upstreams, ", ")))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	address := net.JoinHostPort("127.0.0.1", port)
	answered := make(chan error, 1)
	began := time.Now()
	go func() {
		resp, _, err := (&dns.Client{Net: "tcp", Timeout: 20 * time.Second}).Exchange(new(dns.Msg).SetQuestion("example.org.", dns.TypeA), address)
		if err == nil && resp.Rcode != dns.RcodeServerFailure {
			err = fmt.Errorf("%v", resp)
		}
		answered <- err
	}()
	// Once the query is being answered.
	time.Sleep(500 * time.Millisecond)
	cancel()
	stopping, done := context.WithTimeout(context.Background(), 30*time.Second)
	defer done()
	if err := w.Shutdown(stopping); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(began); took < 5500*time.Millisecond || took > 15*time.Second {
		t.Errorf("stopped %s after the query, want the 6s its upstream servers take", took.Round(time.Millisecond))
	}
	select {
	case err := <-answered:
		if err != nil {
			t.Errorf("the query being answered: %v", err)
		}
	case <-time.After(time.Second):
		t.Error("the query being answered had no answer by the end of the shutdown")
	}
	if _, _, err := (&dns.Client{Timeout: 300 * time.Millisecond}).Exchange(new(dns.Msg).SetQuestion("example.org.", dns.TypeA), address); err == nil {
		t.Error("answering once stopped")
	}
}

// A resolver with nothing of a list says so, rather than leaving the line empty.
func TestResolversPageEmpty(t *testing.T) {
	page := resolversPage("", []resolver.Status{{Name: "bare", ForwardUnknownPrivateReverse: true}}).String()
	for _, want := range []string{
		"        Listening: none\n",
		"        Allow: none\n",
		"        Zones: none\n",
		"        Upstream: none, its own names only\n",
		"        Private reverse: forwarded\n",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("without %q:\n%s", want, page)
		}
	}
	if strings.Contains(page, "Records:") || strings.Contains(page, "Bootstrap:") {
		t.Errorf("a line of nothing:\n%s", page)
	}
}

// The allow of each listener on its own sockets, and what each key's permission may change.
func TestResolversPageAllowAndGrants(t *testing.T) {
	page := resolversPage("", []resolver.Status{{
		Name:  "lan",
		Allow: []string{"192.0.2.0/24", "2001:db8::/32"},
		ListenerAllow: []resolver.ListenerAllowStatus{
			{Listen: "[::]:53", Allow: []string{"192.0.2.0/24"}},
			{Listen: "tls://[::]:853", Listener: "lan", Allow: []string{"2001:db8::/32"}},
		},
		Keys: []resolver.KeyStatus{{
			Name:        "nas",
			Permissions: []string{"addresses", "challenges"},
			Grants: []resolver.GrantStatus{
				{Permission: "addresses", Zone: "home.arpa", Names: []string{"nas.home.arpa"}, Types: []string{"A", "AAAA"}},
				{Permission: "challenges", Types: []string{"TXT"}},
			},
		}},
	}}).String()
	for _, want := range []string{
		"        Allow: 192.0.2.0/24, 2001:db8::/32 (its listeners')\n",
		"            [::]:53: 192.0.2.0/24\n",
		"            tls://[::]:853 (lan): 2001:db8::/32\n",
		"                addresses: nas.home.arpa of home.arpa (A, AAAA)\n",
		"                challenges: not asked of its provider yet (TXT)\n",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("without %q:\n%s", want, page)
		}
	}
	own := resolversPage("", []resolver.Status{{Name: "lan", Allow: []string{"192.0.2.0/24"}, AllowOwn: true}}).String()
	if !strings.Contains(own, "        Allow: 192.0.2.0/24 (the resolver's)\n") {
		t.Errorf("the resolver's own allow:\n%s", own)
	}
}
