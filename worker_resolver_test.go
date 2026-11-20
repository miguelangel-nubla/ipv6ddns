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
resolvers:
  lan:
    listen: 127.0.0.1:%s
    upstream: 127.0.0.1:%s
credentials:
  home:
    provider: resolver
    settings:
      zone: home.arpa
      records: [files CNAME nas]
  office:
    provider: resolver
    settings: {zone: office.test, records: [printer A 192.0.2.20]}
sources:
  wan: {type: static, addresses: [192.0.2.7, "2001:db8::7"]}
tasks:
  nas:
    sources: [wan]
    endpoints: {home: [nas]}
discovery: {ipv6: false}
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
		`ipv6ddns_resolver_upstream_failures_total{resolver="lan",upstream="127.0.0.1:`,
	} {
		if !strings.Contains(metrics.String(), want) {
			t.Errorf("metrics without %s:\n%s", want, metrics.String())
		}
	}
	if report := w.PrettyPrint("", true); !strings.Contains(report, "Resolvers:\n    lan: serving\n        Listening: "+address) {
		t.Errorf("report:\n%s", report)
	}

	other := resolverWorker(t, port)
	otherCtx, otherCancel := context.WithCancel(context.Background())
	defer otherCancel()
	if err := other.Start(otherCtx); err == nil || !strings.Contains(err.Error(), "resolvers.lan.listen: ") || !strings.Contains(err.Error(), "address already in use") {
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
