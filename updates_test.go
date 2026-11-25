package ipv6ddns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/ddns"
	"github.com/miguelangel-nubla/ipv6disc"
	"go.uber.org/zap"
)

// txtRecorder is a provider of the tests' whose TXT records are kept, each SetTXT noted: of the
// zone rec.test, by its id.
type txtRecorder struct {
	mutex sync.Mutex
	calls []string
	txt   map[string][]string
	fail  error
}

var (
	txtRecordersMutex sync.Mutex
	txtRecorders      = map[string]*txtRecorder{}
)

func init() {
	ddns.RegisterProvider("txtrec", func(settings json.RawMessage) (ddns.Service, error) {
		var s struct{ ID string }
		if err := json.Unmarshal(settings, &s); err != nil || s.ID == "" {
			return nil, errors.New("txtrec: no id")
		}
		r := &txtRecorder{txt: map[string][]string{}}
		txtRecordersMutex.Lock()
		txtRecorders[s.ID] = r
		txtRecordersMutex.Unlock()
		return r, nil
	})
}

func (r *txtRecorder) Update(string, *ipv6disc.AddrCollection) error { return nil }
func (r *txtRecorder) Domain(hostname string) string                 { return ddns.FQDN(hostname, "rec.test") }
func (r *txtRecorder) FullName(hostname string) (string, error)      { return r.Domain(hostname), nil }
func (r *txtRecorder) SetTXT(name string, values []string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.fail != nil {
		return r.fail
	}
	r.calls = append(r.calls, fmt.Sprintf("%s %q", name, values))
	r.txt[name] = values
	return nil
}

func (r *txtRecorder) callsSoFar() []string {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return slices.Clone(r.calls)
}

// updatesTestSecret is a key's secret, of 32 bytes.
const updatesTestSecret = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

// challengesWorker is a worker with a resolver at port, whose key nas may write the challenges of
// nas.lan and *.apps through a txtrec credential, of id; started, and stopped with the test.
func challengesWorker(t *testing.T, port, id string) *Worker {
	t.Helper()
	w := workerOf(t, fmt.Sprintf(`
credentials:
  public:
    provider: txtrec
    settings:
      id: %s
resolvers:
  lan:
    listen: 127.0.0.1:%s
    upstream: 127.0.0.1:%s
    updates:
      keys:
        nas:
          secret: %s
          permissions:
            - challenges:
                credential: public
                names:
                  - nas.lan
                  - "*.apps"
sources:
  wan:
    type: static
    addresses:
      - 192.0.2.7
tasks:
  nas:
    sources:
      - wan
    endpoints:
      public:
        - nas
discovery:
  ipv6:
    enabled: false
`, id, port, freeDNSPort(t), updatesTestSecret))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return w
}

// signed sends m signed with the key nas, and checks the response's signature.
func signed(t *testing.T, address string, m *dns.Msg) *dns.Msg {
	t.Helper()
	m.SetTsig("nas.", dns.HmacSHA256, 300, time.Now().Unix())
	c := &dns.Client{Timeout: 3 * time.Second, TsigSecret: map[string]string{"nas.": updatesTestSecret}}
	resp, _, err := c.Exchange(m, address)
	if err != nil {
		t.Fatalf("%v: %v", resp, err)
	}
	return resp
}

func challengeUpdate(t *testing.T, change func(m *dns.Msg, txt func(name, value string) dns.RR)) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetUpdate("rec.test.")
	change(m, func(name, value string) dns.RR {
		rr, err := dns.NewRR(fmt.Sprintf(`%s 60 IN TXT "%s"`, name, value))
		if err != nil {
			t.Fatal(err)
		}
		return rr
	})
	return m
}

// A certificate's challenges, sent as certbot does: the zone found, two values of one name at
// once, removed one by one; and what the provider was given at each.
func TestUpdatesChallenges(t *testing.T) {
	port := freeDNSPort(t)
	w := challengesWorker(t, port, "challenges")
	rec := txtRecorders["challenges"]
	address := net.JoinHostPort("127.0.0.1", port)

	// The zone, as certbot finds it: up from the challenge's name, to the first SOA answered with
	// authority.
	for _, c := range []struct {
		name string
		soa  bool
	}{
		{"_acme-challenge.nas.lan.rec.test.", false},
		{"nas.lan.rec.test.", false},
		{"lan.rec.test.", false},
		{"rec.test.", true},
	} {
		m := new(dns.Msg)
		m.SetQuestion(c.name, dns.TypeSOA)
		resp := signed(t, address, m)
		if !resp.Authoritative || (len(resp.Answer) == 1) != c.soa {
			t.Errorf("SOA of %s: %v", c.name, resp)
		}
	}

	apps := "_acme-challenge.apps.rec.test."
	for _, step := range []struct {
		what   string
		change func(m *dns.Msg, txt func(name, value string) dns.RR)
		want   string
	}{
		{"apps", func(m *dns.Msg, txt func(string, string) dns.RR) { m.Insert([]dns.RR{txt(apps, "one")}) },
			`_acme-challenge.apps.rec.test ["one"]`},
		{"*.apps, beside", func(m *dns.Msg, txt func(string, string) dns.RR) { m.Insert([]dns.RR{txt(apps, "two")}) },
			`_acme-challenge.apps.rec.test ["one" "two"]`},
		{"apps removed", func(m *dns.Msg, txt func(string, string) dns.RR) { m.Remove([]dns.RR{txt(apps, "one")}) },
			`_acme-challenge.apps.rec.test ["two"]`},
		{"*.apps removed", func(m *dns.Msg, txt func(string, string) dns.RR) { m.Remove([]dns.RR{txt(apps, "two")}) },
			`_acme-challenge.apps.rec.test []`},
		{"nas.lan", func(m *dns.Msg, txt func(string, string) dns.RR) {
			m.Insert([]dns.RR{txt("_acme-challenge.nas.lan.rec.test.", "three")})
		}, `_acme-challenge.nas.lan.rec.test ["three"]`},
	} {
		if resp := signed(t, address, challengeUpdate(t, step.change)); resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("%s: %s", step.what, dns.RcodeToString[resp.Rcode])
		}
		if calls := rec.callsSoFar(); len(calls) == 0 || calls[len(calls)-1] != step.want {
			t.Errorf("%s: the provider got %q, want %s last", step.what, calls, step.want)
		}
	}

	// Of a name it hasn't, or of a record not TXT: refused, the provider not asked.
	before := len(rec.callsSoFar())
	for _, change := range []func(m *dns.Msg, txt func(string, string) dns.RR){
		func(m *dns.Msg, txt func(string, string) dns.RR) {
			m.Insert([]dns.RR{txt("_acme-challenge.www.rec.test.", "x")})
		},
		func(m *dns.Msg, txt func(string, string) dns.RR) {
			m.Insert([]dns.RR{txt("nas.lan.rec.test.", "x")})
		},
	} {
		if resp := signed(t, address, challengeUpdate(t, change)); resp.Rcode != dns.RcodeRefused {
			t.Errorf("out of its names: %s", dns.RcodeToString[resp.Rcode])
		}
	}
	if len(rec.callsSoFar()) != before {
		t.Errorf("the provider was asked: %q", rec.callsSoFar()[before:])
	}

	// The provider fails: SERVFAIL, and the value isn't kept as written.
	rec.mutex.Lock()
	rec.fail = errors.New("the API is down")
	rec.mutex.Unlock()
	resp := signed(t, address, challengeUpdate(t, func(m *dns.Msg, txt func(string, string) dns.RR) {
		m.Insert([]dns.RR{txt(apps, "lost")})
	}))
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("the provider failed: %s", dns.RcodeToString[resp.Rcode])
	}
	rec.mutex.Lock()
	rec.fail = nil
	rec.mutex.Unlock()
	q := new(dns.Msg)
	q.SetQuestion(apps, dns.TypeTXT)
	if resp := signed(t, address, q); len(resp.Answer) != 0 {
		t.Errorf("a value the provider didn't write: %v", resp.Answer)
	}

	// The status, the report and the metrics tell of the key.
	st := w.Status(true)
	keys := st.Resolvers[0].Keys
	if len(keys) != 1 || keys[0].Updates["applied"] != 5 || keys[0].Updates["refused"] != 2 || keys[0].Updates["failed"] != 1 ||
		!strings.Contains(keys[0].LastMessage, "the API is down") {
		t.Errorf("the key's status: %+v", keys)
	}
	if page := w.PrettyPrint("", true); !strings.Contains(page, "nas (challenges): applied 5, refused 2, failed 1") {
		t.Errorf("the report:\n%s", page)
	}
	var metrics strings.Builder
	st.WriteMetrics(&metrics)
	if !strings.Contains(metrics.String(), `ipv6ddns_resolver_updates_total{resolver="lan",key="nas",result="applied"} 5`) {
		t.Errorf("the metrics:\n%s", metrics.String())
	}
}

// A value its client left is removed, once its time is over.
func TestUpdatesChallengeExpires(t *testing.T) {
	old := challengeExpiry
	challengeExpiry = 200 * time.Millisecond
	t.Cleanup(func() { challengeExpiry = old })
	port := freeDNSPort(t)
	challengesWorker(t, port, "expires")
	rec := txtRecorders["expires"]
	resp := signed(t, net.JoinHostPort("127.0.0.1", port), challengeUpdate(t, func(m *dns.Msg, txt func(string, string) dns.RR) {
		m.Insert([]dns.RR{txt("_acme-challenge.nas.lan.rec.test.", "left")})
	}))
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatal(dns.RcodeToString[resp.Rcode])
	}
	want := []string{`_acme-challenge.nas.lan.rec.test ["left"]`, `_acme-challenge.nas.lan.rec.test []`}
	for deadline := time.Now().Add(3 * time.Second); !slices.Equal(rec.callsSoFar(), want); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the provider got %q, want %q", rec.callsSoFar(), want)
		}
	}
}

// A credential whose provider can't write TXT records: an error at start, naming the permission.
func TestUpdatesChallengesNoTXT(t *testing.T) {
	cfg := fmt.Sprintf(`
credentials:
  plain:
    provider: fake
    settings:
      id: notxt
resolvers:
  lan:
    listen: 127.0.0.1:%s
    upstream: 127.0.0.1:%s
    updates:
      keys:
        nas:
          secret: %s
          permissions:
            - challenges:
                credential: plain
                names:
                  - nas
tasks:
  nas:
    filter:
      - mac:
          address: "00:11:22:33:44:55"
    endpoints:
      plain:
        - nas
`, freeDNSPort(t), freeDNSPort(t), updatesTestSecret)
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := config.NewConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewWorker(zap.NewNop().Sugar(), c)
	want := "resolvers.lan.updates.keys.nas.permissions[0].challenges.credential: the provider of plain, fake, can't write the TXT records of the DNS challenge"
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("%v, want %s", err, want)
	}
}

// addressesWorker is a worker with a resolver at port, whose key nas may send the addresses of
// vps.example.com to the push source vps, of no password, kept in state; and the task vps, which
// gives them to the fake provider of id. Started, and stopped with ctx.
func addressesWorker(t *testing.T, ctx context.Context, port, id, state string) *Worker {
	t.Helper()
	w := workerOf(t, fmt.Sprintf(`
credentials:
  public:
    provider: fake
    settings:
      id: %s
    debounce: 1ms
resolvers:
  lan:
    listen: 127.0.0.1:%s
    upstream: 127.0.0.1:%s
    updates:
      keys:
        nas:
          secret: %s
          permissions:
            - addresses:
                source: vps
                zone: example.com
sources:
  vps:
    type: push
    state_file: %s
tasks:
  vps:
    sources:
      - vps
    endpoints:
      public:
        - vps
discovery:
  ipv6:
    enabled: false
`, id, port, freeDNSPort(t), updatesTestSecret, state))
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return w
}

func addressUpdate(t *testing.T, change func(m *dns.Msg, rr func(string) dns.RR)) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetUpdate("example.com.")
	change(m, func(line string) dns.RR {
		r, err := dns.NewRR("vps.example.com. " + line)
		if err != nil {
			t.Fatal(err)
		}
		return r
	})
	return m
}

// A host's own addresses, sent as nsupdate does: they become the push source's, the task's
// provider gets them, and a restart keeps them.
func TestUpdatesAddresses(t *testing.T) {
	port := freeDNSPort(t)
	state := filepath.Join(t.TempDir(), "push-vps.json")
	ctx, cancel := context.WithCancel(context.Background())
	w := addressesWorker(t, ctx, port, "addresses", state)
	address := net.JoinHostPort("127.0.0.1", port)
	service := fakeServices["addresses"]

	for _, step := range []struct {
		what   string
		change func(m *dns.Msg, rr func(string) dns.RR)
		rcode  int
		want   []string
	}{
		{"its IPv4", func(m *dns.Msg, rr func(string) dns.RR) {
			m.RemoveRRset([]dns.RR{rr("0 IN A 0.0.0.0")})
			m.Insert([]dns.RR{rr("300 IN A 192.0.2.7")})
		}, dns.RcodeSuccess, []string{"192.0.2.7"}},
		{"its IPv6, beside", func(m *dns.Msg, rr func(string) dns.RR) {
			m.Insert([]dns.RR{rr("300 IN AAAA 2001:db8::7"), rr("300 IN AAAA 2001:db8::8")})
		}, dns.RcodeSuccess, []string{"192.0.2.7", "2001:db8::7", "2001:db8::8"}},
		{"one removed", func(m *dns.Msg, rr func(string) dns.RR) {
			m.Remove([]dns.RR{rr("0 IN AAAA 2001:db8::8")})
		}, dns.RcodeSuccess, []string{"192.0.2.7", "2001:db8::7"}},
		{"the IPv4 removed, if it has IPv6", func(m *dns.Msg, rr func(string) dns.RR) {
			m.RRsetUsed([]dns.RR{rr("0 IN AAAA ::")})
			m.RemoveRRset([]dns.RR{rr("0 IN A 0.0.0.0")})
		}, dns.RcodeSuccess, []string{"2001:db8::7"}},
		{"a prerequisite that fails", func(m *dns.Msg, rr func(string) dns.RR) {
			m.RRsetUsed([]dns.RR{rr("0 IN A 0.0.0.0")})
			m.Insert([]dns.RR{rr("300 IN A 192.0.2.99")})
		}, dns.RcodeNXRrset, []string{"2001:db8::7"}},
		{"a TXT record", func(m *dns.Msg, rr func(string) dns.RR) {
			m.Insert([]dns.RR{rr(`300 IN TXT "x"`)})
		}, dns.RcodeRefused, []string{"2001:db8::7"}},
	} {
		if resp := signed(t, address, addressUpdate(t, step.change)); resp.Rcode != step.rcode {
			t.Errorf("%s: %s, want %s", step.what, dns.RcodeToString[resp.Rcode], dns.RcodeToString[step.rcode])
		}
		if got := slices.Sorted(slices.Values(w.sources["vps"].Addresses().Strings())); !slices.Equal(got, step.want) {
			t.Errorf("%s: the source has %v, want %v", step.what, got, step.want)
		}
	}
	// Another name of the zone: refused.
	m := new(dns.Msg)
	m.SetUpdate("example.com.")
	other, _ := dns.NewRR("www.example.com. 300 IN A 192.0.2.1")
	m.Insert([]dns.RR{other})
	if resp := signed(t, address, m); resp.Rcode != dns.RcodeRefused {
		t.Errorf("another name: %s", dns.RcodeToString[resp.Rcode])
	}
	service.waitFor(t, "vps", "2001:db8::7")

	// Asked, signed: the source's addresses, with authority.
	q := new(dns.Msg)
	q.SetQuestion("vps.example.com.", dns.TypeAAAA)
	if resp := signed(t, address, q); !resp.Authoritative || len(resp.Answer) != 1 || resp.Answer[0].(*dns.AAAA).AAAA.String() != "2001:db8::7" {
		t.Errorf("asked: %v", resp)
	}

	// A restart: the source's file has them, and the resolver answers them again.
	cancel()
	stopping, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err := w.Shutdown(stopping); err != nil {
		t.Fatal(err)
	}
	port = freeDNSPort(t)
	ctx, cancel = context.WithCancel(context.Background())
	t.Cleanup(cancel)
	addressesWorker(t, ctx, port, "addresses-again", state)
	if resp := signed(t, net.JoinHostPort("127.0.0.1", port), q); len(resp.Answer) != 1 {
		t.Errorf("after a restart: %v", resp)
	}
	fakeServices["addresses-again"].waitFor(t, "vps", "2001:db8::7")
}
