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
