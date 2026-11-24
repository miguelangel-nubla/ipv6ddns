package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/miguelangel-nubla/ipv6ddns"
	"github.com/miguelangel-nubla/ipv6ddns/config"
	"go.uber.org/zap"
)

// pushWorker is a worker with two push sources, wan and lab, each with its password, and a static
// one, behind the web server's handler.
func pushWorker(t *testing.T) (*ipv6ddns.Worker, http.Handler) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(`
webserver:
  listen: 127.0.0.1:8053
sources:
  wan:
    type: push
    password: secret
  lab:
    type: push
    password: other
  fixed:
    type: static
    addresses:
      - 192.0.2.1
tasks: {}
credentials: {}
`), 0o600)
	cfg, err := config.NewConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	w, err := ipv6ddns.NewWorker(zap.NewNop().Sugar(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	saved := refusedWait
	refusedWait = 0
	t.Cleanup(func() { refusedWait = saved })
	return w, webHandler(w)
}

// The dyndns2 protocol, as routers speak it: the source named by hostname, its password as basic
// or in the URL, myip with one address or two, myipv6 apart, an empty one ignored; good, then
// nochg; and each mistake with its word and its status.
func TestPushHandler(t *testing.T) {
	w, handler := pushWorker(t)
	ask := func(method, target, user, password string) (int, string) {
		t.Helper()
		req := httptest.NewRequest(method, target, nil)
		// From the LAN, as a router's.
		req.RemoteAddr = "192.168.1.1:40000"
		if user != "" || password != "" {
			req.SetBasicAuth(user, password)
		}
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		return resp.Code, strings.TrimSpace(resp.Body.String())
	}
	addresses := func(name string) []string {
		s, _ := w.PushSource(name)
		return slices.Sorted(slices.Values(s.Addresses().Strings()))
	}
	for _, tc := range []struct {
		name, method, target, user, password string
		status                               int
		body                                 string
	}{
		{"UniFi's inadyn", "GET", "/nic/update?hostname=wan&myip=203.0.113.9", "router", "secret", 200, "good 203.0.113.9"},
		{"the same again", "GET", "/nic/update?hostname=wan&myip=203.0.113.9", "router", "secret", 200, "nochg 203.0.113.9"},
		{"ddclient's two", "GET", "/nic/update?system=dyndns&hostname=wan&myip=203.0.113.9,2001:db8::9&wildcard=ON", "x", "secret", 200, "good 203.0.113.9,2001:db8::9"},
		{"an IPv6 apart, as OPNsense's", "GET", "/nic/update?hostname=wan&myip=2001:db8::10", "x", "secret", 200, "good 203.0.113.9,2001:db8::10"},
		{"Fritz!Box's, password in the URL, no IPv6", "GET", "/nic/update?hostname=wan&myip=203.0.113.10&myipv6=&password=secret", "", "", 200, "good 203.0.113.10,2001:db8::10"},
		{"a POST", "POST", "/nic/update?hostname=wan&myip=203.0.113.10", "x", "secret", 200, "nochg 203.0.113.10,2001:db8::10"},
		{"two sources", "GET", "/nic/update?hostname=wan,lab&myip=203.0.113.11", "x", "secret", 401, "badauth"},
		{"a wrong password", "GET", "/nic/update?hostname=wan&myip=203.0.113.12", "x", "Secret", 401, "badauth"},
		{"no password", "GET", "/nic/update?hostname=wan&myip=203.0.113.12", "", "", 401, "badauth"},
		{"another source's password", "GET", "/nic/update?hostname=wan&myip=203.0.113.12", "x", "other", 401, "badauth"},
		{"no such source", "GET", "/nic/update?hostname=nope&myip=203.0.113.12", "x", "secret", 404, "nohost"},
		{"a source that isn't pushed to", "GET", "/nic/update?hostname=fixed&myip=203.0.113.12", "x", "secret", 404, "nohost"},
		{"no hostname", "GET", "/nic/update?myip=203.0.113.12", "x", "secret", 400, "notfqdn"},
		{"not an address", "GET", "/nic/update?hostname=wan&myip=nonsense", "x", "secret", 400, "911"},
		{"no address, from a private one", "GET", "/nic/update?hostname=wan", "x", "secret", 400, "911"},
	} {
		code, body := ask(tc.method, tc.target, tc.user, tc.password)
		if code != tc.status || body != tc.body {
			t.Errorf("%s: %d %q, want %d %q", tc.name, code, body, tc.status, tc.body)
		}
	}
	if got := addresses("wan"); !slices.Equal(got, []string{"2001:db8::10", "203.0.113.10"}) {
		t.Errorf("wan has %v after the refused ones", got)
	}
	if got := addresses("lab"); len(got) != 0 {
		t.Errorf("lab has %v", got)
	}

	// Without myip, the address it comes from, when public: as from a router on the internet.
	req := httptest.NewRequest("GET", "/nic/update?hostname=lab", nil)
	req.SetBasicAuth("x", "other")
	req.RemoteAddr = "198.51.100.7:4321"
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if body := strings.TrimSpace(resp.Body.String()); resp.Code != 200 || body != "good 198.51.100.7" {
		t.Errorf("from a public address: %d %q", resp.Code, body)
	}
	// A refusal says how to log in.
	code, _ := ask("GET", "/nic/update?hostname=wan&myip=203.0.113.12", "", "")
	if code != 401 {
		t.Fatal(code)
	}
}
