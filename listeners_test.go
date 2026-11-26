package ipv6ddns

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/certfile"
	"go.uber.org/zap"
)

// The listeners and the web servers, in the status and the report alike: each listener's entries,
// the sockets open of them, its certificate and server_name, its servers and its allow; each web
// server's listeners and sockets.
func TestListenersStatus(t *testing.T) {
	certFile, keyFile := selfSigned(t, t.TempDir(), "dns.lan.example.com", "status.lan.example.com")
	cfg := certificateConfig(t, "\n    certificate: "+certFile+"\n    key: "+keyFile, "")
	lan := cfg.Listeners["lan"]
	lan.ServerName = "dns.lan.example.com"
	cfg.Listeners["lan"] = lan
	w, err := NewWorker(zap.NewNop().Sugar(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.discWorker.State.Close)

	// Before they serve: no sockets.
	st := w.Status(false)
	if len(st.Listeners) != 2 || len(st.Listeners[0].Sockets) != 0 || len(st.Webservers) != 1 || len(st.Webservers[0].Sockets) != 0 {
		t.Fatalf("the status before serving: %+v %+v", st.Listeners, st.Webservers)
	}
	if !strings.Contains(w.Page("", false).String(), "    lan\n        Listen: tls://127.0.0.1:") || !strings.Contains(w.Page("", false).String(), "        Sockets: none yet\n") {
		t.Errorf("the report before serving:\n%s", w.Page("", false).String())
	}

	if err := w.resolvers[0].Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		w.resolvers[0].Shutdown(ctx)
	})
	w.WebListening("web", "https://127.0.0.1:8443")

	st = w.Status(false)
	l, web := st.Listeners[0], st.Listeners[1]
	if l.Name != "lan" || l.TLS != "home" || l.ServerName != "dns.lan.example.com" || l.Resolver != "lan" || l.Webserver != "" ||
		len(l.Sockets) != 1 || !strings.HasPrefix(l.Sockets[0], "tls://127.0.0.1:") || !slices.Equal(l.Listen, cfg.Listeners["lan"].Listen) {
		t.Errorf("the listener lan: %+v", l)
	}
	if web.Name != "web" || web.Webserver != "main" || web.Resolver != "" || !slices.Equal(web.Sockets, []string{"https://127.0.0.1:8443"}) || len(web.Allow) != 0 {
		t.Errorf("the listener web: %+v", web)
	}
	if s := st.Webservers[0]; s.Name != "main" || !slices.Equal(s.Listeners, []string{"web"}) || !slices.Equal(s.Sockets, []string{"https://127.0.0.1:8443"}) {
		t.Errorf("the web server: %+v", s)
	}
	data, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"listeners":[{"name":"lan"`, `"server_name":"dns.lan.example.com"`, `"resolver":"lan"`, `"webserver":"main"`, `"webservers":[{"name":"main","listeners":["web"],"sockets":["https://127.0.0.1:8443"]`, `"listeners":["lan","web"]`} {
		if !strings.Contains(string(data), key) {
			t.Errorf("the status's JSON has no %s: %s", key, data)
		}
	}

	page := w.Page("", false).String()
	for _, has := range []string{
		"Listeners:\n    lan\n        Listen: tls://127.0.0.1:",
		"        Sockets: " + l.Sockets[0] + "\n        TLS: home, server name dns.lan.example.com\n        Used by: resolver lan\n        Allow: none, its servers'\n",
		"    web\n", "        Used by: web server main\n", "        Sockets: https://127.0.0.1:8443\n",
		"Web servers:\n    main\n        Listeners: web\n        Sockets: https://127.0.0.1:8443\n        Allow: none, its listeners'\n",
	} {
		if !strings.Contains(page, has) {
			t.Errorf("the report has no %q:\n%s", has, page)
		}
	}
}

// A certificate of acme tells its names, as written, and its credential; and the metrics tell
// until when each certificate is, whether the last attempt of acme failed, and when the next is.
func TestCertificateConfigAndMetrics(t *testing.T) {
	end, next := time.Unix(1900000000, 0), time.Unix(1800000000, 0)
	statuses := []CertificateStatus{
		{Name: "home", UsedBy: []string{"listeners.lan"}, Listeners: []string{"lan"}, Status: &certfile.Status{Names: []string{"dns.lan.example.com"}, NotAfter: end}},
		{Name: "public", UsedBy: []string{"listeners.web"}, Listeners: []string{"web"}, ACMENames: []string{"dns", "status"}, Credential: "cloudflare",
			Status: &certfile.Status{Managed: true, Renewal: "ordering: 429 rate limited", NextAttempt: next}},
	}
	page := certificatesPage("", statuses, end.Add(-60*24*time.Hour)).String()
	if want := "    public (listener web): none yet (getting it failed: ordering: 429 rate limited; again at 2027-01-15 08:00 UTC)\n        ACME: dns, status, by credential cloudflare\n"; !strings.Contains(page, want) {
		t.Errorf("the report has no %q:\n%s", want, page)
	}
	if strings.Count(page, "ACME:") != 1 {
		t.Errorf("a certificate of files has an ACME line:\n%s", page)
	}

	var metrics strings.Builder
	if err := (Status{Certificates: statuses}).WriteMetrics(&metrics); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ipv6ddns_certificate_expiry_timestamp_seconds{certificate=\"home\"} 1900000000\n",
		"ipv6ddns_certificate_last_renewal_failed{certificate=\"public\"} 1\n",
		"ipv6ddns_certificate_next_attempt_timestamp_seconds{certificate=\"public\"} 1800000000\n",
	} {
		if !strings.Contains(metrics.String(), want) {
			t.Errorf("the metrics have no %q:\n%s", want, metrics.String())
		}
	}
	for _, not := range []string{`expiry_timestamp_seconds{certificate="public"}`, `last_renewal_failed{certificate="home"}`, `next_attempt_timestamp_seconds{certificate="home"}`} {
		if strings.Contains(metrics.String(), not) {
			t.Errorf("the metrics have %s:\n%s", not, metrics.String())
		}
	}
}
