//go:build linux && integration

package main

// The web server's HTTPS, as the command serves it, asked by curl.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/miguelangel-nubla/ipv6ddns/internal/livetest"
)

// A machine runs ipv6ddns with a web server of HTTP and of HTTPS, of a certificate of the test's
// authority: curl, which trusts it, gets /healthz over HTTPS, by HTTP/2, at the name of the
// certificate; over HTTP still at the plain entry; and a router's update over HTTPS. The report
// tells the certificate.
func TestLiveWebserverHTTPS(t *testing.T) {
	lan := livetest.NewLAN(t, 29)
	srv := lan.Machine(t, "srv", 10)
	client := lan.Machine(t, "client", 30)
	caFile, certFile, keyFile := writeTestCA(t, t.TempDir())
	address := srv.IPv4.String()
	config := fmt.Sprintf(`
webserver:
  listen:
    - 8053
    - "https://%[1]s"
  tls:
    certificate: %[2]s
    key: %[3]s
sources:
  wan:
    type: push
    password: secret
tasks: {}
credentials: {}
`, address, certFile, keyFile)
	one := configure(t, srv, lan.Router, "srv", 8053, config).start().serving()
	curl := func(args ...string) string {
		t.Helper()
		cmd := client.Command("curl", append([]string{"-sS", "--max-time", "5", "--cacert", caFile, "--resolve", encryptedHost + ":8443:" + address}, args...)...)
		cmd.Stderr = nil
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("curl %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	if got := curl("-w", " %{http_version}", "https://"+encryptedHost+":8443/healthz"); got != "ok\n 2" && got != "ok 2" {
		t.Errorf("/healthz over HTTPS: %q", got)
	}
	if got := curl("http://" + address + ":8053/healthz"); got != "ok" {
		t.Errorf("/healthz over HTTP: %q", got)
	}
	if got := curl("-u", "router:secret", "https://"+encryptedHost+":8443/nic/update?hostname=wan&myip=203.0.113.9"); got != "good 203.0.113.9" {
		t.Errorf("an update over HTTPS: %q", got)
	}
	// A client that expects another name doesn't take the certificate.
	cmd := client.Command("curl", "-sS", "--max-time", "5", "--cacert", caFile, "https://"+address+":8443/healthz")
	cmd.Stderr = nil
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Errorf("the certificate taken for the address, which it isn't for: %s", out)
	}
	if report := one.page("/status.txt"); !strings.Contains(report, "Webserver:\n    Certificate: "+encryptedHost+", until ") {
		t.Errorf("the report:\n%s", report)
	}
}
