//go:build linux && integration

package main

// A push source, as the command serves it, sent to by real DynDNS clients: inadyn, which UniFi's
// gateways run, ddclient, which OPNsense runs, and curl with the URL a Fritz!Box makes.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/internal/livetest"
)

// The addresses the instance's source has, as /status.json tells them.
func pushedAddresses(i *instance, name string) []string {
	for _, s := range i.status().Sources {
		if s.Name == name {
			return slices.Sorted(slices.Values(s.Addresses))
		}
	}
	return nil
}

// A machine runs ipv6ddns with a push source, wan; the router sends it its public addresses with
// inadyn, as UniFi's gateways do, then with ddclient, IPv4 and IPv6 at once, then a Fritz!Box's
// URL with curl, the password in it; a wrong password changes nothing; and the addresses are
// there again after a restart.
func TestLivePush(t *testing.T) {
	for _, tool := range []string{"inadyn", "ddclient", "curl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("the live test of the push source runs %s, as tools/live-test.sh installs it: not found", tool)
		}
	}
	lan := livetest.NewLAN(t, 28)
	srv := lan.Machine(t, "srv", 10)
	router := lan.Router
	server := srv.IPv4.String() + ":8053"

	config := `
webserver:
  listen:
    - 8053
sources:
  wan:
    type: push
    password: secret
tasks: {}
credentials: {}
`
	one := configure(t, srv, router, "srv", 8053, config).start().serving()
	dir := t.TempDir()
	run := func(name string, args ...string) {
		t.Helper()
		cmd := router.Command(name, args...)
		cmd.Stderr = nil
		out, err := cmd.CombinedOutput()
		t.Logf("%s: %v\n%s", name, err, out)
	}
	expect := func(what string, want ...string) {
		t.Helper()
		slices.Sort(want)
		waitFor(t, 10*time.Second, what, func() bool { return slices.Equal(pushedAddresses(one, "wan"), want) }, func() string {
			return fmt.Sprintf("the source has %v, want %v\n%s", pushedAddresses(one, "wan"), want, one.tells())
		})
	}

	// inadyn, with UniFi's path, the public address from a command, as its own check finds it.
	inadynConf := filepath.Join(dir, "inadyn.conf")
	os.WriteFile(inadynConf, fmt.Appendf(nil, `
custom unifi {
    ssl = false
    ddns-server = %q
    ddns-path = "/nic/update?hostname=%%h&myip=%%i"
    username = router
    password = secret
    hostname = wan
    checkip-command = "echo 203.0.113.9"
}
`, server), 0o600)
	run("inadyn", "--once", "--foreground", "--force", "-f", inadynConf, "--cache-dir", filepath.Join(dir, "inadyn"))
	expect("inadyn's IPv4", "203.0.113.9")

	// ddclient, dyndns2, both families in one request.
	// Its commands are programs, not lines of a shell: a script of each address.
	script := func(name, address string) string {
		path := filepath.Join(dir, name)
		os.WriteFile(path, []byte("#!/bin/sh\necho "+address+"\n"), 0o755)
		return path
	}
	ddclientConf := filepath.Join(dir, "ddclient.conf")
	os.WriteFile(ddclientConf, fmt.Appendf(nil, `
ssl=no
usev4=cmdv4, cmdv4=%s
usev6=cmdv6, cmdv6=%s
protocol=dyndns2
server=%s
login=router
password=secret
wan
`, script("v4", "203.0.113.10"), script("v6", "2001:db8::10"), server), 0o600)
	run("ddclient", "-foreground", "-daemon=0", "-force", "-file", ddclientConf, "-cache", filepath.Join(dir, "ddclient.cache"))
	expect("ddclient's IPv4 and IPv6", "203.0.113.10", "2001:db8::10")

	// A Fritz!Box's URL, with the password in it, and no IPv6 this time: the IPv6 stays.
	run("curl", "-fsS", "http://"+server+"/nic/update?hostname=wan&myip=203.0.113.11&myipv6=&ip6lanprefix=2001:db8:5:6::/64&password=secret")
	expect("a Fritz!Box's IPv4", "203.0.113.11", "2001:db8::10")
	for _, s := range one.status().Sources {
		if s.Name == "wan" && s.Prefix != "2001:db8:5:6::/64" {
			t.Errorf("the prefix of the LAN: %q", s.Prefix)
		}
	}

	// A wrong password changes nothing.
	run("curl", "-sS", "-u", "router:wrong", "http://"+server+"/nic/update?hostname=wan&myip=203.0.113.99")
	expect("after a wrong password", "203.0.113.11", "2001:db8::10")

	// After a restart, the addresses the router sent last, from the source's file.
	one.terminate()
	two := one.start().serving()
	if got := pushedAddresses(two, "wan"); !slices.Equal(got, []string{"2001:db8::10", "203.0.113.11"}) {
		t.Errorf("after a restart: %v", got)
	}
}
