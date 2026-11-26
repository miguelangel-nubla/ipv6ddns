package config

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// sharedCredential is a zone of the resolver lan.
const sharedCredential = `
  home:
    provider: resolver
    settings:
      resolver: lan
      zone: home.arpa`

// sharedConfig is a configuration of two resolvers, lan and kids, each of its listener, whose
// entries and keys are lan's and kids', with certificates of the names given: lan's, dns, and
// kids', local; of no names given dns, local alone.
func sharedConfig(t *testing.T, lan, kids string, dnsNames, localNames []string) (Config, error) {
	t.Helper()
	localCert, localKey := writeTestCertificateFor(t, localNames...)
	dns := ""
	if dnsNames != nil {
		dnsCert, dnsKey := writeTestCertificateFor(t, dnsNames...)
		dns = `
  dns:
    certificate: ` + dnsCert + `
    key: ` + dnsKey
	}
	text := `listeners:
  lan:` + lan + `
  kids:` + kids + `
resolvers:
  lan:
    listeners:
      - lan
    upstream:
      - 192.168.1.1
  kids:
    listeners:
      - kids
    upstream:
      - 192.168.1.1
certificates:` + dns + `
  local:
    certificate: ` + localCert + `
    key: ` + localKey + `
` + "credentials:\n" + sharedCredential + "\ntasks:\n" + nasTask + "\n"
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return NewConfig(path)
}

// Encrypted entries of two listeners on one address and port, of one scheme, are shared: each
// resolver has its own, of its listener's certificate, allow and server name, in the order the
// listeners are written, however spelled, a port given or not; plain DNS of each stays its own.
func TestListenersShared(t *testing.T) {
	// kids is written after lan, though before it by name: lan is the first.
	cfg, err := sharedConfig(t, `
    listen:
      - tls://127.0.0.1
      - quic://127.0.0.1
      - https://127.0.0.1:8443
    tls: dns`, `
    listen:
      - dns://127.0.0.1:5300
      - tls://127.0.0.1:853
      - quic://127.0.0.1
      - https://127.0.0.1:8443/dns-query
    tls: local
    server_name: kids.dns.local.example.com
    allow:
      - 127.0.0.2/32`, []string{"dns.lan.example.com"}, []string{"dns.local.example.com", "*.dns.local.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if lan, kids := cfg.Listeners["lan"].Rank, cfg.Listeners["kids"].Rank; lan != 0 || kids != 1 {
		t.Errorf("ranks: lan %d, kids %d; want 0, 1", lan, kids)
	}
	for _, c := range []struct {
		resolver, listener, serverName string
		rank                           int
	}{
		{"lan", "lan", "", 0},
		{"kids", "kids", "kids.dns.local.example.com", 1},
	} {
		spec := cfg.Resolvers[c.resolver].Spec
		if len(spec.Encrypted) != 3 {
			t.Fatalf("%s: %d encrypted entries, want 3: %v", c.resolver, len(spec.Encrypted), spec.Encrypted)
		}
		for _, e := range spec.Encrypted {
			if !e.Shared || e.Listener != c.listener || e.Rank != c.rank || e.ServerName != c.serverName {
				t.Errorf("%s: %s: shared %t, listener %s, rank %d, server name %q", c.resolver, e.Line, e.Shared, e.Listener, e.Rank, e.ServerName)
			}
		}
	}
	if spec := cfg.Resolvers["kids"].Spec; len(spec.Listen) != 1 || spec.Listen[0].String() != "127.0.0.1:5300" {
		t.Errorf("kids's plain DNS: %v", spec.Listen)
	}
}

// Two listeners of one certificate, or of certificates both for a name, share a port when the
// second has a server name: a client that asks it gets the second, and one that asks another name
// of both, the first. The first needs none.
func TestListenersSharedOneCertificate(t *testing.T) {
	localNames := []string{"dns.local.example.com", "*.dns.local.example.com"}
	for _, c := range []struct {
		name, lan, kids  string
		dnsNames, locals []string
	}{
		{"one certificate, both with a server name", `
    listen:
      - tls://127.0.0.1
      - https://127.0.0.1:8443
    tls: local
    server_name: dns.local.example.com`, `
    listen:
      - tls://127.0.0.1
      - https://127.0.0.1:8443
    tls: local
    server_name: kids.dns.local.example.com`, nil, localNames},
		{"one certificate, the first without a server name", `
    listen:
      - tls://127.0.0.1
    tls: local`, `
    listen:
      - tls://127.0.0.1
    tls: local
    server_name: kids.dns.local.example.com`, nil, localNames},
		{"certificates both for a name", `
    listen:
      - tls://127.0.0.1
    tls: dns`, `
    listen:
      - tls://127.0.0.1
    tls: local
    server_name: kids.dns.local.example.com`, []string{"kids.dns.local.example.com"}, localNames},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := sharedConfig(t, c.lan, c.kids, c.dnsNames, c.locals)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"lan", "kids"} {
				for _, e := range cfg.Resolvers[name].Spec.Encrypted {
					if !e.Shared || e.Listener != name {
						t.Errorf("%s: %s: shared %t, listener %s", name, e.Line, e.Shared, e.Listener)
					}
				}
			}
		})
	}
}

// Entries on different addresses or ports, or of different protocols, aren't shared.
func TestListenersNotShared(t *testing.T) {
	cfg, err := sharedConfig(t, `
    listen:
      - tls://127.0.0.1
    tls: dns`, `
    listen:
      - tls://127.0.0.1:8853
      - quic://127.0.0.1
    tls: local`, []string{"dns.lan.example.com"}, []string{"dns.local.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"lan", "kids"} {
		for _, e := range cfg.Resolvers[name].Spec.Encrypted {
			if e.Shared {
				t.Errorf("%s: %s is shared", name, e.Line)
			}
		}
	}
}

// What can't be shared, or tell its listeners apart, is refused, saying where and what to write.
func TestListenersSharedErrors(t *testing.T) {
	lan := `
    listen:
      - tls://127.0.0.1
    tls: dns`
	dnsNames, localNames := []string{"dns.lan.example.com"}, []string{"dns.local.example.com", "*.dns.local.example.com"}
	for _, c := range []struct {
		name, lan, kids  string
		dnsNames, locals []string
		want             string
	}{
		{"two schemes on one TCP port", lan, `
    listen:
      - https://127.0.0.1:853
    tls: local`, dnsNames, localNames, "listeners.kids.listen: https://127.0.0.1:853 is on the address and port of listeners.lan's tls://127.0.0.1: only entries of one scheme share a port"},
		{"every address and one of them", lan, `
    listen:
      - tls://853
    tls: local`, dnsNames, localNames, "listeners.kids.listen: tls://853 is on port 853, as listeners.lan's tls://127.0.0.1, and one of them is on every address, two sockets that can't both listen: to share the port, write the same address in both, as tls://127.0.0.1"},
		{"one certificate", lan, `
    listen:
      - tls://127.0.0.1
    tls: dns`, dnsNames, localNames, "listeners.kids.tls: listeners lan and kids share tls://127.0.0.1 with one certificate, dns"},
		{"a name of both", lan, `
    listen:
      - tls://127.0.0.1
    tls: local`, dnsNames, []string{"dns.local.example.com", "dns.lan.example.com"}, "listeners.kids.tls: listeners lan and kids share tls://127.0.0.1, and both their certificates, dns and local, are for dns.lan.example.com"},
		{"a wildcard of the other's name", lan, `
    listen:
      - tls://127.0.0.1
    tls: local`, []string{"kids.dns.local.example.com"}, localNames, "listeners.kids.tls: listeners lan and kids share tls://127.0.0.1, and both their certificates, dns and local, are for kids.dns.local.example.com"},
		{"one certificate, the second without a server name", `
    listen:
      - tls://127.0.0.1
    tls: local
    server_name: dns.local.example.com`, `
    listen:
      - tls://127.0.0.1
    tls: local`, dnsNames, localNames, "listeners.kids.tls: listeners lan and kids share tls://127.0.0.1 with one certificate, local, and the name a client asks can't tell them apart: add a server_name to kids, a name of the certificate its clients ask, as server_name: kids.dns.local.example.com, or give each"},
		{"one server name of both", `
    listen:
      - tls://127.0.0.1
    tls: local
    server_name: kids.dns.local.example.com`, `
    listen:
      - tls://127.0.0.1
    tls: local
    server_name: KIDS.dns.local.example.com.`, dnsNames, localNames, "listeners.kids.server_name: listeners lan and kids share tls://127.0.0.1, and both have the server_name KIDS.dns.local.example.com.: a client that asks it can't be told which. Give each a name of its own"},
		{"a name of both, the second without a server name", `
    listen:
      - tls://127.0.0.1
    tls: dns
    server_name: dns.lan.example.com`, `
    listen:
      - tls://127.0.0.1
    tls: local`, dnsNames, []string{"dns.local.example.com", "dns.lan.example.com"}, "listeners.kids.tls: listeners lan and kids share tls://127.0.0.1, and both their certificates, dns and local, are for dns.lan.example.com: a client that asks it can't be told which. Add a server_name to kids"},
		{"a server name of another certificate", `
    listen:
      - tls://127.0.0.1
    tls: dns
    server_name: dns.local.example.com`, `
    listen:
      - tls://127.0.0.1:8853
    tls: local`, dnsNames, localNames, "listeners.lan.server_name: the certificate dns isn't for dns.local.example.com: it is for dns.lan.example.com. Give one of its names, as server_name: dns.lan.example.com, or add"},
		{"a wildcard server name", `
    listen:
      - tls://127.0.0.1
    tls: dns
    server_name: "*.lan.example.com"`, `
    listen:
      - tls://127.0.0.1:8853
    tls: local`, dnsNames, localNames, "listeners.lan.server_name: *.lan.example.com is a wildcard"},
		{"a server name without encrypted entries", `
    listen:
      - dns://127.0.0.1:5300
    server_name: dns.lan.example.com`, `
    listen:
      - tls://127.0.0.1:8853
    tls: local`, dnsNames, localNames, "listeners.lan.server_name is the name of the encrypted entries of listen, and there is none"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := sharedConfig(t, c.lan, c.kids, c.dnsNames, c.locals)
			if err == nil || !strings.HasPrefix(err.Error(), c.want) {
				t.Errorf("got %v\nwant %s", err, c.want)
			}
		})
	}
}

// A shared entry of a listener that no resolver uses, a web server's alone, is refused.
func TestListenersSharedWebOnly(t *testing.T) {
	dnsCert, dnsKey := writeTestCertificateFor(t, "dns.lan.example.com")
	localCert, localKey := writeTestCertificateFor(t, "dns.local.example.com")
	text := fmt.Sprintf(`listeners:
  lan:
    listen:
      - https://127.0.0.1:8443
    tls: dns
  web:
    listen:
      - https://127.0.0.1:8443
    tls: local
resolvers:
  lan:
    listeners:
      - lan
    upstream:
      - 192.168.1.1
webservers:
  main:
    listeners:
      - web
certificates:
  dns:
    certificate: %s
    key: %s
  local:
    certificate: %s
    key: %s
credentials:
%s
tasks:
%s
`, dnsCert, dnsKey, localCert, localKey, sharedCredential, nasTask)
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewConfig(path)
	want := "listeners.web.listen: https://127.0.0.1:8443 is shared with another listener, and only a resolver's entries are shared"
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("got %v\nwant %s", err, want)
	}
}

// The listeners' order is the file's, of YAML and of JSON.
func TestListenerOrder(t *testing.T) {
	for _, c := range []struct {
		name, raw string
		yaml      bool
	}{
		{"yaml", "log_level: info\nlisteners:\n  b:\n    listen: dns://53\n  a:\n    listen: dns://54\n  c: {}\n", true},
		{"json", `{"log_level": "info", "listeners": {"b": {"listen": "dns://53"}, "a": {"listen": ["dns://54"]}, "c": {}}}`, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := listenerOrder([]byte(c.raw), c.yaml); !slices.Equal(got, []string{"b", "a", "c"}) {
				t.Errorf("got %v, want [b a c]", got)
			}
		})
	}
}

// Names overlap when one certificate would be shown for a name of the other's, as RFC 6125 matches
// a wildcard: of one label.
func TestNamesOverlap(t *testing.T) {
	for _, c := range []struct {
		a, b []string
		want string
	}{
		{[]string{"dns.lan.example.com"}, []string{"dns.local.example.com"}, ""},
		{[]string{"DNS.lan.example.com."}, []string{"dns.lan.example.com"}, "dns.lan.example.com"},
		{[]string{"*.lan.example.com"}, []string{"kids.lan.example.com"}, "kids.lan.example.com"},
		{[]string{"a.kids.lan.example.com"}, []string{"*.lan.example.com"}, ""},
		{[]string{"*.lan.example.com"}, []string{"*.lan.example.com"}, "*.lan.example.com"},
		{[]string{"*.lan.example.com"}, []string{"*.kids.lan.example.com"}, ""},
		{[]string{"lan.example.com"}, []string{"*.lan.example.com"}, ""},
	} {
		if got := namesOverlap(c.a, c.b); got != c.want {
			t.Errorf("%v and %v: got %q, want %q", c.a, c.b, got, c.want)
		}
	}
}
