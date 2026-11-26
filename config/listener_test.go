package config

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// listenerConfig is a configuration of a listener, lan, with the blocks given: of servers that
// use it, or not; and of a certificate, home, of files.
func listenerConfig(t *testing.T, blocks string) string {
	t.Helper()
	certFile, keyFile := writeTestCertificate(t)
	credential, endpoint := "home:\n    provider: resolver\n    settings:\n      zone: home.arpa", "home"
	if !strings.Contains(blocks, "\nresolvers:") {
		credential, endpoint = "duck:\n    provider: duckdns\n    settings:\n      token: x", "duck"
	}
	return blocks + `
certificates:
  home:
    certificate: ` + certFile + `
    key: ` + keyFile + `
credentials:
  ` + credential + `
tasks:
  nas:
    filter:
      - mac:
          address: "00:11:22:33:44:55"
    endpoints:
      ` + endpoint + `:
        - nas
`
}

const sharedListener = `
listeners:
  lan:
    listen:
      - dns://127.0.0.1:5353
      - tls://127.0.0.1:8853
      - https://127.0.0.1
      - http://127.0.0.1
    tls: home
    allow:
      - 127.0.0.0/8
`

// A listener a resolver and a web server share: the resolver takes its DNS entries, with the
// listener's certificate and allow, and its HTTPS one, whose other paths are the web server's;
// the web server its HTTP entry, and the HTTPS one through the resolver, of the listener's allow.
func TestListenerShared(t *testing.T) {
	cfg, err := loadConfig(t, listenerConfig(t, sharedListener+`  web:
    listen:
      - http://127.0.0.1:18053
resolvers:
  lan:
    listeners:
      - lan
    upstream:
      - 1.1.1.1
webservers:
  main:
    listeners:
      - web
      - lan
`))
	if err != nil {
		t.Fatal(err)
	}
	listener := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	spec := cfg.Resolvers["lan"].Spec
	if len(spec.Listen) != 1 || spec.Listen[0].String() != "127.0.0.1:5353" || !slices.Equal(spec.ListenAllow[0], listener) {
		t.Errorf("plain DNS: %v, allow %v", spec.Listen, spec.ListenAllow)
	}
	var transports []string
	for _, e := range spec.Encrypted {
		transports = append(transports, e.Transport+" "+e.Entry.String()+" "+e.CertificateName+" "+e.Web)
		if !slices.Equal(e.Allow, listener) {
			t.Errorf("%s: allow %v", e.Line, e.Allow)
		}
	}
	if want := []string{"tls 127.0.0.1:8853 home ", "https 127.0.0.1:443 home lan"}; !slices.Equal(transports, want) {
		t.Errorf("the encrypted entries: %q, want %q", transports, want)
	}
	web := cfg.Webservers["main"]
	var own []string
	for _, e := range web.Entries {
		own = append(own, e.Entry.String())
	}
	if !slices.Equal(own, []string{"127.0.0.1:18053", "127.0.0.1:8053"}) || web.Entries[0].Allow != nil || !slices.Equal(web.Entries[1].Allow, listener) {
		t.Errorf("the web server's own entries: %v, %+v", own, web.Entries)
	}
	if len(web.Shared) != 1 || web.Shared[0].Listener != "lan" || web.Shared[0].Resolver != "resolvers.lan" || !slices.Equal(web.Shared[0].Allow, listener) {
		t.Errorf("shared: %+v", web.Shared)
	}
	if used := cfg.Certificates["home"].UsedBy; !slices.Equal(used, []string{"listeners.lan"}) {
		t.Errorf("the certificate is used by %v", used)
	}
}

// A server's own allow replaces its listener's, there.
func TestListenerAllowReplaced(t *testing.T) {
	cfg, err := loadConfig(t, listenerConfig(t, sharedListener+`
resolvers:
  lan:
    listeners:
      - lan
    allow:
      - 10.0.0.0/8
    upstream:
      - 1.1.1.1
webservers:
  main:
    listeners:
      - lan
    allow:
      - 192.168.1.0/24
`))
	if err != nil {
		t.Fatal(err)
	}
	own := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
	web := cfg.Webservers["main"]
	if !slices.Equal(web.Shared[0].Allow, own) || !slices.Equal(web.Entries[0].Allow, own) {
		t.Errorf("the web server's allow: shared %v, own %v", web.Shared[0].Allow, web.Entries[0].Allow)
	}
	// The resolver's own allow, which replaces the listener's at the queries.
	if spec := cfg.Resolvers["lan"].Spec; !slices.Equal(spec.Allow, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}) {
		t.Errorf("the resolver's allow: %v", spec.Allow)
	}
}

// A listener only a web server uses serves its HTTPS entries itself, with the listener's
// certificate.
func TestListenerOfAWebServer(t *testing.T) {
	cfg, err := loadConfig(t, listenerConfig(t, `
listeners:
  web:
    listen:
      - https://127.0.0.1:8443
    tls: home
webservers:
  main:
    listeners:
      - web
`))
	if err != nil {
		t.Fatal(err)
	}
	web := cfg.Webservers["main"]
	if len(web.Entries) != 1 || web.Entries[0].Certificate != "home" || web.Entries[0].Entry.String() != "127.0.0.1:8443" || len(web.Shared) != 0 {
		t.Errorf("%+v, shared %+v", web.Entries, web.Shared)
	}
}

// Each mistake, told.
func TestListenerErrors(t *testing.T) {
	resolverOf := func(listeners ...string) string {
		return "\nresolvers:\n  lan:\n    listeners:\n      - " + strings.Join(listeners, "\n      - ") + "\n    upstream:\n      - 1.1.1.1\n"
	}
	for _, c := range []struct{ name, blocks, want string }{
		{"no such listener", "\nwebservers:\n  main:\n    listeners:\n      - nope\n", "webservers.main.listeners: there is no listener nope"},
		{"an entry without a scheme", "\nlisteners:\n  lan:\n    listen:\n      - 127.0.0.1\n" + resolverOf("lan"), `listeners.lan.listen: "127.0.0.1" has no scheme`},
		{"an unknown scheme", "\nlisteners:\n  lan:\n    listen:\n      - ftp://127.0.0.1\n" + resolverOf("lan"), `listeners.lan.listen: "ftp://127.0.0.1" has no scheme`},
		{"encrypted without tls", "\nlisteners:\n  lan:\n    listen:\n      - https://127.0.0.1\n" + resolverOf("lan"), "listeners.lan.tls is missing"},
		{"a listener no server uses", "\nlisteners:\n  lan:\n    listen:\n      - dns://127.0.0.1\n  other:\n    listen:\n      - dns://127.0.0.1:5353\n" + resolverOf("other"), "listeners.lan: no server uses it"},
		{"DNS without a resolver", "\nlisteners:\n  lan:\n    listen:\n      - dns://127.0.0.1\n\nwebservers:\n  main:\n    listeners:\n      - lan\n", "listeners.lan.listen: dns://127.0.0.1 is DNS, which only a resolver serves"},
		{"HTTP without a web server", "\nlisteners:\n  lan:\n    listen:\n      - http://127.0.0.1\n" + resolverOf("lan"), "listeners.lan.listen: http://127.0.0.1 is HTTP, which only a web server serves"},
		{"two resolvers on one listener", "\nlisteners:\n  lan:\n    listen:\n      - dns://127.0.0.1\n" + resolverOf("lan") + "  guests:\n    listeners:\n      - lan\n    upstream:\n      - 1.1.1.1\n", "resolvers.lan.listeners: lan is resolvers.guests's already"},
		{"the web server of before", "\nwebserver:\n  listen:\n    - 8053\n", "webserver is now webservers"},
		{"a web server without listeners", "\nwebservers:\n  main:\n    allow:\n      - 10.0.0.0/8\n", "webservers.main.listeners is missing"},
		{"a web server with listen", "\nwebservers:\n  main:\n    listen:\n      - 8053\n", "webservers.main.listen is a listener's now"},
		{"a resolver with listen", "\nresolvers:\n  lan:\n    listen:\n      - 127.0.0.1\n    upstream:\n      - 1.1.1.1\n", "resolvers.lan.listen is a listener's now"},
		{"a resolver with tls", "\nlisteners:\n  lan:\n    listen:\n      - dns://127.0.0.1\n\nresolvers:\n  lan:\n    listeners:\n      - lan\n    tls: home\n    upstream:\n      - 1.1.1.1\n", "resolvers.lan.tls is a listener's now"},
		{"a resolver without listeners", "\nresolvers:\n  lan:\n    upstream:\n      - 1.1.1.1\n", "resolvers.lan.listeners is missing"},
	} {
		t.Run(c.name, func(t *testing.T) {
			blocks := c.blocks
			if !strings.Contains(blocks, "    tls: home") {
				// The certificate, used: a listener of a web server of its own shows it.
				blocks = withBlock(blocks, "listeners", "  cert:\n    listen:\n      - https://127.0.0.1:9443\n    tls: home\n")
				blocks = withBlock(blocks, "webservers", "  cert:\n    listeners:\n      - cert\n")
			}
			_, err := loadConfig(t, listenerConfig(t, blocks))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("got %v\nwant %s", err, c.want)
			}
		})
	}
}

// withBlock adds the entries to the top-level block key of blocks, or the block, if it has none.
func withBlock(blocks, key, entries string) string {
	if strings.Contains(blocks, "\n"+key+":\n") {
		return strings.Replace(blocks, "\n"+key+":\n", "\n"+key+":\n"+entries, 1)
	}
	return blocks + "\n" + key + ":\n" + entries
}
