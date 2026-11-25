package config

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// updatesConfig is a configuration with a resolver, home, whose updates are given, indented as
// its keys: with the credential public, of example.com, a push source, wan, a static one, fixed,
// and a certificate of ipv6ddns's own, of nas.lan.
func updatesConfig(t *testing.T, listen, updates string) (Config, error) {
	t.Helper()
	return loadConfig(t, `
credentials:
  public:
    provider: cloudflare
    settings:
      api_token: token
      zone: example.com
      ttl: 1h
      proxied: false
  other:
    provider: cloudflare
    settings:
      api_token: token
      zone: example.net
      ttl: 1h
      proxied: false
  home:
    provider: resolver
    settings:
      zone: home.arpa
webserver:
  listen:
    - 127.0.0.1:8053
sources:
  wan:
    type: push
    password: secret
  fixed:
    type: static
    addresses:
      - 192.0.2.1
tasks:
  printer:
    filter:
      - mac:
          address: "00:11:22:33:44:55"
    endpoints:
      home:
        - printer
certificates:
  dns:
    acme:
      names:
        - dns.lan
      credential: public
resolvers:
  home:
    listen:
`+listen+`
    tls: dns
    upstream:
      - 1.1.1.1
    updates:
`+updates)
}

const (
	plainAndTLS = `      - 192.168.1.2
      - tls://192.168.1.2`
	testSecretYAML = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
)

func TestUpdates(t *testing.T) {
	cfg, err := updatesConfig(t, plainAndTLS, `
      allow:
        - 192.168.1.0/24
      keys:
        nas:
          secret: `+testSecretYAML+`
          permissions:
            - challenges:
                credential: public
                names:
                  - nas.lan
                  - "*.apps"
        router:
          secret: `+testSecretYAML+`
          algorithm: hmac-sha512
          allow:
            - 192.168.1.1
          permissions:
            - addresses:
                source: wan
                zone: example.com
        kea:
          secret: `+testSecretYAML+`
          permissions:
            - names:
                zone: lan.example.com
            - challenges:
                credential: other
                names:
                  - printer`)
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.Resolvers["home"]
	if !slices.Equal(r.Spec.UpdateAllow, []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}) {
		t.Errorf("the updates' allow: %v", r.Spec.UpdateAllow)
	}
	keys := r.Updates.Keys
	if k := keys["nas"].Spec; k.Name != "nas" || k.Algorithm != dns.HmacSHA256 || k.Secret != testSecretYAML || k.Allow != nil {
		t.Errorf("nas: %+v", k)
	}
	if k := keys["router"].Spec; k.Algorithm != dns.HmacSHA512 || !slices.Equal(k.Allow, []netip.Prefix{netip.MustParsePrefix("192.168.1.1/32")}) {
		t.Errorf("router: %+v", k)
	}
	var kinds []string
	for _, p := range keys["kea"].Permissions {
		kinds = append(kinds, p.Kind())
	}
	if !slices.Equal(kinds, []string{PermissionNames, PermissionChallenges}) {
		t.Errorf("kea's permissions: %v", kinds)
	}
}

// One key may have a name twice: a certificate's name and its wildcard share a challenge, and a
// name written relative and in full is one.
func TestUpdatesOneKeyTwice(t *testing.T) {
	_, err := updatesConfig(t, plainAndTLS, `
      keys:
        nas:
          secret: `+testSecretYAML+`
          permissions:
            - challenges:
                credential: public
                names:
                  - apps
                  - "*.apps"
                  - apps.example.com
            - addresses:
                source: wan
                zone: example.com
            - addresses:
                source: wan
                zone: example.com
                name: wan.example.com`)
	if err != nil {
		t.Error(err)
	}
}

// Two keys of one resolver can't change one name, of any kind.
func TestUpdatesTwoKeysOneName(t *testing.T) {
	two := func(permission string) string {
		return "\n      keys:\n        a:\n          secret: " + testSecretYAML + "\n          permissions:\n" + permission +
			"        b:\n          secret: " + testSecretYAML + "\n          permissions:\n" + permission
	}
	for _, c := range []struct{ what, permission, want string }{
		{"a challenge", "            - challenges:\n                credential: public\n                names:\n                  - \"*.apps\"\n",
			"resolvers.home.updates.keys.b.permissions[0].challenges.names: apps.example.com is resolvers.home.updates.keys.a.permissions[0].challenges.names's already"},
		{"addresses", "            - addresses:\n                source: wan\n                zone: example.com\n",
			"resolvers.home.updates.keys.b.permissions[0].addresses: wan.example.com is resolvers.home.updates.keys.a.permissions[0].addresses's already"},
		{"names", "            - names:\n                zone: lan.example.com\n",
			"resolvers.home.updates.keys.b.permissions[0].names: lan.example.com is resolvers.home.updates.keys.a.permissions[0].names's already"},
	} {
		if _, err := updatesConfig(t, plainAndTLS, two(c.permission)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %s", c.what, err, c.want)
		}
	}
}

func TestUpdatesErrors(t *testing.T) {
	key := func(permissions string) string {
		return `
      keys:
        nas:
          secret: ` + testSecretYAML + `
          permissions:
` + permissions
	}
	challenges := func(credential string, names ...string) string {
		out := "            - challenges:\n                credential: " + credential + "\n                names:\n"
		for _, n := range names {
			out += "                  - \"" + n + "\"\n"
		}
		return out
	}
	for _, c := range []struct {
		what, listen, updates, want string
	}{
		{"no keys", plainAndTLS, "      allow:\n        - 192.168.1.0/24", "resolvers.home.updates: keys is required"},
		{"only encrypted listen entries", "      - https://192.168.1.2\n      - quic://192.168.1.2", key(challenges("public", "nas.lan")),
			"resolvers.home.updates: updates come over plain DNS or DNS over TLS, and the resolver listens on neither"},
		{"a key name with a space", plainAndTLS, strings.Replace(key(challenges("public", "nas.lan")), "nas:", `"n a s":`, 1),
			`resolvers.home.updates.keys: "n a s" is not a name a TSIG key can have`},
		{"no secret", plainAndTLS, strings.Replace(key(challenges("public", "nas.lan")), "secret: "+testSecretYAML, `secret: ""`, 1),
			"secret"},
		{"a secret not base64", plainAndTLS, strings.Replace(key(challenges("public", "nas.lan")), testSecretYAML, "not-base64!", 1),
			"resolvers.home.updates.keys.nas.secret is not base64, as tsig-keygen writes it"},
		{"a secret too short", plainAndTLS, strings.Replace(key(challenges("public", "nas.lan")), testSecretYAML, "c2hvcnQ=", 1),
			"resolvers.home.updates.keys.nas.secret has 5 bytes, and must have 16 at least: tsig-keygen makes one of 32"},
		{"an algorithm too weak", plainAndTLS, strings.Replace(key(challenges("public", "nas.lan")), "          permissions:", "          algorithm: hmac-md5\n          permissions:", 1),
			"algorithm"},
		{"a bad allow", plainAndTLS, strings.Replace(key(challenges("public", "nas.lan")), "          permissions:", "          allow:\n            - lan\n          permissions:", 1),
			`resolvers.home.updates.keys.nas.allow: "lan" is not a network`},
		{"two kinds in one", plainAndTLS, key(challenges("public", "nas.lan") + "              names:\n                zone: lan.example.com\n"),
			"permissions"},

		{"a credential missing", plainAndTLS, key(challenges("nope", "nas.lan")),
			"resolvers.home.updates.keys.nas.permissions[0].challenges.credential: there is no credential nope"},
		{"a resolver's zone", plainAndTLS, key(challenges("home", "nas")),
			"resolvers.home.updates.keys.nas.permissions[0].challenges.credential: home is a zone of the resolver, which the authority can't ask"},
		{"a wildcard inside", plainAndTLS, key(challenges("public", "a.*.lan")),
			`resolvers.home.updates.keys.nas.permissions[0].challenges.names: "a.*.lan" is not a name: a wildcard is only its first label, as *.apps`},
		{"a name of ipv6ddns's own certificate", plainAndTLS, key(challenges("public", "*.dns.lan")),
			"resolvers.home.updates.keys.nas.permissions[0].challenges.names: *.dns.lan is a name of certificates.dns, whose challenge ipv6ddns writes itself"},
		{"a source missing", plainAndTLS, key("            - addresses:\n                source: nope\n                zone: example.com\n"),
			"resolvers.home.updates.keys.nas.permissions[0].addresses.source: there is no source nope: add it under sources, with type: push"},
		{"a source not push", plainAndTLS, key("            - addresses:\n                source: fixed\n                zone: example.com\n"),
			"resolvers.home.updates.keys.nas.permissions[0].addresses.source: fixed is a source of type static: the addresses sent go to a source of type push"},
		{"a zone missing", plainAndTLS, key("            - addresses:\n                source: wan\n"), "zone"},
	} {
		t.Run(c.what, func(t *testing.T) {
			_, err := updatesConfig(t, c.listen, c.updates)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("%v, want %s", err, c.want)
			}
		})
	}
}

// Two keys, of two resolvers, can't change one name.
func TestUpdatesClaimedAcrossResolvers(t *testing.T) {
	_, err := loadConfig(t, `
credentials:
  public:
    provider: cloudflare
    settings:
      api_token: token
      zone: example.com
      ttl: 1h
      proxied: false
tasks:
  printer:
    filter:
      - mac:
          address: "00:11:22:33:44:55"
    endpoints:
      public:
        - printer
resolvers:
  a:
    listen:
      - 192.168.1.2
    upstream:
      - 1.1.1.1
    updates:
      keys:
        nas:
          secret: `+testSecretYAML+`
          permissions:
            - challenges:
                credential: public
                names:
                  - nas.lan
  b:
    listen:
      - 192.168.2.2
    upstream:
      - 1.1.1.1
    updates:
      keys:
        nas2:
          secret: `+testSecretYAML+`
          permissions:
            - challenges:
                credential: public
                names:
                  - NAS.lan
`)
	want := "resolvers.b.updates.keys.nas2.permissions[0].challenges.names: nas.lan.example.com is resolvers.a.updates.keys.nas.permissions[0].challenges.names's already: a name can be changed by one key alone"
	if err == nil || err.Error() != want {
		t.Errorf("%v, want %s", err, want)
	}
}

// A push source without a password takes a key's updates: it needs no web server, and a key that
// sends to it.
func TestUpdatesPushWithoutPassword(t *testing.T) {
	text := func(keys string) string {
		return `
sources:
  vps:
    type: push
tasks:
  vps:
    sources:
      - vps
    endpoints:
      home:
        - vps
credentials:
  home:
    provider: resolver
    settings:
      zone: home.arpa
resolvers:
  home:
    listen:
      - 192.168.1.2
    upstream:
      - 1.1.1.1
` + keys
	}
	if _, err := loadConfig(t, text(`    updates:
      keys:
        vps:
          secret: `+testSecretYAML+`
          permissions:
            - addresses:
                source: vps
                zone: example.com
`)); err != nil {
		t.Error(err)
	}
	want := "source vps: a push source needs a password, which a router sends with its updates, or a key of a resolver's updates whose permission of addresses sends them"
	if _, err := loadConfig(t, text("")); err == nil || err.Error() != want {
		t.Errorf("%v, want %s", err, want)
	}
}
