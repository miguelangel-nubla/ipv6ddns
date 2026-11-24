package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// resolverConfig is a configuration with a resolver lan, a credential home of its zone home.arpa,
// and a task nas there, with extra in YAML after it.
func resolverConfig(t *testing.T, resolvers, credentials, tasks string) (Config, error) {
	t.Helper()
	text := "resolvers:\n" + resolvers + "\ncredentials:\n" + credentials + "\ntasks:\n" + tasks + "\n"
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return NewConfig(path)
}

const (
	lanResolver = `
  lan:
    listen: 192.168.1.0/24
    upstream:
      - 192.168.1.1
      - "1.1.1.1:5353"
      - "[2606:4700:4700::1111]"
    records:
      - www.example.com. CNAME nas.home.arpa.`
	homeCredential = `
  home:
    provider: resolver
    settings:
      zone: home.arpa
      records:
        - printer A 192.168.1.20
        - files CNAME nas
        - "_ipp._tcp SRV 0 0 631 printer"`
	nasTask = `
  nas:
    filter:
      - mac:
          address: "00:11:22:33:44:55"
    endpoints:
      home:
        - nas
        - "*.dev"`
)

func TestResolverConfig(t *testing.T) {
	cfg, err := resolverConfig(t, lanResolver, homeCredential, nasTask)
	if err != nil {
		t.Fatal(err)
	}
	spec := cfg.Resolvers["lan"].Spec
	if spec.Name != "lan" || len(spec.Listen) != 1 || spec.Listen[0].Port != "53" || spec.Listen[0].Network.String() != "192.168.1.0/24" {
		t.Errorf("listen: %+v", spec.Listen)
	}
	if want := []string{"192.168.1.1:53", "1.1.1.1:5353", "[2606:4700:4700::1111]:53"}; strings.Join(spec.Upstreams, " ") != strings.Join(want, " ") {
		t.Errorf("upstreams: %v", spec.Upstreams)
	}
	if spec.Allow != nil {
		t.Errorf("allow, left to its default: %v", spec.Allow)
	}
	if len(spec.Records) != 1 || spec.Records[0].Header().Name != "www.example.com." {
		t.Errorf("records: %v", spec.Records)
	}
	if len(spec.Zones) != 1 {
		t.Fatalf("zones: %+v", spec.Zones)
	}
	z := spec.Zones[0]
	if z.Credential != "home" || z.Name != "home.arpa." || z.TTL != time.Minute || len(z.Records) != 3 {
		t.Errorf("zone: %+v", z)
	}
	if z.Tasks["nas.home.arpa."] != "nas" || z.Tasks["*.dev.home.arpa."] != "nas" {
		t.Errorf("tasks: %v", z.Tasks)
	}
	if srv, ok := z.Records[2].(*dns.SRV); !ok || srv.Target != "printer.home.arpa." || srv.Hdr.Ttl != 60 {
		t.Errorf("SRV: %v", z.Records[2])
	}
	// Nothing goes anywhere: the updates are at once.
	if d := cfg.Credentials["home"].Debounce.Duration; d != 0 {
		t.Errorf("debounce: %s", d)
	}

	// Two resolvers, and an allow, a TTL and a debounce given.
	cfg, err = resolverConfig(t, lanResolver+`
    allow:
      - 192.168.1.0/24
      - "fd00::/64"
      - 10.0.0.7
  lab:
    listen: 10.0.0.2
    upstream: 10.0.0.1`, homeCredential+`
      resolver: lan
      ttl: 5m
    debounce: 2s
  labs:
    provider: resolver
    settings:
      resolver: lab
      zone: home.arpa`, nasTask)
	if err != nil {
		t.Fatal(err)
	}
	lan := cfg.Resolvers["lan"].Spec
	if got := lan.Allow; len(got) != 3 || got[2].String() != "10.0.0.7/32" {
		t.Errorf("allow: %v", got)
	}
	if lan.Zones[0].TTL != 5*time.Minute || lan.Zones[0].Records[0].Header().Ttl != 300 || cfg.Credentials["home"].Debounce.Duration != 2*time.Second {
		t.Errorf("ttl, debounce: %+v", lan.Zones[0])
	}
	// One zone on two resolvers: split horizon.
	if lab := cfg.Resolvers["lab"].Spec; len(lab.Zones) != 1 || lab.Zones[0].Credential != "labs" {
		t.Errorf("lab: %+v", lab.Zones)
	}

	// A zone with no task serves its records.
	if _, err := resolverConfig(t, lanResolver, homeCredential, " {}"); err != nil {
		t.Error(err)
	}
}

func TestResolverConfigErrors(t *testing.T) {
	for _, c := range []struct {
		name, resolvers, credentials, tasks, want string
	}{
		{"no listen", `
  lan:
    upstream: 192.168.1.1`, homeCredential, nasTask,
			"resolvers.lan.listen is missing: give where the resolver answers. That's the clients' network, as 192.168.1.0/24, for this machine's address in it, or the address itself. Without a port, 53"},
		{"no upstream", `
  lan:
    listen: 192.168.1.0/24`, homeCredential, nasTask,
			"resolvers.lan.upstream is missing: give one or more servers to ask about the names that aren't the resolver's own, as 192.168.1.1 or 1.1.1.1:53. Without them, it answers no other name"},
		{"an empty upstream", `
  lan:
    listen: 192.168.1.0/24
    upstream: []`, homeCredential, nasTask,
			"resolvers.lan.upstream is missing: give one or more servers to ask about the names that aren't the resolver's own"},
		{"a bad listen", `
  lan:
    listen: "192.168.1.0/33"
    upstream: 192.168.1.1`, homeCredential, nasTask,
			`resolvers.lan.listen: "192.168.1.0/33": write a network as 10.2.3.0/24 or fd00::/64, without a port: it uses the default one`},
		{"a host name upstream without bootstrap", `
  lan:
    listen: 192.168.1.0/24
    upstream:
      - 1.1.1.1
      - dns.google`, homeCredential, nasTask,
			`resolvers.lan.upstream: "dns.google" is a host name, and there's no bootstrap to look it up. Add bootstrap, servers used for that lookup only, as bootstrap: 9.9.9.9. The system's resolver isn't used, as it may be this one`},
		{"a bootstrap with no host name to find", `
  lan:
    listen: 192.168.1.0/24
    upstream: 1.1.1.1
    bootstrap: 9.9.9.9`, homeCredential, nasTask,
			"resolvers.lan.bootstrap only looks up upstream servers given by host name, and every upstream here is an address: leave it out"},
		{"a host name bootstrap", `
  lan:
    listen: 192.168.1.0/24
    upstream: dns.google
    bootstrap: dns.quad9.net`, homeCredential, nasTask,
			`resolvers.lan.bootstrap: "dns.quad9.net" is not an address, with or without a port, as 192.168.1.1, 1.1.1.1:53 or [2001:db8::1]:53`},
		{"an upstream that is neither", `
  lan:
    listen: 192.168.1.0/24
    upstream: "dns google"
    bootstrap: 9.9.9.9`, homeCredential, nasTask,
			`resolvers.lan.upstream: "dns google" is not an address or a host name, with or without a port, as 192.168.1.1, 1.1.1.1:53, [2001:db8::1]:53 or dns.example.net`},
		{"a host name upstream of port 0", `
  lan:
    listen: 192.168.1.0/24
    upstream: dns.google:0
    bootstrap: 9.9.9.9`, homeCredential, nasTask,
			`resolvers.lan.upstream: "dns.google:0" is not an address or a host name, with or without a port, as 192.168.1.1, 1.1.1.1:53, [2001:db8::1]:53 or dns.example.net`},
		{"an encrypted upstream by host name without bootstrap", `
  lan:
    listen: 192.168.1.0/24
    upstream:
      - 1.1.1.1
      - "tls://dns.example.net"`, homeCredential, nasTask,
			`resolvers.lan.upstream: "tls://dns.example.net" is at a host name, and there's no bootstrap to look it up. Add bootstrap, servers used for that lookup only, as bootstrap: 9.9.9.9. The system's resolver isn't used, as it may be this one`},
		{"a bootstrap with encrypted upstreams at addresses", `
  lan:
    listen: 192.168.1.0/24
    upstream:
      - "tls://1.1.1.1"
      - "https://[2606:4700:4700::1111]/dns-query"
    bootstrap: 9.9.9.9`, homeCredential, nasTask,
			"resolvers.lan.bootstrap only looks up upstream servers given by host name, and every upstream here is an address: leave it out"},
		{"an unknown scheme", `
  lan:
    listen: 192.168.1.0/24
    upstream: "quic://dns.example.net"`, homeCredential, nasTask,
			`resolvers.lan.upstream: "quic://dns.example.net": unknown scheme quic: use plain DNS, as 1.1.1.1 or dns.example.net; tls:// for DNS over TLS, as tls://1.1.1.1; or https:// for DNS over HTTPS, as https://dns.example.net/dns-query`},
		{"DNS over HTTP, not HTTPS", `
  lan:
    listen: 192.168.1.0/24
    upstream: "http://dns.example.net/dns-query"`, homeCredential, nasTask,
			`resolvers.lan.upstream: "http://dns.example.net/dns-query": unknown scheme http: use plain DNS, as 1.1.1.1 or dns.example.net; tls:// for DNS over TLS, as tls://1.1.1.1; or https:// for DNS over HTTPS, as https://dns.example.net/dns-query`},
		{"DNS over HTTPS without a path", `
  lan:
    listen: 192.168.1.0/24
    upstream: "https://dns.example.net"
    bootstrap: 9.9.9.9`, homeCredential, nasTask,
			`resolvers.lan.upstream: "https://dns.example.net": DNS over HTTPS needs a path, as https://dns.example.net/dns-query`},
		{"DNS over HTTPS with the root for a path", `
  lan:
    listen: 192.168.1.0/24
    upstream: "https://1.1.1.1:8443/"`, homeCredential, nasTask,
			`resolvers.lan.upstream: "https://1.1.1.1:8443/": DNS over HTTPS needs a path, as https://1.1.1.1:8443/dns-query`},
		{"DNS over HTTPS with a query", `
  lan:
    listen: 192.168.1.0/24
    upstream: "https://dns.example.net/dns-query?dns=x"
    bootstrap: 9.9.9.9`, homeCredential, nasTask,
			`resolvers.lan.upstream: "https://dns.example.net/dns-query?dns=x": DNS over HTTPS takes a host, with or without a port, and a path: no user, query or fragment`},
		{"DNS over HTTPS with a fragment", `
  lan:
    listen: 192.168.1.0/24
    upstream: "https://dns.example.net/dns-query#x"
    bootstrap: 9.9.9.9`, homeCredential, nasTask,
			`resolvers.lan.upstream: "https://dns.example.net/dns-query#x": DNS over HTTPS takes a host, with or without a port, and a path: no user, query or fragment`},
		{"DNS over HTTPS with a user", `
  lan:
    listen: 192.168.1.0/24
    upstream: "https://me:secret@dns.example.net/dns-query"
    bootstrap: 9.9.9.9`, homeCredential, nasTask,
			`resolvers.lan.upstream: "https://me:secret@dns.example.net/dns-query": DNS over HTTPS takes a host, with or without a port, and a path: no user, query or fragment`},
		{"DNS over TLS with a path", `
  lan:
    listen: 192.168.1.0/24
    upstream: "tls://1.1.1.1/dns-query"`, homeCredential, nasTask,
			`resolvers.lan.upstream: "tls://1.1.1.1/dns-query": DNS over TLS takes a host, with or without a port, and no path: paths are for https://`},
		{"DNS over TLS with a query", `
  lan:
    listen: 192.168.1.0/24
    upstream: "tls://1.1.1.1?x=1"`, homeCredential, nasTask,
			`resolvers.lan.upstream: "tls://1.1.1.1?x=1": DNS over TLS takes a host, with or without a port: no user, query or fragment`},
		{"DNS over TLS at port 0", `
  lan:
    listen: 192.168.1.0/24
    upstream: "tls://1.1.1.1:0"`, homeCredential, nasTask,
			`resolvers.lan.upstream: "tls://1.1.1.1:0": the port 0 is out of range: ports go from 1 to 65535`},
		{"DNS over HTTPS at port 0", `
  lan:
    listen: 192.168.1.0/24
    upstream: "https://dns.example.net:0/dns-query"
    bootstrap: 9.9.9.9`, homeCredential, nasTask,
			`resolvers.lan.upstream: "https://dns.example.net:0/dns-query": the port 0 is out of range: ports go from 1 to 65535`},
		{"DNS over TLS at a port too high", `
  lan:
    listen: 192.168.1.0/24
    upstream: "tls://1.1.1.1:65536"`, homeCredential, nasTask,
			`resolvers.lan.upstream: "tls://1.1.1.1:65536": the port 65536 is out of range: ports go from 1 to 65535`},
		{"DNS over TLS with no host", `
  lan:
    listen: 192.168.1.0/24
    upstream: "tls://:853"`, homeCredential, nasTask,
			`resolvers.lan.upstream: "tls://:853": the host must be an address or a host name, with or without a port, as tls://1.1.1.1, tls://[2606:4700:4700::1111]:853 or tls://dns.example.net`},
		{"DNS over HTTPS at a name of one label", `
  lan:
    listen: 192.168.1.0/24
    upstream: "https://router/dns-query"`, homeCredential, nasTask,
			`resolvers.lan.upstream: "https://router/dns-query": the host must be an address or a host name, with or without a port, as https://1.1.1.1/dns-query, https://[2606:4700:4700::1111]/dns-query or https://dns.example.net/dns-query`},
		{"a cache of less than none", lanResolver + `
    cache_size: -1`, homeCredential, nasTask,
			"<schema>"},
		{"a cache that isn't a number", lanResolver + `
    cache_size: big`, homeCredential, nasTask,
			"<schema>"},
		{"a bad allow", lanResolver + `
    allow:
      - lan`, homeCredential, nasTask,
			`resolvers.lan.allow: "lan" is not a network, as 192.168.1.0/24 or fd00::/64, nor an address`},
		{"a resolver naming none", lanResolver, homeCredential + `
      resolver: wan`, nasTask,
			"credentials.home.settings.resolver: there's no resolver wan: the resolvers are lan"},
		{"no resolver", ` {}`, homeCredential, nasTask,
			"credentials.home: the resolver provider is a zone that one of the resolvers answers, and there are none: add one under resolvers, with its listen and upstream"},
		{"which of two", lanResolver + `
  lab:
    listen: 10.0.0.2
    upstream: 10.0.0.1`, homeCredential, nasTask,
			"credentials.home.settings.resolver is missing: say which of lab, lan answers the zone"},
		{"no zone", lanResolver, `
  home:
    provider: resolver
    settings: {}`, nasTask,
			"credentials.home.settings.zone is missing: give the zone the resolver answers, as home.arpa"},
		{"one zone twice", lanResolver, homeCredential + `
  office:
    provider: resolver
    settings:
      zone: Home.Arpa.`, nasTask,
			"credentials home and office are both the zone home.arpa of resolver lan: a zone can belong to only one credential"},
		{"one address twice", lanResolver + `
  lab:
    listen:
      - 10.0.0.2
      - 192.168.1.0/24
    upstream: 10.0.0.1`, homeCredential + `
      resolver: lan`, nasTask,
			"resolvers lab and lan both listen on 192.168.1.0/24 port 53: an address and port can belong to only one resolver"},
		{"a zone record outside", lanResolver, `
  home:
    provider: resolver
    settings:
      zone: home.arpa
      records:
        - printer.example.com. A 192.168.1.20`, nasTask,
			`credentials.home.settings.records: "printer.example.com. A 192.168.1.20": printer.example.com. isn't in the zone home.arpa: a zone's records must be for its names, relative to it or absolute within it`},
		{"a resolver record without its dot", `
  lan:
    listen: 192.168.1.0/24
    upstream: 192.168.1.1
    records:
      - www.example.com CNAME nas.home.arpa.`, homeCredential, nasTask,
			`resolvers.lan.records: "www.example.com CNAME nas.home.arpa.": the name www.example.com must be absolute, ending in a dot, as www.example.com.: these records belong to no zone`},
		{"a resolver record's target without its dot", `
  lan:
    listen: 192.168.1.0/24
    upstream: 192.168.1.1
    records:
      - www.example.com. CNAME nas`, homeCredential, nasTask,
			`resolvers.lan.records: "www.example.com. CNAME nas": bad CNAME Target: "nas": every name in these records must be absolute, ending in a dot`},
		{"a resolver record in a zone", `
  lan:
    listen: 192.168.1.0/24
    upstream: 192.168.1.1
    records:
      - tv.home.arpa. A 192.168.1.30`, homeCredential, nasTask,
			`resolvers.lan.records: "tv.home.arpa. A 192.168.1.30": tv.home.arpa. is in the zone home.arpa, of credential home: give it in that credential's records`},
		{"a record that doesn't parse", lanResolver, `
  home:
    provider: resolver
    settings:
      zone: home.arpa
      records:
        - printer A 192.168.1.300`, nasTask,
			`credentials.home.settings.records: "printer A 192.168.1.300": bad A A: "192.168.1.300"`},
		{"a record with no data", lanResolver, `
  home:
    provider: resolver
    settings:
      zone: home.arpa
      records:
        - printer A`, nasTask,
			`credentials.home.settings.records: "printer A": a A record with no data`},
		{"a CNAME beside other data", lanResolver, `
  home:
    provider: resolver
    settings:
      zone: home.arpa
      records:
        - files CNAME nas
        - files TXT "x"`, nasTask,
			"credentials.home.settings.records: files.home.arpa. has a CNAME and other records: a name with a CNAME can't have others, since its data is the target's"},
		{"a record of a task's name", lanResolver, `
  home:
    provider: resolver
    settings:
      zone: home.arpa
      records:
        - NAS TXT "x"`, nasTask,
			`credentials.home.settings.records: "NAS TXT \"x\"": nas.home.arpa. is published by task nas, which gives its addresses: records are for other names`},
		{"a CNAME loop", lanResolver, `
  home:
    provider: resolver
    settings:
      zone: home.arpa
      records:
        - a CNAME b
        - b CNAME A`, nasTask,
			"resolvers.lan: the CNAMEs a.home.arpa. -> b.home.arpa. -> a.home.arpa. are a loop"},
		{"a CNAME loop through a zone and the resolver", `
  lan:
    listen: 192.168.1.0/24
    upstream: 192.168.1.1
    records:
      - www.example.com. CNAME a.home.arpa.`, `
  home:
    provider: resolver
    settings:
      zone: home.arpa
      records:
        - a CNAME www.example.com.`, nasTask,
			"resolvers.lan: the CNAMEs www.example.com. -> a.home.arpa. -> www.example.com. are a loop"},
		{"a CNAME loop through a wildcard", lanResolver, `
  home:
    provider: resolver
    settings:
      zone: home.arpa
      records:
        - "*.lab CNAME x.lab"`, nasTask,
			"resolvers.lan: the CNAMEs *.lab.home.arpa. -> x.lab.home.arpa. -> x.lab.home.arpa. are a loop"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := resolverConfig(t, c.resolvers, c.credentials, c.tasks)
			if c.want == "<schema>" {
				// In the schema's words.
				if err == nil || !strings.Contains(err.Error(), "cache_size") {
					t.Errorf("got %v, want an error of cache_size", err)
				}
				return
			}
			if err == nil || err.Error() != c.want {
				t.Errorf("got %v\nwant %s", err, c.want)
			}
		})
	}
}

// Encrypted upstream servers, over TLS and over HTTPS, are kept as written: at addresses, and at
// host names, which need the bootstrap servers.
func TestResolverConfigEncrypted(t *testing.T) {
	cfg, err := resolverConfig(t, `
  lan:
    listen: 192.168.1.0/24
    upstream:
      - "tls://1.1.1.1"
      - "TLS://Dns.Example.NET:8853"
      - "tls://[2606:4700:4700::1111]"
      - "https://dns.example.net/dns-query"
      - "https://9.9.9.9:5053/a/b"
      - "https://[2620:fe::fe]:443/dns-query"
      - 192.168.1.1
    bootstrap: 9.9.9.9`, homeCredential, nasTask)
	if err != nil {
		t.Fatal(err)
	}
	spec := cfg.Resolvers["lan"].Spec
	want := []string{"tls://1.1.1.1", "TLS://Dns.Example.NET:8853", "tls://[2606:4700:4700::1111]", "https://dns.example.net/dns-query", "https://9.9.9.9:5053/a/b", "https://[2620:fe::fe]:443/dns-query", "192.168.1.1:53"}
	if !slices.Equal(spec.Upstreams, want) {
		t.Errorf("upstreams: %q\nwant %q", spec.Upstreams, want)
	}
	// At addresses alone, no bootstrap.
	if _, err := resolverConfig(t, `
  lan:
    listen: 192.168.1.0/24
    upstream:
      - "tls://1.1.1.1:853"
      - "https://1.1.1.1/dns-query"`, homeCredential, nasTask); err != nil {
		t.Error(err)
	}
}

// The cache is on, of 10000 answers, unless cache_size says: 0 is none. And the listen entries
// keep their text, for the errors at start.
func TestResolverConfigCache(t *testing.T) {
	for text, want := range map[string]int{"": 10000, "\n    cache_size: 0": 0, "\n    cache_size: 250": 250} {
		cfg, err := resolverConfig(t, `
  lan:
    listen:
      - 192.168.1.0/24
      - " 192.168.1.2:5353"
      - "192.168.1.0/24"
      - "[fd00::2]"
      - 192.168.1.2
    upstream: 192.168.1.1`+text, homeCredential, nasTask)
		if err != nil {
			t.Fatal(err)
		}
		spec := cfg.Resolvers["lan"].Spec
		if spec.CacheSize != want {
			t.Errorf("cache_size%s: %d, want %d", text, spec.CacheSize, want)
		}
		if lines := []string{"192.168.1.0/24", "192.168.1.2:5353", "[fd00::2]", "192.168.1.2"}; !slices.Equal(spec.ListenLines, lines) || len(spec.Listen) != len(lines) {
			t.Errorf("listen: %+v, as written %q", spec.Listen, spec.ListenLines)
		}
	}
}

// Upstream servers by host name, with the bootstrap servers that find them.
func TestResolverConfigHostNames(t *testing.T) {
	cfg, err := resolverConfig(t, `
  lan:
    listen: 192.168.1.0/24
    upstream:
      - DNS.Example.NET.
      - "dns.example.org:5353"
      - 1.1.1.1
    bootstrap:
      - 9.9.9.9
      - "[2620:fe::fe]:53"`, homeCredential, nasTask)
	if err != nil {
		t.Fatal(err)
	}
	spec := cfg.Resolvers["lan"].Spec
	if want := "dns.example.net:53 dns.example.org:5353 1.1.1.1:53"; strings.Join(spec.Upstreams, " ") != want {
		t.Errorf("upstreams: %v, want %s", spec.Upstreams, want)
	}
	if want := "9.9.9.9:53 [2620:fe::fe]:53"; strings.Join(spec.Bootstrap, " ") != want {
		t.Errorf("bootstrap: %v, want %s", spec.Bootstrap, want)
	}
}

// writeTestCertificate writes a self-signed certificate and its key, in PEM, and returns their
// paths.
func writeTestCertificate(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"dns.home.arpa"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	return certFile, keyFile
}

// An entry of listen that starts with tls://, https:// or quic:// answers over that encrypted
// transport, on its port by default; https:// takes the path /dns-query, where it answers. They
// need the certificate and its key, which must read as a pair; and these are for them alone.
func TestResolverConfigEncryptedListen(t *testing.T) {
	certFile, keyFile := writeTestCertificate(t)
	files := "\n    tls_certificate: " + certFile + "\n    tls_key: " + keyFile
	cfg, err := resolverConfig(t, `
  lan:
    listen:
      - 192.168.1.0/24
      - "tls://192.168.1.0/24"
      - "HTTPS://192.168.1.2/dns-query"
      - "quic://[fd00::2]:8853"
    upstream: 192.168.1.1`+files, homeCredential, nasTask)
	if err != nil {
		t.Fatal(err)
	}
	spec := cfg.Resolvers["lan"].Spec
	var got []string
	for _, e := range spec.Encrypted {
		got = append(got, e.Transport+" "+e.Entry.String()+" "+e.Line)
	}
	want := []string{
		"tls 192.168.1.0/24 port 853 tls://192.168.1.0/24",
		"https 192.168.1.2:443 HTTPS://192.168.1.2/dns-query",
		"quic [fd00::2]:8853 quic://[fd00::2]:8853",
	}
	if len(spec.Listen) != 1 || !slices.Equal(got, want) || spec.CertFile != certFile || spec.KeyFile != keyFile {
		t.Errorf("listen %v, encrypted:\n%q\nwant\n%q", spec.Listen, got, want)
	}

	for _, c := range []struct {
		name, resolvers, want string
	}{
		{"an encrypted entry without a certificate", `
  lan:
    listen: "tls://192.168.1.0/24"
    upstream: 192.168.1.1`, "resolvers.lan: an entry of listen is encrypted, tls://, https:// or quic://, and the clients must be shown a certificate: give tls_certificate and tls_key, the files of the certificate and of its key, in PEM"},
		{"a certificate without an encrypted entry", `
  lan:
    listen: 192.168.1.0/24
    upstream: 192.168.1.1` + files, "resolvers.lan: tls_certificate and tls_key are for the encrypted entries of listen, and there is none: add one, as tls://192.168.1.0/24, or leave them out"},
		{"a key that isn't the certificate's", `
  lan:
    listen: "quic://192.168.1.0/24"
    upstream: 192.168.1.1
    tls_certificate: ` + certFile + `
    tls_key: ` + certFile, "resolvers.lan.tls_certificate: "},
		{"two resolvers on one address over TLS", `
  lan:
    listen: "tls://192.168.1.2"
    upstream: 192.168.1.1` + files + `
  lab:
    listen: "tls://192.168.1.2:853"
    upstream: 192.168.1.1` + files, "resolvers lab and lan both listen on "},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := resolverConfig(t, c.resolvers, homeCredential, nasTask)
			if err == nil || !strings.HasPrefix(err.Error(), c.want) {
				t.Errorf("got %v\nwant %s", err, c.want)
			}
		})
	}

	// Over TLS and over QUIC, one port is two: TCP and UDP.
	if _, err := resolverConfig(t, `
  lan:
    listen: "tls://192.168.1.2"
    upstream: 192.168.1.1`+files+`
  lab:
    listen: "quic://192.168.1.2"
    upstream: 192.168.1.1`+files, strings.Replace(homeCredential, "zone: home.arpa", "resolver: lan\n      zone: home.arpa", 1), nasTask); err != nil {
		t.Errorf("TLS and QUIC on port 853: %v", err)
	}
}
