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
// and a task nas there, with extra in YAML after it. Unless the resolvers give their own listeners,
// in a block after theirs, it has lanListener.
func resolverConfig(t *testing.T, resolvers, credentials, tasks string) (Config, error) {
	t.Helper()
	text := "resolvers:\n" + resolvers + "\ncredentials:\n" + credentials + "\ntasks:\n" + tasks + "\n"
	if !strings.Contains(resolvers, "\nlisteners:\n") {
		text += lanListener
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return NewConfig(path)
}

const (
	lanListener = `listeners:
  lan:
    listen:
      - dns://192.168.1.0/24
`
	lanResolver = `
  lan:
    listeners:
      - lan
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
    listeners:
      - lab
    upstream: 10.0.0.1
`+lanListener+`  lab:
    listen:
      - dns://10.0.0.2`, homeCredential+`
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
		{"no listeners", `
  lan:
    upstream: 192.168.1.1`, homeCredential, nasTask,
			"resolvers.lan.listeners is missing: give the listeners where the resolver answers, under listeners, as dns://192.168.1.2 for this machine's address on the clients' network. Without a port, 53"},
		{"no upstream", `
  lan:
    listeners:
      - lan`, homeCredential, nasTask,
			"resolvers.lan.upstream is missing: give one or more servers to ask about the names that aren't the resolver's own, as 192.168.1.1 or 1.1.1.1:53. Without them, it answers no other name"},
		{"an empty upstream", `
  lan:
    listeners:
      - lan
    upstream: []`, homeCredential, nasTask,
			"resolvers.lan.upstream is missing: give one or more servers to ask about the names that aren't the resolver's own"},
		{"a bad listen", `
  lan:
    listeners:
      - lan
    upstream: 192.168.1.1
listeners:
  lan:
    listen:
      - "dns://192.168.1.0/33"`, homeCredential, nasTask,
			`listeners.lan.listen: "192.168.1.0/33": write a network as 10.2.3.0/24 or fd00::/64, without a port: it uses the default one`},
		{"a host name upstream without bootstrap", `
  lan:
    listeners:
      - lan
    upstream:
      - 1.1.1.1
      - dns.google`, homeCredential, nasTask,
			`resolvers.lan.upstream: "dns.google" is a host name, and there's no bootstrap to look it up. Add bootstrap, servers used for that lookup only, as bootstrap: 9.9.9.9. The system's resolver isn't used, as it may be this one`},
		{"a bootstrap with no host name to find", `
  lan:
    listeners:
      - lan
    upstream: 1.1.1.1
    bootstrap: 9.9.9.9`, homeCredential, nasTask,
			"resolvers.lan.bootstrap only looks up upstream servers given by host name, and every upstream here is an address: leave it out"},
		{"a host name bootstrap", `
  lan:
    listeners:
      - lan
    upstream: dns.google
    bootstrap: dns.quad9.net`, homeCredential, nasTask,
			`resolvers.lan.bootstrap: "dns.quad9.net" is not an address, with or without a port, as 192.168.1.1, 1.1.1.1:53 or [2001:db8::1]:53`},
		{"an upstream that is neither", `
  lan:
    listeners:
      - lan
    upstream: "dns google"
    bootstrap: 9.9.9.9`, homeCredential, nasTask,
			`resolvers.lan.upstream: "dns google" is not an address or a host name, with or without a port, as 192.168.1.1, 1.1.1.1:53, [2001:db8::1]:53 or dns.example.net`},
		{"a host name upstream of port 0", `
  lan:
    listeners:
      - lan
    upstream: dns.google:0
    bootstrap: 9.9.9.9`, homeCredential, nasTask,
			`resolvers.lan.upstream: "dns.google:0" is not an address or a host name, with or without a port, as 192.168.1.1, 1.1.1.1:53, [2001:db8::1]:53 or dns.example.net`},
		{"an encrypted upstream by host name without bootstrap", `
  lan:
    listeners:
      - lan
    upstream:
      - 1.1.1.1
      - "tls://dns.example.net"`, homeCredential, nasTask,
			`resolvers.lan.upstream: "tls://dns.example.net" is at a host name, and there's no bootstrap to look it up. Add bootstrap, servers used for that lookup only, as bootstrap: 9.9.9.9. The system's resolver isn't used, as it may be this one`},
		{"a bootstrap with encrypted upstreams at addresses", `
  lan:
    listeners:
      - lan
    upstream:
      - "tls://1.1.1.1"
      - "https://[2606:4700:4700::1111]/dns-query"
    bootstrap: 9.9.9.9`, homeCredential, nasTask,
			"resolvers.lan.bootstrap only looks up upstream servers given by host name, and every upstream here is an address: leave it out"},
		{"an unknown scheme", `
  lan:
    listeners:
      - lan
    upstream: "quic://dns.example.net"`, homeCredential, nasTask,
			`resolvers.lan.upstream: "quic://dns.example.net": unknown scheme quic: use plain DNS, as 1.1.1.1 or dns.example.net; tls:// for DNS over TLS, as tls://1.1.1.1; or https:// for DNS over HTTPS, as https://dns.example.net/dns-query`},
		{"DNS over HTTP, not HTTPS", `
  lan:
    listeners:
      - lan
    upstream: "http://dns.example.net/dns-query"`, homeCredential, nasTask,
			`resolvers.lan.upstream: "http://dns.example.net/dns-query": unknown scheme http: use plain DNS, as 1.1.1.1 or dns.example.net; tls:// for DNS over TLS, as tls://1.1.1.1; or https:// for DNS over HTTPS, as https://dns.example.net/dns-query`},
		{"DNS over HTTPS without a path", `
  lan:
    listeners:
      - lan
    upstream: "https://dns.example.net"
    bootstrap: 9.9.9.9`, homeCredential, nasTask,
			`resolvers.lan.upstream: "https://dns.example.net": DNS over HTTPS needs a path, as https://dns.example.net/dns-query`},
		{"DNS over HTTPS with the root for a path", `
  lan:
    listeners:
      - lan
    upstream: "https://1.1.1.1:8443/"`, homeCredential, nasTask,
			`resolvers.lan.upstream: "https://1.1.1.1:8443/": DNS over HTTPS needs a path, as https://1.1.1.1:8443/dns-query`},
		{"DNS over HTTPS with a query", `
  lan:
    listeners:
      - lan
    upstream: "https://dns.example.net/dns-query?dns=x"
    bootstrap: 9.9.9.9`, homeCredential, nasTask,
			`resolvers.lan.upstream: "https://dns.example.net/dns-query?dns=x": DNS over HTTPS takes a host, with or without a port, and a path: no user, query or fragment`},
		{"DNS over HTTPS with a fragment", `
  lan:
    listeners:
      - lan
    upstream: "https://dns.example.net/dns-query#x"
    bootstrap: 9.9.9.9`, homeCredential, nasTask,
			`resolvers.lan.upstream: "https://dns.example.net/dns-query#x": DNS over HTTPS takes a host, with or without a port, and a path: no user, query or fragment`},
		{"DNS over HTTPS with a user", `
  lan:
    listeners:
      - lan
    upstream: "https://me:secret@dns.example.net/dns-query"
    bootstrap: 9.9.9.9`, homeCredential, nasTask,
			`resolvers.lan.upstream: "https://me:secret@dns.example.net/dns-query": DNS over HTTPS takes a host, with or without a port, and a path: no user, query or fragment`},
		{"DNS over TLS with a path", `
  lan:
    listeners:
      - lan
    upstream: "tls://1.1.1.1/dns-query"`, homeCredential, nasTask,
			`resolvers.lan.upstream: "tls://1.1.1.1/dns-query": DNS over TLS takes a host, with or without a port, and no path: paths are for https://`},
		{"DNS over TLS with a query", `
  lan:
    listeners:
      - lan
    upstream: "tls://1.1.1.1?x=1"`, homeCredential, nasTask,
			`resolvers.lan.upstream: "tls://1.1.1.1?x=1": DNS over TLS takes a host, with or without a port: no user, query or fragment`},
		{"DNS over TLS at port 0", `
  lan:
    listeners:
      - lan
    upstream: "tls://1.1.1.1:0"`, homeCredential, nasTask,
			`resolvers.lan.upstream: "tls://1.1.1.1:0": the port 0 is out of range: ports go from 1 to 65535`},
		{"DNS over HTTPS at port 0", `
  lan:
    listeners:
      - lan
    upstream: "https://dns.example.net:0/dns-query"
    bootstrap: 9.9.9.9`, homeCredential, nasTask,
			`resolvers.lan.upstream: "https://dns.example.net:0/dns-query": the port 0 is out of range: ports go from 1 to 65535`},
		{"DNS over TLS at a port too high", `
  lan:
    listeners:
      - lan
    upstream: "tls://1.1.1.1:65536"`, homeCredential, nasTask,
			`resolvers.lan.upstream: "tls://1.1.1.1:65536": the port 65536 is out of range: ports go from 1 to 65535`},
		{"DNS over TLS with no host", `
  lan:
    listeners:
      - lan
    upstream: "tls://:853"`, homeCredential, nasTask,
			`resolvers.lan.upstream: "tls://:853": the host must be an address or a host name, with or without a port, as tls://1.1.1.1, tls://[2606:4700:4700::1111]:853 or tls://dns.example.net`},
		{"DNS over HTTPS at a name of one label", `
  lan:
    listeners:
      - lan
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
			"credentials.home: the resolver provider is a zone that one of the resolvers answers, and there are none: add one under resolvers, with its listeners and upstream"},
		{"which of two", lanResolver + `
  lab:
    listeners:
      - lab
    upstream: 10.0.0.1
` + lanListener + `  lab:
    listen:
      - dns://10.0.0.2`, homeCredential, nasTask,
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
    listeners:
      - lab
    upstream: 10.0.0.1
` + lanListener + `  lab:
    listen:
      - dns://10.0.0.2
      - dns://192.168.1.0/24`, homeCredential + `
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
    listeners:
      - lan
    upstream: 192.168.1.1
    records:
      - www.example.com CNAME nas.home.arpa.`, homeCredential, nasTask,
			`resolvers.lan.records: "www.example.com CNAME nas.home.arpa.": the name www.example.com must be absolute, ending in a dot, as www.example.com.: these records belong to no zone`},
		{"a resolver record's target without its dot", `
  lan:
    listeners:
      - lan
    upstream: 192.168.1.1
    records:
      - www.example.com. CNAME nas`, homeCredential, nasTask,
			`resolvers.lan.records: "www.example.com. CNAME nas": bad CNAME Target: "nas": every name in these records must be absolute, ending in a dot`},
		{"a resolver record in a zone", `
  lan:
    listeners:
      - lan
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
    listeners:
      - lan
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
    listeners:
      - lan
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
    listeners:
      - lan
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
    listeners:
      - lan
    upstream: 192.168.1.1`+text+`
listeners:
  lan:
    listen:
      - dns://192.168.1.0/24
      - " dns://192.168.1.2:5353"
      - "dns://192.168.1.0/24"
      - "dns://[fd00::2]"
      - dns://192.168.1.2`, homeCredential, nasTask)
		if err != nil {
			t.Fatal(err)
		}
		spec := cfg.Resolvers["lan"].Spec
		if spec.CacheSize != want {
			t.Errorf("cache_size%s: %d, want %d", text, spec.CacheSize, want)
		}
		if lines := []string{"dns://192.168.1.0/24", "dns://192.168.1.2:5353", "dns://[fd00::2]", "dns://192.168.1.2"}; !slices.Equal(spec.ListenLines, lines) || len(spec.Listen) != len(lines) {
			t.Errorf("listen: %+v, as written %q", spec.Listen, spec.ListenLines)
		}
	}
}

// Upstream servers by host name, with the bootstrap servers that find them.
func TestResolverConfigHostNames(t *testing.T) {
	cfg, err := resolverConfig(t, `
  lan:
    listeners:
      - lan
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

// filesCertificate is a certificates block of one certificate, home, of its files.
func filesCertificate(certFile, keyFile string) string {
	return "\ncertificates:\n  home:\n    certificate: " + certFile + "\n    key: " + keyFile
}

// An entry of a listener that starts with tls://, https:// or quic:// answers over that encrypted
// transport, on its port by default; https:// takes the path /dns-query, where it answers. They
// need a certificate, of certificates, the listener's tls; and it is for them alone.
func TestResolverConfigEncryptedListen(t *testing.T) {
	certFile, keyFile := writeTestCertificate(t)
	certificates := filesCertificate(certFile, keyFile)
	cfg, err := resolverConfig(t, `
  lan:
    listeners:
      - lan
    upstream: 192.168.1.1
listeners:
  lan:
    listen:
      - dns://192.168.1.0/24
      - "tls://192.168.1.0/24"
      - "HTTPS://192.168.1.2/dns-query"
      - "quic://[fd00::2]:8853"
    tls: home`+certificates, homeCredential, nasTask)
	if err != nil {
		t.Fatal(err)
	}
	spec := cfg.Resolvers["lan"].Spec
	var got []string
	for _, e := range spec.Encrypted {
		got = append(got, e.Transport+" "+e.Entry.String()+" "+e.Line)
		if e.CertificateName != "home" {
			t.Errorf("%s: the certificate %q", e.Line, e.CertificateName)
		}
	}
	want := []string{
		"tls 192.168.1.0/24 port 853 tls://192.168.1.0/24",
		"https 192.168.1.2:443 HTTPS://192.168.1.2/dns-query",
		"quic [fd00::2]:8853 quic://[fd00::2]:8853",
	}
	if len(spec.Listen) != 1 || !slices.Equal(got, want) {
		t.Errorf("listen %v, encrypted:\n%q\nwant\n%q", spec.Listen, got, want)
	}
	if home := cfg.Certificates["home"]; home.CertFile != certFile || home.KeyFile != keyFile || !slices.Equal(home.UsedBy, []string{"listeners.lan"}) {
		t.Errorf("the certificate: %+v", home)
	}

	for _, c := range []struct {
		name, resolvers, want string
	}{
		{"an encrypted entry without a certificate", `
  lan:
    listeners:
      - lan
    upstream: 192.168.1.1
listeners:
  lan:
    listen:
      - "tls://192.168.1.0/24"`, "listeners.lan.tls is missing: an entry of listen is encrypted, tls://, quic:// or https://, and the clients must be shown a certificate: give the name of one of certificates, as tls: home"},
		{"a certificate without an encrypted entry", `
  lan:
    listeners:
      - lan
    upstream: 192.168.1.1
listeners:
  lan:
    listen:
      - dns://192.168.1.0/24
    tls: home` + certificates, "listeners.lan.tls is for the encrypted entries of listen, and there is none: add one, as https://192.168.1.2, or leave tls out"},
		{"a certificate that isn't there", `
  lan:
    listeners:
      - lan
    upstream: 192.168.1.1
listeners:
  lan:
    listen:
      - "tls://192.168.1.0/24"
    tls: hom` + certificates, "listeners.lan.tls: there is no certificate hom: add it under certificates, or fix its name"},
		{"two resolvers on one address over TLS", `
  lan:
    listeners:
      - lan
    upstream: 192.168.1.1
  lab:
    listeners:
      - lab
    upstream: 192.168.1.1
listeners:
  lan:
    listen:
      - "tls://192.168.1.2"
    tls: home
  lab:
    listen:
      - "tls://192.168.1.2:853"
    tls: home` + certificates, "resolvers lab and lan both listen on "},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := resolverConfig(t, c.resolvers, homeCredential, nasTask)
			if err == nil || !strings.HasPrefix(err.Error(), c.want) {
				t.Errorf("got %v\nwant %s", err, c.want)
			}
		})
	}

	// Over TLS and over QUIC, one port is two: TCP and UDP. And two resolvers show one
	// certificate.
	cfg, err = resolverConfig(t, `
  lan:
    listeners:
      - lan
    upstream: 192.168.1.1
  lab:
    listeners:
      - lab
    upstream: 192.168.1.1
listeners:
  lan:
    listen:
      - "tls://192.168.1.2"
    tls: home
  lab:
    listen:
      - "quic://192.168.1.2"
    tls: home`+certificates, strings.Replace(homeCredential, "zone: home.arpa", "resolver: lan\n      zone: home.arpa", 1), nasTask)
	if err != nil {
		t.Fatalf("TLS and QUIC on port 853: %v", err)
	}
	if used := cfg.Certificates["home"].UsedBy; !slices.Equal(used, []string{"listeners.lab", "listeners.lan"}) {
		t.Errorf("used by %v", used)
	}
}

// The files of a certificate, relative, are in the configuration's folder, wherever the program
// runs.
func TestCertificateRelative(t *testing.T) {
	certFile, keyFile := writeTestCertificate(t)
	dir := t.TempDir()
	for from, to := range map[string]string{certFile: "certs/fullchain.pem", keyFile: "certs/privkey.pem"} {
		data, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}
		os.MkdirAll(filepath.Join(dir, "certs"), 0o700)
		if err := os.WriteFile(filepath.Join(dir, to), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "config.yaml")
	text := "listeners:\n  lan:\n    listen:\n      - \"tls://192.168.1.0/24\"\n    tls: home\nresolvers:\n  lan:\n    listeners:\n      - lan\n    upstream: 192.168.1.1\ncertificates:\n  home:\n    certificate: certs/fullchain.pem\n    key: certs/privkey.pem\ncredentials:\n" + homeCredential + "\ntasks:\n" + nasTask + "\n"
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := NewConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if home := cfg.Certificates["home"]; home.CertFile != filepath.Join(dir, "certs/fullchain.pem") || home.KeyFile != filepath.Join(dir, "certs/privkey.pem") {
		t.Errorf("the files: %s, %s", home.CertFile, home.KeyFile)
	}
}

// acme: names relative to the zone of the credential, which writes the challenge, and the files
// where ipv6ddns writes the certificate, by default in tls/<name>/ of the configuration's folder,
// the account's key beside them. Each mistake is told; and a certificate no server shows, or two
// of the same files.
func TestCertificateACME(t *testing.T) {
	certFile, keyFile := writeTestCertificate(t)
	public := homeCredential + `
  public:
    provider: cloudflare
    settings:
      api_token: token
      zone: example.com
      ttl: 5m
      proxied: false`
	lan := `
  lan:
    listeners:
      - lan
    upstream: 192.168.1.1
listeners:
  lan:
    listen:
      - "tls://192.168.1.0/24"
    tls: home`
	certificates := func(home string) string { return lan + "\ncertificates:\n  home:" + home }
	cfg, err := resolverConfig(t, certificates(`
    acme:
      names: dns.lan
      credential: public`), public, nasTask)
	if err != nil {
		t.Fatal(err)
	}
	home := cfg.Certificates["home"]
	dir := cfg.BaseDir
	if home.CertFile != filepath.Join(dir, "tls", "home", "fullchain.pem") || home.KeyFile != filepath.Join(dir, "tls", "home", "privkey.pem") ||
		home.AccountKeyFile != filepath.Join(dir, "tls", "home", "acme-account.key") {
		t.Errorf("the files: %+v", home)
	}
	if !slices.Equal(home.ACME.Names, []string{"dns.lan"}) {
		t.Errorf("the names: %v", home.ACME.Names)
	}
	cfg, err = resolverConfig(t, certificates(`
    certificate: /var/lib/ipv6ddns/cert.pem
    key: keys/key.pem
    acme:
      names:
        - dns.lan
        - "*.lan"
      credential: public
      email: me@example.com`), public, nasTask)
	if err != nil {
		t.Fatal(err)
	}
	home = cfg.Certificates["home"]
	if home.CertFile != "/var/lib/ipv6ddns/cert.pem" || home.KeyFile != filepath.Join(cfg.BaseDir, "keys/key.pem") || home.AccountKeyFile != "/var/lib/ipv6ddns/acme-account.key" {
		t.Errorf("the files given: %+v", home)
	}

	acmeOf := func(certificate, key string) string {
		return "\n    certificate: " + certificate + "\n    key: " + key + "\n    acme:\n      names: dns.lan\n      credential: public"
	}
	for _, c := range []struct{ name, resolvers, want string }{
		{"no names", certificates(`
    acme:
      credential: public`), "certificates.home.acme.names is missing"},
		{"no credential", certificates(`
    acme:
      names: dns.lan`), "certificates.home.acme.credential is missing"},
		{"a credential that isn't there", certificates(`
    acme:
      names: dns.lan
      credential: nope`), "certificates.home.acme.credential: there is no credential nope"},
		{"the resolver's zone", certificates(`
    acme:
      names: dns.lan
      credential: home`), "certificates.home.acme.credential: home is a zone of the resolver"},
		{"a certificate without its key", certificates(`
    certificate: cert.pem
    acme:
      names: dns.lan
      credential: public`), "certificates.home: give both certificate and key"},
		{"neither files nor acme", certificates(`
    key: key.pem`), "certificates.home: give certificate and key"},
		{"an entry of nothing", lan + "\ncertificates:\n  home:", "the configuration is not valid:\n- certificates.home: Invalid type. Expected: object, given: null"},
		{"a key that isn't the certificate's", certificates(`
    certificate: ` + certFile + `
    key: ` + certFile), "certificates.home: "},
		{"a certificate no server shows", certificates(acmeOf("a/cert.pem", "a/key.pem")) + `
  spare:` + acmeOf("b/cert.pem", "b/key.pem"), "certificates.spare: no server shows it"},
		{"two certificates of one file", certificates(acmeOf("a/cert.pem", "a/key.pem")) + `
  other:` + acmeOf("a/cert.pem", "b/key.pem"), "certificates home and other both use the file "},
		{"two certificates of one folder, and so one account key", certificates(acmeOf("a/cert.pem", "a/key.pem")) + `
  other:` + acmeOf("a/other.pem", "a/otherkey.pem"), "certificates home and other both use the file "},
		{"a certificate's file that acme writes", certificates(acmeOf(certFile, keyFile)) + `
  other:
    certificate: ` + certFile + `
    key: ` + keyFile, "certificates home and other both use the file "},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := resolverConfig(t, c.resolvers, public, nasTask)
			if err == nil || !strings.HasPrefix(err.Error(), c.want) {
				t.Errorf("got %v\nwant %s", err, c.want)
			}
		})
	}
}

// The https:// entries of a web server's listener serve HTTPS, with the listener's certificate,
// of certificates, which its http:// entries don't need; one a resolver's listener shows too; and
// each mistake is told.
func TestWebserverTLS(t *testing.T) {
	certFile, keyFile := writeTestCertificate(t)
	load := func(text string) (Config, error) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config.yaml")
		os.WriteFile(path, []byte(text+"\ncredentials:\n"+homeCredential+"\ntasks:\n"+nasTask+"\n"), 0o600)
		return NewConfig(path)
	}
	certificates := filesCertificate(certFile, keyFile)
	cfg, err := load(`listeners:
  web:
    listen:
      - http://172.30.32.1:8053
      - "https://192.168.1.2:8443"
      - "HTTPS://192.168.1.3:9443"
    tls: home
  lan:
    listen:
      - "tls://192.168.1.0/24"
    tls: home
webservers:
  main:
    listeners:
      - web
resolvers:
  lan:
    listeners:
      - lan
    upstream: 192.168.1.1` + certificates)
	if err != nil {
		t.Fatal(err)
	}
	var plain, https []string
	for _, e := range cfg.Webservers["main"].Entries {
		switch e.Certificate {
		case "":
			plain = append(plain, e.Entry.String())
		case "home":
			https = append(https, e.Entry.String())
		}
	}
	if !slices.Equal(plain, []string{"172.30.32.1:8053"}) || !slices.Equal(https, []string{"192.168.1.2:8443", "192.168.1.3:9443"}) {
		t.Errorf("plain %v, https %v", plain, https)
	}
	if used := cfg.Certificates["home"].UsedBy; !slices.Equal(used, []string{"listeners.lan", "listeners.web"}) {
		t.Errorf("used by %v", used)
	}

	for _, c := range []struct{ name, text, want string }{
		{"an https entry without tls", `listeners:
  lan:
    listen:
      - dns://192.168.1.0/24
  web:
    listen:
      - "https://192.168.1.2:8443"
webservers:
  main:
    listeners:
      - web`, "listeners.web.tls is missing: an entry of listen is encrypted, tls://, quic:// or https://"},
		{"tls without an https entry", `listeners:
  lan:
    listen:
      - dns://192.168.1.0/24
  web:
    listen:
      - http://192.168.1.2
    tls: home
webservers:
  main:
    listeners:
      - web` + certificates, "listeners.web.tls is for the encrypted entries of listen, and there is none: add one, as https://192.168.1.2"},
		{"a bad https entry", `listeners:
  lan:
    listen:
      - dns://192.168.1.0/24
  web:
    listen:
      - "https://192.168.1.0/33"
    tls: home
webservers:
  main:
    listeners:
      - web` + certificates, "listeners.web.listen: "},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := load(c.text + "\nresolvers:" + lanResolver); err == nil || !strings.HasPrefix(err.Error(), c.want) {
				t.Errorf("got %v\nwant %s", err, c.want)
			}
		})
	}
}
