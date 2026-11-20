package config

import (
	"os"
	"path/filepath"
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
    upstream: [192.168.1.1, "1.1.1.1:5353", "[2606:4700:4700::1111]"]
    records: [www.example.com. CNAME nas.home.arpa.]`
	homeCredential = `
  home:
    provider: resolver
    settings:
      zone: home.arpa
      records: [printer A 192.168.1.20, files CNAME nas, "_ipp._tcp SRV 0 0 631 printer"]`
	nasTask = `
  nas:
    filter: [{mac: {address: "00:11:22:33:44:55"}}]
    endpoints:
      home: [nas, "*.dev"]`
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
    allow: [192.168.1.0/24, "fd00::/64", 10.0.0.7]
  lab:
    listen: 10.0.0.2
    upstream: 10.0.0.1`, homeCredential+`
      resolver: lan
      ttl: 5m
    debounce: 2s
  labs:
    provider: resolver
    settings: {resolver: lab, zone: home.arpa}`, nasTask)
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
			"resolvers.lan.listen: where the resolver answers is to be given: the network of its clients, as 192.168.1.0/24, for the machine's address in it, or that address; without a port, 53"},
		{"no upstream", `
  lan:
    listen: 192.168.1.0/24`, homeCredential, nasTask,
			"resolvers.lan.upstream: the servers the resolver asks what isn't its own are to be given, one or more, as 192.168.1.1 or 1.1.1.1:53: without them, it would answer no other name"},
		{"an empty upstream", `
  lan:
    listen: 192.168.1.0/24
    upstream: []`, homeCredential, nasTask,
			"resolvers.lan.upstream: the servers the resolver asks what isn't its own are to be given, one or more"},
		{"a bad listen", `
  lan:
    listen: "192.168.1.0/33"
    upstream: 192.168.1.1`, homeCredential, nasTask,
			`resolvers.lan.listen: "192.168.1.0/33": a network is as 10.2.3.0/24 or fd00::/64, and takes the default port`},
		{"a host name upstream without bootstrap", `
  lan:
    listen: 192.168.1.0/24
    upstream: [1.1.1.1, dns.google]`, homeCredential, nasTask,
			`resolvers.lan.upstream: "dns.google" is a host name: its addresses are asked of bootstrap, the servers for that alone, which is to be given, as bootstrap: [9.9.9.9]; not the system's resolver, which can be this one`},
		{"a bootstrap with no host name to find", `
  lan:
    listen: 192.168.1.0/24
    upstream: 1.1.1.1
    bootstrap: 9.9.9.9`, homeCredential, nasTask,
			"resolvers.lan.bootstrap: the servers that find the upstream servers given by host name, and every upstream is an address: leave it out"},
		{"a host name bootstrap", `
  lan:
    listen: 192.168.1.0/24
    upstream: dns.google
    bootstrap: dns.quad9.net`, homeCredential, nasTask,
			`resolvers.lan.bootstrap: "dns.quad9.net": an address, with a port or not, as 192.168.1.1, 1.1.1.1:53 or [2001:db8::1]:53`},
		{"an upstream that is neither", `
  lan:
    listen: 192.168.1.0/24
    upstream: "dns google"
    bootstrap: 9.9.9.9`, homeCredential, nasTask,
			`resolvers.lan.upstream: "dns google": an address or a host name, with a port or not, as 192.168.1.1, 1.1.1.1:53, [2001:db8::1]:53 or dns.example.net`},
		{"a host name upstream of port 0", `
  lan:
    listen: 192.168.1.0/24
    upstream: dns.google:0
    bootstrap: 9.9.9.9`, homeCredential, nasTask,
			`resolvers.lan.upstream: "dns.google:0": an address or a host name, with a port or not, as 192.168.1.1, 1.1.1.1:53, [2001:db8::1]:53 or dns.example.net`},
		{"a bad allow", lanResolver + `
    allow: [lan]`, homeCredential, nasTask,
			`resolvers.lan.allow: "lan": a network, as 192.168.1.0/24 or fd00::/64, or an address`},
		{"a resolver naming none", lanResolver, homeCredential + `
      resolver: wan`, nasTask,
			"credentials.home.settings.resolver: wan is no resolver: they are lan"},
		{"no resolver", ` {}`, homeCredential, nasTask,
			"credentials.home: the provider resolver is a zone that a resolver answers, and there is none: add one to resolvers, with where it listens and the servers it asks"},
		{"which of two", lanResolver + `
  lab:
    listen: 10.0.0.2
    upstream: 10.0.0.1`, homeCredential, nasTask,
			"credentials.home.settings.resolver: which resolver answers the zone is to be said, of lab, lan"},
		{"no zone", lanResolver, `
  home:
    provider: resolver
    settings: {}`, nasTask,
			"credentials.home.settings.zone: the zone the resolver answers is to be given, as home.arpa"},
		{"one zone twice", lanResolver, homeCredential + `
  office:
    provider: resolver
    settings: {zone: Home.Arpa.}`, nasTask,
			"credentials home and office: both are the zone home.arpa of resolver lan: a zone is one credential's"},
		{"one address twice", lanResolver + `
  lab:
    listen: [10.0.0.2, 192.168.1.0/24]
    upstream: 10.0.0.1`, homeCredential + `
      resolver: lan`, nasTask,
			"resolvers lab and lan both listen on 192.168.1.0/24 port 53: an address and port is one resolver's"},
		{"a zone record outside", lanResolver, `
  home:
    provider: resolver
    settings: {zone: home.arpa, records: [printer.example.com. A 192.168.1.20]}`, nasTask,
			`credentials.home.settings.records: "printer.example.com. A 192.168.1.20": printer.example.com. is not of the zone home.arpa: a zone's records are of its names, relative to it, or absolute within it`},
		{"a resolver record without its dot", `
  lan:
    listen: 192.168.1.0/24
    upstream: 192.168.1.1
    records: [www.example.com CNAME nas.home.arpa.]`, homeCredential, nasTask,
			`resolvers.lan.records: "www.example.com CNAME nas.home.arpa.": the name www.example.com is to be absolute, with its trailing dot, as www.example.com.: these records are of no zone`},
		{"a resolver record's target without its dot", `
  lan:
    listen: 192.168.1.0/24
    upstream: 192.168.1.1
    records: [www.example.com. CNAME nas]`, homeCredential, nasTask,
			`resolvers.lan.records: "www.example.com. CNAME nas": bad CNAME Target: "nas": every name in these records is absolute, with its trailing dot`},
		{"a resolver record in a zone", `
  lan:
    listen: 192.168.1.0/24
    upstream: 192.168.1.1
    records: [tv.home.arpa. A 192.168.1.30]`, homeCredential, nasTask,
			`resolvers.lan.records: "tv.home.arpa. A 192.168.1.30": tv.home.arpa. is of the zone home.arpa, of credential home: give it there, in its records`},
		{"a record that doesn't parse", lanResolver, `
  home:
    provider: resolver
    settings: {zone: home.arpa, records: [printer A 192.168.1.300]}`, nasTask,
			`credentials.home.settings.records: "printer A 192.168.1.300": bad A A: "192.168.1.300"`},
		{"a record with no data", lanResolver, `
  home:
    provider: resolver
    settings: {zone: home.arpa, records: [printer A]}`, nasTask,
			`credentials.home.settings.records: "printer A": a A record with no data`},
		{"a CNAME beside other data", lanResolver, `
  home:
    provider: resolver
    settings: {zone: home.arpa, records: [files CNAME nas, files TXT "x"]}`, nasTask,
			"credentials.home.settings.records: files.home.arpa. has a CNAME and other records: a CNAME is alone at its name, the other data is its target's"},
		{"a record of a task's name", lanResolver, `
  home:
    provider: resolver
    settings: {zone: home.arpa, records: [NAS TXT "x"]}`, nasTask,
			`credentials.home.settings.records: "NAS TXT \"x\"": nas.home.arpa. is a name task nas publishes, which has its addresses: a record is of another name`},
		{"a CNAME loop", lanResolver, `
  home:
    provider: resolver
    settings: {zone: home.arpa, records: [a CNAME b, b CNAME A]}`, nasTask,
			"resolvers.lan: the CNAMEs a.home.arpa. -> b.home.arpa. -> a.home.arpa. are a loop"},
		{"a CNAME loop through a zone and the resolver", `
  lan:
    listen: 192.168.1.0/24
    upstream: 192.168.1.1
    records: [www.example.com. CNAME a.home.arpa.]`, `
  home:
    provider: resolver
    settings: {zone: home.arpa, records: [a CNAME www.example.com.]}`, nasTask,
			"resolvers.lan: the CNAMEs www.example.com. -> a.home.arpa. -> www.example.com. are a loop"},
		{"a CNAME loop through a wildcard", lanResolver, `
  home:
    provider: resolver
    settings: {zone: home.arpa, records: ["*.lab CNAME x.lab"]}`, nasTask,
			"resolvers.lan: the CNAMEs *.lab.home.arpa. -> x.lab.home.arpa. -> x.lab.home.arpa. are a loop"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := resolverConfig(t, c.resolvers, c.credentials, c.tasks)
			if err == nil || err.Error() != c.want {
				t.Errorf("got %v\nwant %s", err, c.want)
			}
		})
	}
}

// Upstream servers by host name, with the bootstrap servers that find them.
func TestResolverConfigHostNames(t *testing.T) {
	cfg, err := resolverConfig(t, `
  lan:
    listen: 192.168.1.0/24
    upstream: [DNS.Example.NET., "dns.example.org:5353", 1.1.1.1]
    bootstrap: [9.9.9.9, "[2620:fe::fe]:53"]`, homeCredential, nasTask)
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
