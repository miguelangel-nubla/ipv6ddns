package config

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/certfile"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/listen"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/resolver"
	"go.yaml.in/yaml/v2"
)

// listenerOrder are the names of the listeners, in the order raw, of YAML or JSON, writes them:
// none, of a file that doesn't read, whose error the rest of the reading tells.
func listenerOrder(raw []byte, isYAML bool) []string {
	var names []string
	if isYAML {
		var doc yaml.MapSlice
		if yaml.Unmarshal(raw, &doc) != nil {
			return nil
		}
		for _, item := range doc {
			if item.Key != "listeners" {
				continue
			}
			listeners, _ := item.Value.(yaml.MapSlice)
			for _, l := range listeners {
				names = append(names, fmt.Sprint(l.Key))
			}
		}
		return names
	}
	keys := func(raw []byte, each func(key string, d *json.Decoder) error) error {
		d := json.NewDecoder(bytes.NewReader(raw))
		if t, err := d.Token(); err != nil || t != json.Delim('{') {
			return fmt.Errorf("no object")
		}
		for d.More() {
			t, err := d.Token()
			if err != nil {
				return err
			}
			key, _ := t.(string)
			if err := each(key, d); err != nil {
				return err
			}
		}
		return nil
	}
	_ = keys(raw, func(key string, d *json.Decoder) error {
		var value json.RawMessage
		if err := d.Decode(&value); err != nil || key != "listeners" {
			return err
		}
		return keys(value, func(name string, d *json.Decoder) error {
			names = append(names, name)
			var skip json.RawMessage
			return d.Decode(&skip)
		})
	})
	return names
}

// listenersInOrder are the names of the listeners in the order written, as NewConfig read it, and
// those it didn't, by name, after.
func (c *Config) listenersInOrder() []string {
	var order []string
	for _, name := range c.ListenerOrder {
		if _, ok := c.Listeners[name]; ok && !slices.Contains(order, name) {
			order = append(order, name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(c.Listeners)) {
		if !slices.Contains(order, name) {
			order = append(order, name)
		}
	}
	return order
}

// certificateNames are the names a certificate of certificates is for: of its files, read now;
// of ACME, its names as written, relative to the zone of its credential, or full. Of files that
// don't read, an error.
func (c *Config) certificateNames(name string) (names []string, acme bool, err error) {
	t, ok := c.Certificates[name]
	if !ok {
		return nil, false, fmt.Errorf("listeners: there is no certificate %s: add it under certificates, or fix its name", name)
	}
	if t.ACME != nil {
		return slices.Clone(t.ACME.Names), true, nil
	}
	pair, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
	if err != nil {
		return nil, false, fmt.Errorf("certificates.%s: %s and %s can't be read: %w", name, t.CertFile, t.KeyFile, err)
	}
	if pair.Leaf == nil {
		return nil, false, fmt.Errorf("certificates.%s: %s has no certificate: give one of PEM", name, t.CertFile)
	}
	return slices.Clone(pair.Leaf.DNSNames), false, nil
}

// checkServerName checks the server_name of the listener at path: no wildcard, of a listener with
// encrypted entries, and a name its certificate is for. Of ACME, whose names are relative to a
// zone only its provider knows, a name of the certificate followed by any zone.
func (c *Config) checkServerName(path string, l Listener) error {
	name := certfile.Canonical(l.ServerName)
	switch {
	case l.ServerName == "":
		return nil
	case l.TLS == "":
		return fmt.Errorf("%s.server_name is the name of the encrypted entries of listen, and there is none: add one, as tls://192.168.1.2, or leave server_name out", path)
	case strings.Contains(name, "*"):
		return fmt.Errorf("%s.server_name: %s is a wildcard, and the clients need a name to ask: give one it is for, as server_name: dns.lan.example.com", path, l.ServerName)
	}
	names, acme, err := c.certificateNames(l.TLS)
	if err != nil {
		return err
	}
	for _, n := range names {
		if certfile.Matches(n, name) {
			return nil
		}
		// Of ACME, as relative: dns.lan of example.com.
		if extra := strings.Count(name, ".") - strings.Count(certfile.Canonical(n), "."); acme && extra > 0 {
			labels := strings.Split(name, ".")
			if certfile.Matches(n+"."+strings.Join(labels[len(labels)-extra:], "."), name) {
				return nil
			}
		}
	}
	example := ""
	if i := slices.IndexFunc(names, func(n string) bool { return !strings.HasPrefix(n, "*") }); i >= 0 {
		example = fmt.Sprintf(", as server_name: %s,", names[i])
	}
	if len(names) == 0 {
		return fmt.Errorf("%s.server_name: the certificate %s is for no name, and the clients need one to ask: add %s to the certificate, or leave server_name out", path, l.TLS, l.ServerName)
	}
	return fmt.Errorf("%s.server_name: the certificate %s isn't for %s: it is for %s. Give one of its names%s or add %s to the certificate", path, l.TLS, l.ServerName, strings.Join(names, ", "), example, l.ServerName)
}

// sharing is an address of a listener's entry, as it listens there.
type sharing struct {
	listener string
	entry    int
	scheme   string
	// host:port, as listen.Addresses has it: "" the host of every address.
	address string
}

// protocolsOf are the protocols of IP an encrypted scheme listens over.
func protocolsOf(scheme string) []string { return []string{resolver.Protocol(scheme)} }

// checkListenersShared checks the entries of different listeners on one address and port, of one
// protocol, however written: a port alone and every address are the same. Only encrypted entries of
// one scheme share one, plain DNS never, which has no name a client asks, each listener with a
// resolver and a certificate: a client is told the listener by the name it asks in its handshake,
// its server_name, or else the first, as written, whose certificate is for it, and one that asks
// none, or another, gets the first. Two of one certificate, or whose certificates are both for a
// name, are told apart by the later one's server_name, which no other's is. Those are marked Shared.
func (c *Config) checkListenersShared() error {
	order := c.listenersInOrder()
	var all []sharing
	for _, name := range order {
		for i, e := range c.Listeners[name].Entries {
			if e.Scheme == SchemeDNS || e.Scheme == SchemeHTTP {
				// Plain DNS, which has no name a client asks, and HTTP, which is no resolver's:
				// the resolvers' and the web servers' own checks tell of two on one address.
				continue
			}
			// One that doesn't read now, as a network no address of the machine is in yet, is
			// the start's to tell.
			addresses, err := listen.Addresses([]listen.Entry{e.Entry})
			if err != nil {
				continue
			}
			for _, a := range addresses {
				// Any port that is free: never another's.
				if strings.HasSuffix(a, ":0") {
					continue
				}
				all = append(all, sharing{name, i, e.Scheme, a})
			}
		}
	}
	for i, a := range all {
		for _, b := range all[i+1:] {
			if a.listener == b.listener || resolver.Overlap(a.address, b.address) == "" ||
				!slices.ContainsFunc(protocolsOf(a.scheme), func(p string) bool { return slices.Contains(protocolsOf(b.scheme), p) }) {
				continue
			}
			if a.address != b.address {
				// Every address and one of them: two sockets, which can't both listen.
				ea, eb := c.Listeners[a.listener].Entries[a.entry], c.Listeners[b.listener].Entries[b.entry]
				_, port, _ := net.SplitHostPort(b.address)
				example := eb.Line
				if resolver.Overlap(a.address, b.address) == a.address {
					example = ea.Line
				}
				return fmt.Errorf("listeners.%s.listen: %s is on port %s, as listeners.%s's %s, and one of them is on every address, two sockets that can't both listen: to share the port, write the same address in both, as %s", b.listener, eb.Line, port, a.listener, ea.Line, example)
			}
			if err := c.checkShared(a, b); err != nil {
				return err
			}
			c.Listeners[a.listener].Entries[a.entry].Shared = true
			c.Listeners[b.listener].Entries[b.entry].Shared = true
		}
	}
	return nil
}

// checkShared checks that the entries a and b, of two listeners, a's the first, can share their
// address and port.
func (c *Config) checkShared(a, b sharing) error {
	la, lb := c.Listeners[a.listener], c.Listeners[b.listener]
	ea, eb := la.Entries[a.entry], lb.Entries[b.entry]
	path := "listeners." + b.listener
	switch {
	case a.scheme != b.scheme:
		return fmt.Errorf("%s.listen: %s is on the address and port of listeners.%s's %s: only entries of one scheme share a port, tls:// with tls://, quic:// with quic://, https:// with https://. Give one of them another port", path, eb.Line, a.listener, ea.Line)
	case la.Resolver == "" || lb.Resolver == "":
		alone := a.listener
		if lb.Resolver == "" {
			alone = b.listener
		}
		return fmt.Errorf("listeners.%s.listen: %s is shared with another listener, and only a resolver's entries are shared: name %s in a resolver's listeners, or give the entry an address or port of its own", alone, map[string]string{a.listener: ea.Line, b.listener: eb.Line}[alone], alone)
	case la.ServerName != "" && certfile.Canonical(la.ServerName) == certfile.Canonical(lb.ServerName):
		return fmt.Errorf("%s.server_name: listeners %s and %s share %s, and both have the server_name %s: a client that asks it can't be told which. Give each a name of its own", path, a.listener, b.listener, eb.Line, lb.ServerName)
	case lb.ServerName != "":
		// Told apart by its server_name, asked exactly: a name both certificates are for, and
		// no server_name, is a's, the first.
		return nil
	case la.TLS == lb.TLS:
		return fmt.Errorf("%s.tls: listeners %s and %s share %s with one certificate, %s, and the name a client asks can't tell them apart: add a server_name to %s, a name of the certificate its clients ask%s or give each a certificate of its own names", path, a.listener, b.listener, eb.Line, la.TLS, b.listener, c.serverNameExample(la, b.listener))
	}
	na, _, err := c.certificateNames(la.TLS)
	if err != nil {
		return err
	}
	nb, _, err := c.certificateNames(lb.TLS)
	if err != nil {
		return err
	}
	if name := namesOverlap(na, nb); name != "" {
		return fmt.Errorf("%s.tls: listeners %s and %s share %s, and both their certificates, %s and %s, are for %s: a client that asks it can't be told which. Add a server_name to %s, the name its clients ask, or give each certificate names the other's isn't for", path, a.listener, b.listener, eb.Line, la.TLS, lb.TLS, name, b.listener)
	}
	return nil
}

// serverNameExample is ", as server_name: <name>," of a name of l's certificate a listener of
// the name listener could be given, other than l's server_name: of a wildcard, the listener's name
// below it, else another name of it. It is "", of none.
func (c *Config) serverNameExample(l Listener, listener string) string {
	names, _, err := c.certificateNames(l.TLS)
	if err != nil {
		return ""
	}
	taken := certfile.Canonical(l.ServerName)
	for _, n := range names {
		if base, ok := strings.CutPrefix(n, "*."); ok && certfile.Canonical(listener+"."+base) != taken {
			return fmt.Sprintf(", as server_name: %s,", listener+"."+base)
		}
	}
	for _, n := range names {
		if !strings.HasPrefix(n, "*") && certfile.Canonical(n) != taken {
			return fmt.Sprintf(", as server_name: %s,", n)
		}
	}
	return ""
}

// namesOverlap is a name that certificates of the names a and b would both be shown for, or ""
// of none: the same name, or a wildcard and a name of one label more, or the same wildcard.
func namesOverlap(a, b []string) string {
	for _, x := range a {
		for _, y := range b {
			switch {
			case certfile.Matches(x, y):
				return certfile.Canonical(y)
			case certfile.Matches(y, x):
				return certfile.Canonical(x)
			}
		}
	}
	return ""
}
