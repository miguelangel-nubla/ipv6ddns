package config

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/listen"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/resolver"
)

// Listener is where servers listen, which several can share: a resolver and a web server, on
// the same HTTPS port, the resolver at /dns-query and the web server at every other path. The
// servers name it in their listeners.
type Listener struct {
	// Where, each entry with its scheme: dns://, tls://, quic://, https:// or http://.
	Listen StringList `json:"listen,omitempty"`
	// The certificate of the encrypted entries: the name of one of certificates. Required with
	// one, and only then.
	TLS string `json:"tls,omitempty"`
	// The clients its servers answer, unless a server gives its own allow, which replaces it.
	Allow AllowList `json:"allow,omitempty"`
	// The name the clients use for its encrypted entries, which its certificate must be for: the
	// target that DDR tells them. None: the certificate's first name that is no wildcard.
	ServerName string `json:"server_name,omitempty"`

	// Read: the entries, allow, and the servers that use it, by their paths; and its place
	// among the listeners, as written, the first 0.
	Entries  []ListenerEntry `json:"-"`
	Allowed  []netip.Prefix  `json:"-"`
	Resolver string          `json:"-"`
	Web      string          `json:"-"`
	Rank     int             `json:"-"`
}

// ListenerEntry is an entry of a listener: its scheme, the entry, and its text, as written; and
// whether other listeners share its socket, telling each other apart by the name a client asks.
type ListenerEntry struct {
	Scheme string
	Entry  listen.Entry
	Line   string
	Shared bool
}

// The schemes of a listener's entries.
const (
	SchemeDNS   = "dns"
	SchemeHTTP  = "http"
	SchemeHTTPS = "https"
)

// listenerSchemes are the schemes of a listener's entries, with the port of each that gives none.
var listenerSchemes = map[string]string{
	SchemeDNS:              "53",
	resolver.TransportTLS:  resolver.DefaultTLSPort,
	resolver.TransportQUIC: resolver.DefaultPortOf(resolver.TransportQUIC),
	SchemeHTTPS:            resolver.DefaultPortOf(resolver.TransportHTTPS),
	SchemeHTTP:             DefaultWebserverPort,
}

// setUpListeners reads the listeners: their entries, their certificate and their allow. Which
// servers use them, the servers' set up says.
func (c *Config) setUpListeners() error {
	order := c.listenersInOrder()
	for _, name := range slices.Sorted(maps.Keys(c.Listeners)) {
		l := c.Listeners[name]
		path := "listeners." + name
		l.Entries, l.Allowed, l.Resolver, l.Web = nil, nil, "", ""
		l.Rank = slices.Index(order, name)
		if len(l.Listen) == 0 {
			return fmt.Errorf("%s.listen is missing: give where it listens, each entry with its scheme, as https://192.168.1.2", path)
		}
		encrypted := false
		for _, line := range l.Listen {
			text := strings.TrimSpace(line)
			scheme, rest, ok := strings.Cut(text, "://")
			scheme = strings.ToLower(scheme)
			port, known := listenerSchemes[scheme]
			if !ok || !known {
				return fmt.Errorf("%s.listen: %q has no scheme: write it as dns://, tls://, quic://, https:// or http://, as https://%s", path, text, text)
			}
			if scheme == SchemeHTTPS {
				// Where DNS over HTTPS answers, written as the clients' URL has it.
				rest = strings.TrimSuffix(rest, resolver.DoHPath)
			}
			entries, err := listen.Parse([]string{rest}, port)
			if err != nil {
				return fmt.Errorf("%s.listen: %w", path, err)
			}
			for _, e := range entries {
				l.Entries = append(l.Entries, ListenerEntry{Scheme: scheme, Entry: e, Line: text})
			}
			encrypted = encrypted || scheme == resolver.TransportTLS || scheme == resolver.TransportQUIC || scheme == SchemeHTTPS
		}
		if err := c.useCertificate(path, l.TLS, encrypted, "tls://, quic:// or https://", "https://192.168.1.2"); err != nil {
			return err
		}
		if err := c.checkServerName(path, l); err != nil {
			return err
		}
		allowed, err := parseAllow(path, l.Allow)
		if err != nil {
			return err
		}
		l.Allowed = allowed
		c.Listeners[name] = l
	}
	return nil
}

// noteListenerUsers notes the servers that use each listener, before they are set up: a resolver
// tells by it whether its HTTPS entries are a web server's too.
func (c *Config) noteListenerUsers() error {
	for _, name := range slices.Sorted(maps.Keys(c.Resolvers)) {
		if err := c.useListeners("resolvers."+name, c.Resolvers[name].Listeners, true); err != nil {
			return err
		}
	}
	for _, name := range slices.Sorted(maps.Keys(c.Webservers)) {
		if err := c.useListeners("webservers."+name, c.Webservers[name].Listeners, false); err != nil {
			return err
		}
	}
	return nil
}

// useListeners notes the server at path as one that uses the listeners named: one resolver and one
// web server each, at most.
func (c *Config) useListeners(path string, names []string, resolver bool) error {
	for _, name := range names {
		l, ok := c.Listeners[name]
		if !ok {
			return fmt.Errorf("%s.listeners: there is no listener %s: add it under listeners, or fix its name", path, name)
		}
		user := &l.Web
		if resolver {
			user = &l.Resolver
		}
		if *user != "" && *user != path {
			return fmt.Errorf("%s.listeners: %s is %s's already: a listener has one resolver and one web server at most", path, name, *user)
		}
		*user = path
		c.Listeners[name] = l
	}
	return nil
}

// checkListenersServed tells of a listener no server uses, and of an entry of one that none of
// its servers serves: plain DNS, DNS over TLS or QUIC without a resolver, HTTP without a web
// server, HTTPS without either.
func (c *Config) checkListenersServed() error {
	for _, name := range slices.Sorted(maps.Keys(c.Listeners)) {
		l := c.Listeners[name]
		path := "listeners." + name
		if l.Resolver == "" && l.Web == "" {
			return fmt.Errorf("%s: no server uses it: name it in a resolver's or a web server's listeners, or leave it out", path)
		}
		for _, e := range l.Entries {
			switch {
			case e.Scheme == SchemeHTTP && l.Web == "":
				return fmt.Errorf("%s.listen: %s is HTTP, which only a web server serves, and none uses %s: name it in a web server's listeners, or leave the entry out", path, e.Line, name)
			case e.Scheme != SchemeHTTP && e.Scheme != SchemeHTTPS && l.Resolver == "":
				return fmt.Errorf("%s.listen: %s is DNS, which only a resolver serves, and none uses %s: name it in a resolver's listeners, or leave the entry out", path, e.Line, name)
			}
		}
	}
	return nil
}
