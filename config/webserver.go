package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/listen"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/resolver"
)

// Webserver is a web server, of the report, /status.json and /metrics, and of /nic/update for the
// push sources: one of webservers, by its name.
type Webserver struct {
	// Required. The listeners it serves on, by name: their HTTP entries, and every path but
	// /dns-query of their HTTPS ones.
	Listeners StringList `json:"listeners,omitempty"`
	// The clients it answers; any other gets 403. It replaces its listeners' allow. Default: each
	// listener's, on that listener's entries; without one, everyone.
	Allow AllowList `json:"allow,omitempty"`

	// Read: where its errors are, as webservers.main; the sockets it opens itself, and the HTTPS
	// entries of resolvers it shares, by the listeners' names.
	Path    string           `json:"-"`
	Entries []WebEntry       `json:"-"`
	Shared  []SharedWebEntry `json:"-"`
}

// WebEntry is a socket a web server opens, of a listener: of HTTP, or of HTTPS with a
// certificate, and the clients it answers, nil for everyone.
type WebEntry struct {
	Listener    string
	Entry       listen.Entry
	Certificate string
	Allow       []netip.Prefix
}

// SharedWebEntry is a listener's HTTPS entries, which its resolver opens and serves the web
// server on, at every path but /dns-query: the clients it answers there, nil for everyone.
type SharedWebEntry struct {
	Listener, Resolver string
	Lines              []string
	Allow              []netip.Prefix
}

// DefaultWebserverPort is the port of a listener's http:// entries that give none.
const DefaultWebserverPort = "8053"

// checkWebserverRenamed tells, of a configuration not yet checked by the schema, that webserver
// is named now, under webservers, with its block as it was.
func checkWebserverRenamed(configData []byte) error {
	var c map[string]json.RawMessage
	if json.Unmarshal(configData, &c) != nil {
		return nil
	}
	const example = "\n\nlisteners:\n  web:\n    listen:\n      - http://8053\n      - https://192.168.1.2:8443\n    tls: home\nwebservers:\n  main:\n    listeners:\n      - web"
	if _, ok := c["webserver"]; ok {
		return errors.New("webserver is now webservers, each web server by a name of your choice, with its listen and tls in a listener under listeners, its plain entries as http://, as" + example)
	}
	var webservers map[string]map[string]json.RawMessage
	if json.Unmarshal(c["webservers"], &webservers) != nil {
		return nil
	}
	for _, name := range slices.Sorted(maps.Keys(webservers)) {
		for _, key := range []string{"listen", "tls"} {
			if _, ok := webservers[name][key]; ok {
				return fmt.Errorf("webservers.%s.%s is a listener's now: move the web server's listen and tls to one under listeners, its plain entries as http://, and name it in the web server's listeners, as%s", name, key, example)
			}
		}
		if _, ok := webservers[name]["listeners"]; !ok {
			return fmt.Errorf("webservers.%s.listeners is missing: give the listeners where it serves, under listeners, as http://8053", name)
		}
	}
	return nil
}

// setUpWebservers reads the web servers' entries, of their listeners: of HTTP, of HTTPS, and of
// HTTPS a resolver opens and shares.
func (c *Config) setUpWebservers() error {
	for _, name := range slices.Sorted(maps.Keys(c.Webservers)) {
		w := c.Webservers[name]
		w.Path = "webservers." + name
		w.Entries, w.Shared = nil, nil
		if len(w.Listeners) == 0 {
			return fmt.Errorf("%s.listeners is missing: give the listeners where it serves, under listeners, as http://8053", w.Path)
		}
		allow, err := parseAllow(w.Path, w.Allow)
		if err != nil {
			return err
		}
		for i, ln := range w.Listeners {
			// A listener named twice is one.
			if slices.Contains(w.Listeners[:i], ln) {
				continue
			}
			l := c.Listeners[ln]
			entryAllow := allow
			if entryAllow == nil {
				entryAllow = l.Allowed
			}
			var shared []string
			for j, le := range l.Entries {
				// An entry written twice is one socket, as a resolver's is.
				if slices.ContainsFunc(l.Entries[:j], func(o ListenerEntry) bool { return o.Scheme == le.Scheme && o.Entry == le.Entry }) {
					continue
				}
				switch {
				case le.Scheme == SchemeHTTP:
					w.Entries = append(w.Entries, WebEntry{Listener: ln, Entry: le.Entry, Allow: entryAllow})
				case le.Scheme == SchemeHTTPS && l.Resolver != "":
					shared = append(shared, le.Line)
				case le.Scheme == SchemeHTTPS:
					w.Entries = append(w.Entries, WebEntry{Listener: ln, Entry: le.Entry, Certificate: l.TLS, Allow: entryAllow})
				}
			}
			if len(shared) > 0 {
				w.Shared = append(w.Shared, SharedWebEntry{Listener: ln, Resolver: l.Resolver, Lines: shared, Allow: entryAllow})
			}
		}
		c.Webservers[name] = w
	}
	return c.checkWebSockets()
}

// checkWebserversServe tells of a web server that would serve nowhere, as none of its listeners
// has an http:// or https:// entry: it would open nothing, without a word. And of a push source
// with a password when no web server serves: a router's updates come through one. After the web
// servers are set up, and the listeners' own errors.
func (c *Config) checkWebserversServe() error {
	for _, name := range slices.Sorted(maps.Keys(c.Webservers)) {
		if w := c.Webservers[name]; len(w.Entries) == 0 && len(w.Shared) == 0 {
			return fmt.Errorf("%s.listeners: %s has no http:// nor https:// entry, so the web server would serve nowhere: add one to its listen, as http://8053, or name a listener that has one", w.Path, strings.Join(w.Listeners, ", "))
		}
	}
	for _, name := range slices.Sorted(maps.Keys(c.Sources)) {
		if c.Sources[name].Type == SourcePush && c.Sources[name].Password != "" && !c.HasWebserver() {
			return fmt.Errorf("source %s: a router pushes its addresses through a web server, at /nic/update: add one under webservers", name)
		}
	}
	return nil
}

// checkWebSockets tells of a socket a web server opens that is on the address and port of
// another, however written: of another web server's, or of an entry a resolver listens on over
// TCP, plain DNS or DNS over TLS. One of them couldn't listen, and the start would fail after
// the rest had started. The HTTPS entries of two listeners are checkListenersShared's; and two
// entries of one web server that aren't the same address, as a port alone and a network, are
// the start's to tell, as two of one resolver are.
func (c *Config) checkWebSockets() error {
	type socket struct {
		listener, scheme, line, address string
		// The web server that opens it: none, a resolver's.
		web string
	}
	var all []socket
	for _, name := range c.listenersInOrder() {
		l := c.Listeners[name]
		for j, e := range l.Entries {
			web := ""
			if e.Scheme == SchemeHTTP || e.Scheme == SchemeHTTPS && l.Resolver == "" {
				web = l.Web
			}
			served := web != "" || l.Resolver != "" && e.Scheme != SchemeHTTP
			if !served || e.Scheme == resolver.TransportQUIC ||
				slices.ContainsFunc(l.Entries[:j], func(o ListenerEntry) bool { return o.Scheme == e.Scheme && o.Entry == e.Entry }) {
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
				if !strings.HasSuffix(a, ":0") {
					all = append(all, socket{name, e.Scheme, e.Line, a, web})
				}
			}
		}
	}
	for i, a := range all {
		for _, b := range all[i+1:] {
			if a.web == "" && b.web == "" || a.web == b.web && a.address != b.address || resolver.Overlap(a.address, b.address) == "" {
				continue
			}
			if a.listener != b.listener && a.scheme == SchemeHTTPS && b.scheme == SchemeHTTPS {
				continue
			}
			return fmt.Errorf("listeners.%s.listen: %s is on the address and port of listeners.%s's %s, two sockets that can't both listen: give one of them another port, or leave one out", b.listener, b.line, a.listener, a.line)
		}
	}
	return nil
}

// HasWebserver tells whether a web server has a socket to serve on, its own or one a resolver
// shares, once the web servers are set up: for /nic/update, of the push sources.
func (c *Config) HasWebserver() bool {
	for _, w := range c.Webservers {
		if len(w.Entries) > 0 || len(w.Shared) > 0 {
			return true
		}
	}
	return false
}
