package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/listen"
)

// Webserver is a web server, of the report, /status.json and /metrics, and of /nic/update for the
// push sources: one of webservers, by its name.
type Webserver struct {
	// Required. The listeners it serves on, by name: their HTTP entries, and every path but
	// /dns-query of their HTTPS ones.
	Listeners StringList `json:"listeners,omitempty"`
	// The clients it answers; any other gets 403. It replaces its listeners' allow. Default: each
	// listener's, on that listener's entries; without one, everyone.
	Allow StringList `json:"allow,omitempty"`

	// Read: where its errors are, as webservers.main; the sockets it opens itself, and the HTTPS
	// entries of resolvers it shares, by the listeners' names.
	Path    string           `json:"-"`
	Entries []WebEntry       `json:"-"`
	Shared  []SharedWebEntry `json:"-"`
}

// WebEntry is a socket a web server opens: of HTTP, or of HTTPS with a certificate, and the
// clients it answers, nil for everyone.
type WebEntry struct {
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
		var allow []netip.Prefix
		for _, a := range w.Allow {
			p, err := parseNetwork(a)
			if err != nil {
				return fmt.Errorf("%s.allow: %w", w.Path, err)
			}
			allow = append(allow, p)
		}
		for _, ln := range w.Listeners {
			l := c.Listeners[ln]
			entryAllow := allow
			if entryAllow == nil {
				entryAllow = l.Allowed
			}
			var shared []string
			for _, le := range l.Entries {
				switch {
				case le.Scheme == SchemeHTTP:
					w.Entries = append(w.Entries, WebEntry{Entry: le.Entry, Allow: entryAllow})
				case le.Scheme == SchemeHTTPS && l.Resolver != "":
					shared = append(shared, le.Line)
				case le.Scheme == SchemeHTTPS:
					w.Entries = append(w.Entries, WebEntry{Entry: le.Entry, Certificate: l.TLS, Allow: entryAllow})
				}
			}
			if len(shared) > 0 {
				w.Shared = append(w.Shared, SharedWebEntry{Listener: ln, Resolver: l.Resolver, Lines: shared, Allow: entryAllow})
			}
		}
		c.Webservers[name] = w
	}
	return nil
}

// HasWebserver tells whether a web server serves anywhere: for /nic/update, of the push sources.
func (c *Config) HasWebserver() bool {
	return len(c.Webservers) > 0
}
