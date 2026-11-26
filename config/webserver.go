package config

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/listen"
)

// Webserver is a web server, of the report, /status.json and /metrics, and of /nic/update for the
// push sources: one of webservers, by its name.
type Webserver struct {
	// Where: ports, addresses, networks of the machine's addresses and host names, as listen
	// takes them; without a port, 8053. An entry that starts with https:// serves HTTPS there,
	// with the certificate of tls, on port 8443 without one.
	Listen StringList `json:"listen,omitempty"`
	// The certificate of the HTTPS entries: the name of one of certificates. Required with one,
	// and only then.
	TLS string `json:"tls,omitempty"`
	// The clients it answers; any other gets 403. Default: everyone on its listen, and each
	// listener's allow on that listener's entries, which this replaces.
	Allow StringList `json:"allow,omitempty"`
	// The listeners it serves on too, by name: their HTTP entries, and every path but /dns-query
	// of their HTTPS ones.
	Listeners StringList `json:"listeners,omitempty"`

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

// The ports of the web server's entries that give none: of HTTP, and of HTTPS.
const (
	DefaultWebserverPort      = "8053"
	DefaultWebserverHTTPSPort = "8443"
)

// checkWebserverRenamed tells, of a configuration not yet checked by the schema, that webserver
// is named now, under webservers, with its block as it was.
func checkWebserverRenamed(configData []byte) error {
	var c map[string]json.RawMessage
	if json.Unmarshal(configData, &c) != nil {
		return nil
	}
	if _, ok := c["webserver"]; ok {
		return fmt.Errorf("webserver is now webservers, each web server by a name of your choice: indent the block under one, as\n\nwebservers:\n  main:\n    listen:\n      - 8053")
	}
	return nil
}

// setUpWebservers reads the web servers' entries, HTTP and HTTPS, and their listeners', and checks
// the certificates of the HTTPS ones.
func (c *Config) setUpWebservers() error {
	for _, name := range slices.Sorted(maps.Keys(c.Webservers)) {
		w := c.Webservers[name]
		w.Path = "webservers." + name
		w.Entries, w.Shared = nil, nil
		if len(w.Listen) == 0 && len(w.Listeners) == 0 {
			return fmt.Errorf("%s.listen is missing: give where it serves, as 8053", w.Path)
		}
		var allow []netip.Prefix
		for _, a := range w.Allow {
			p, err := parseNetwork(a)
			if err != nil {
				return fmt.Errorf("%s.allow: %w", w.Path, err)
			}
			allow = append(allow, p)
		}
		https := false
		for _, line := range w.Listen {
			text := strings.TrimSpace(line)
			port, certificate := DefaultWebserverPort, ""
			if after, ok := cutScheme(text, "https://"); ok {
				text, port, certificate, https = after, DefaultWebserverHTTPSPort, w.TLS, true
			}
			entries, err := listen.Parse([]string{text}, port)
			if err != nil {
				return fmt.Errorf("%s.listen: %w", w.Path, err)
			}
			for _, e := range entries {
				w.Entries = append(w.Entries, WebEntry{Entry: e, Certificate: certificate, Allow: allow})
			}
		}
		if err := c.useCertificate(w.Path, w.TLS, https, "https://", "https://192.168.1.2"); err != nil {
			return err
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

// cutScheme is the entry after its scheme, if it has it, whatever its letters' case.
func cutScheme(entry, scheme string) (string, bool) {
	if len(entry) >= len(scheme) && strings.EqualFold(entry[:len(scheme)], scheme) {
		return entry[len(scheme):], true
	}
	return "", false
}
