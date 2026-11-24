package config

import (
	"fmt"
	"strings"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/listen"
)

// Webserver serves the report, /status.json and /metrics.
type Webserver struct {
	// Where: ports, addresses, networks of the machine's addresses and host names, as listen
	// takes them; without a port, 8053. An entry that starts with https:// serves HTTPS there,
	// with the certificate of tls, on port 8443 without one. None: no web server.
	Listen StringList `json:"listen,omitempty"`
	// The certificate of the HTTPS entries: the name of one of certificates. Required with one,
	// and only then.
	TLS string `json:"tls,omitempty"`

	// The entries, read: of HTTP, and of HTTPS.
	Plain, HTTPS []listen.Entry `json:"-"`
}

// The ports of the web server's entries that give none: of HTTP, and of HTTPS.
const (
	DefaultWebserverPort      = "8053"
	DefaultWebserverHTTPSPort = "8443"
)

// setUpWebserver reads the entries, HTTP and HTTPS, and checks the certificate of the HTTPS ones.
func (c *Config) setUpWebserver() error {
	c.Webserver.Plain, c.Webserver.HTTPS = nil, nil
	for _, line := range c.Webserver.Listen {
		text := strings.TrimSpace(line)
		if after, ok := cutScheme(text, "https://"); ok {
			entries, err := listen.Parse([]string{after}, DefaultWebserverHTTPSPort)
			if err != nil {
				return fmt.Errorf("webserver.listen: %w", err)
			}
			c.Webserver.HTTPS = append(c.Webserver.HTTPS, entries...)
			continue
		}
		entries, err := listen.Parse([]string{text}, DefaultWebserverPort)
		if err != nil {
			return fmt.Errorf("webserver.listen: %w", err)
		}
		c.Webserver.Plain = append(c.Webserver.Plain, entries...)
	}
	return c.useCertificate("webserver", c.Webserver.TLS, len(c.Webserver.HTTPS) > 0)
}

// cutScheme is the entry after its scheme, if it has it, whatever its letters' case.
func cutScheme(entry, scheme string) (string, bool) {
	if len(entry) >= len(scheme) && strings.EqualFold(entry[:len(scheme)], scheme) {
		return entry[len(scheme):], true
	}
	return "", false
}
