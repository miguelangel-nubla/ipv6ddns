package config

import (
	"fmt"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/listen"
)

// Webserver serves the report, /status.json and /metrics.
type Webserver struct {
	// Where: ports, addresses, networks of the machine's addresses and host names, as listen
	// takes them; without a port, 8053. None: no web server.
	Listen StringList `json:"listen,omitempty"`
}

// DefaultWebserverPort is the port of the web server's entries that give none.
const DefaultWebserverPort = "8053"

// setUpWebserver checks the entries.
func (c *Config) setUpWebserver() error {
	if _, err := listen.Parse(c.Webserver.Listen, DefaultWebserverPort); err != nil {
		return fmt.Errorf("webserver.listen: %w", err)
	}
	return nil
}
