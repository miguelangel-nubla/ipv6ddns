package config

import (
	"fmt"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/listen"
)

// Webserver serves the report, /status.json and /metrics.
type Webserver struct {
	// Where: ports, addresses, networks of the machine's addresses and host names, as listen
	// takes them; without a port, 80. None: no web server. The -webserver_listen flag, given,
	// wins.
	Listen StringList `json:"listen,omitempty"`
}

// DefaultWebserverPort is the port of the web server's entries that give none.
const DefaultWebserverPort = "80"

// setUpWebserver takes the deprecated webserver_listen, and checks the entries.
func (c *Config) setUpWebserver() ([]string, error) {
	var warnings []string
	if len(c.WebserverListen) > 0 {
		if len(c.Webserver.Listen) > 0 {
			return nil, fmt.Errorf("webserver_listen is the deprecated form of webserver.listen: give one of them")
		}
		c.Webserver.Listen, c.WebserverListen = c.WebserverListen, nil
		warnings = append(warnings, "webserver_listen is deprecated, and goes in v1.0: it is webserver.listen")
	}
	if _, err := listen.Parse(c.Webserver.Listen, DefaultWebserverPort); err != nil {
		return nil, fmt.Errorf("webserver.listen: %w", err)
	}
	return warnings, nil
}
