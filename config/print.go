package config

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/blocklist"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/resolver"
)

// shownSettings are the settings of a credential that tell no secret, in a line: its zone, TTL,
// address, resolver and the count of its records, as the providers' schemas have them; the rest,
// as tokens and passwords, hidden. A setting not known to tell none is hidden.
func shownSettings(raw json.RawMessage) string {
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(raw, &settings); err != nil {
		return hidden
	}
	var shown []string
	rest := false
	for _, key := range slices.Sorted(maps.Keys(settings)) {
		value := settings[key]
		switch key {
		case "records":
			var records []json.RawMessage
			if json.Unmarshal(value, &records) != nil {
				rest = true
				continue
			}
			shown = append(shown, fmt.Sprintf("records %d", len(records)))
		case "resolvers":
			var names []string
			if json.Unmarshal(value, &names) != nil {
				rest = true
				continue
			}
			shown = append(shown, key+" "+strings.Join(names, ", "))
		case "zone", "ttl", "resolver", "region", "site", "proxied", "use_tls", "tsig_algorithm":
			shown = append(shown, key+" "+settingValue(value))
		case "address", "server", "endpoint":
			// A URL can hold a user and a token, and an address over SSH its user: an endpoint is
			// a provider's name for one of its own, as ovh-eu, or a URL.
			address := settingValue(value)
			if u, err := url.Parse(address); err == nil && u.Scheme != "" && u.Host != "" {
				address = u.Scheme + "://" + u.Host
			} else if strings.ContainsAny(address, "@/?") {
				rest = true
				continue
			}
			shown = append(shown, key+" "+address)
		default:
			rest = true
		}
	}
	if rest {
		shown = append(shown, hidden)
	}
	if len(shown) == 0 {
		return "none"
	}
	return strings.Join(shown, ", ")
}

// settingValue is a setting's value as written: a string without its quotes.
func settingValue(value json.RawMessage) string {
	var s string
	if json.Unmarshal(value, &s) == nil {
		return s
	}
	return string(value)
}

// list is a list in a line, or none.
func list(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ", ")
}

// printServers adds to the page the resolvers, the listeners, the web servers, the certificates
// and the Home Assistant device, as written; the state folder, the log level, and the warnings of
// what in the configuration does nothing. hideSensible hides the secrets of the keys, the
// certificates' files, ACME's email, and of its directory all but the scheme and the host.
func (c *Config) printServers(result *strings.Builder, prefix string, hideSensible bool) {
	// The upstream servers, as written, or with the paths of DNS over HTTPS hidden.
	upstreams := func(servers []string) []string {
		if !hideSensible {
			return servers
		}
		shown := resolver.PathsHidden(servers, hidden)
		out := make([]string, len(servers))
		for i, s := range servers {
			out[i] = shown[s]
		}
		return out
	}
	line := func(indent int, format string, args ...any) {
		result.WriteString(prefix + strings.Repeat(" ", indent) + fmt.Sprintf(format, args...) + "\n")
	}
	secret := func(value string) string {
		if hideSensible {
			return hidden
		}
		return value
	}

	if len(c.Resolvers) > 0 {
		line(4, "Resolvers:")
		for _, name := range slices.Sorted(maps.Keys(c.Resolvers)) {
			r := c.Resolvers[name]
			line(8, "%s:", name)
			line(12, "Listeners: %s", list(r.Listeners))
			line(12, "Allow: %s", list(r.Allow))
			// An encrypted server's has no user nor query, which parseEncrypted refuses; its path,
			// which a service can name the account by, as dns.nextdns.io/<id>, is hidden too.
			line(12, "Upstream: %s", list(upstreams(r.Upstream)))
			line(12, "Bootstrap: %s", list(r.Bootstrap))
			if len(r.Forward) > 0 {
				line(12, "Forward:")
				for _, f := range r.Forward {
					line(16, "%s: %s", f.Domain, list(upstreams(f.Upstream)))
				}
			}
			if len(r.Records) > 0 {
				line(12, "Records:")
				for _, record := range r.Records {
					line(16, "%s", record)
				}
			}
			if r.CacheSize != nil {
				line(12, "Cache size: %d", *r.CacheSize)
			}
			if r.ForwardUnknownPrivateReverseQueries {
				line(12, "Forward unknown private reverse queries: true")
			}
			if r.Block != nil {
				line(12, "Block:")
				line(16, "Lists: %s", list(r.Block.Lists))
				line(16, "Allow: %s", list(r.Block.Allow))
				answer := r.Block.Answer
				if answer == "" {
					answer = "nxdomain"
				}
				line(16, "Answer: %s", answer)
				if r.Block.TTL != nil {
					line(16, "TTL: %s", r.Block.TTL.Duration)
				}
			}
			if r.Updates == nil {
				continue
			}
			line(12, "Updates:")
			line(16, "Allow: %s", list(r.Updates.Allow))
			for _, keyName := range slices.Sorted(maps.Keys(r.Updates.Keys)) {
				key := r.Updates.Keys[keyName]
				line(16, "Key %s:", keyName)
				algorithm := key.Algorithm
				if algorithm == "" {
					algorithm = "hmac-sha256"
				}
				line(20, "Algorithm: %s", algorithm)
				line(20, "Allow: %s", list(key.Allow))
				for _, p := range key.Permissions {
					switch p.Kind() {
					case PermissionChallenges:
						line(20, "- challenges: credential %s, names %s", p.Challenges.Credential, list(p.Challenges.Names))
					case PermissionAddresses:
						name := p.Addresses.Name
						if name == "" {
							name = p.Addresses.Source
						}
						line(20, "- addresses: source %s, zone %s, name %s", p.Addresses.Source, p.Addresses.Zone, name)
					default:
						line(20, "- names: zone %s", p.Names.Zone)
					}
				}
				line(20, "Secret: %s", secret(key.Secret))
			}
		}
	}

	if len(c.Blocklists) > 0 {
		line(4, "Blocklists:")
		for _, name := range slices.Sorted(maps.Keys(c.Blocklists)) {
			l := c.Blocklists[name]
			line(8, "%s:", name)
			shown := l.URL
			if hideSensible {
				shown = blocklist.Redacted(shown, hidden)
			}
			line(12, "URL: %s", shown)
			line(12, "Interval: %s", l.IntervalOf().Duration)
		}
	}

	if len(c.Listeners) > 0 {
		line(4, "Listeners:")
		for _, name := range slices.Sorted(maps.Keys(c.Listeners)) {
			l := c.Listeners[name]
			line(8, "%s:", name)
			line(12, "Listen: %s", list(l.Listen))
			if l.TLS != "" {
				line(12, "TLS: %s", l.TLS)
			}
			if l.ServerName != "" {
				line(12, "Server name: %s", l.ServerName)
			}
			line(12, "Allow: %s", list(l.Allow))
		}
	}

	if len(c.Webservers) > 0 {
		line(4, "Webservers:")
		for _, name := range slices.Sorted(maps.Keys(c.Webservers)) {
			web := c.Webservers[name]
			line(8, "%s:", name)
			line(12, "Listeners: %s", list(web.Listeners))
			line(12, "Allow: %s", list(web.Allow))
		}
	}

	if len(c.Certificates) > 0 {
		line(4, "Certificates:")
		for _, name := range slices.Sorted(maps.Keys(c.Certificates)) {
			cert := c.Certificates[name]
			line(8, "%s:", name)
			if cert.Certificate != "" || cert.Key != "" {
				if hideSensible {
					line(12, "Files: %s", hidden)
				} else {
					line(12, "Files: %s, %s", cert.Certificate, cert.Key)
				}
			}
			if cert.ACME != nil {
				line(12, "ACME:")
				line(16, "Names: %s", list(cert.ACME.Names))
				line(16, "Credential: %s", cert.ACME.Credential)
				if cert.ACME.Directory != "" {
					// A URL, which can hold a user and a token.
					directory := cert.ACME.Directory
					if hideSensible {
						directory = hideURL(directory)
					}
					line(16, "Directory: %s", directory)
				}
				if cert.ACME.Email != "" {
					line(16, "Email: %s", secret(cert.ACME.Email))
				}
			}
		}
	}

	if h := c.HomeAssistant; h != nil {
		line(4, "Home Assistant:")
		if h.Name != "" {
			line(8, "Name: %s", h.Name)
		}
		if h.FriendlyName != "" {
			line(8, "Friendly name: %s", h.FriendlyName)
		}
		if h.Port != 0 {
			line(8, "Port: %d", h.Port)
		}
		line(8, "Listen: %s", list(h.Listen))
		if h.Announce != nil {
			line(8, "Announce: %s", strconv.FormatBool(*h.Announce))
		}
		if h.KeyProvisioning {
			line(8, "Key provisioning: true")
			if h.KeyProvisioningStateFile != "" {
				line(8, "Key provisioning state file: %s", h.KeyProvisioningStateFile)
			}
		}
		if h.Key != "" {
			line(8, "Key: %s", secret(h.Key))
		}
	}

	stateDir := c.StateFolder
	if stateDir == "" {
		stateDir = c.StateDir
	}
	if stateDir != "" {
		line(4, "State dir: %s", stateDir)
	}
	logLevel := c.LogLevel
	if logLevel == "" {
		logLevel = "info"
	}
	line(4, "Log level: %s", logLevel)

	if len(c.Warnings) > 0 {
		line(4, "Warnings:")
		for _, warning := range c.Warnings {
			line(8, "- %s", warning)
		}
	}
}
