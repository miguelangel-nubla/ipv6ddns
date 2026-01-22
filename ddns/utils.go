package ddns

import (
	"strings"
)

// FQDN returns a fully qualified domain name given a hostname and a zone.
func FQDN(hostname, zone string) string {
	hostname = strings.Trim(hostname, ".")
	zone = strings.Trim(zone, ".")

	if hostname == "" {
		return zone
	}

	if zone != "" && strings.HasSuffix(hostname, zone) {
		return hostname
	}

	if zone == "" {
		return hostname
	}

	return strings.Join([]string{hostname, zone}, ".")
}

// SplitFQDN splits a fully qualified domain name into hostname and domain parts.
func SplitFQDN(fqdn string) (string, string) {
	fqdn = strings.Trim(fqdn, ".")

	parts := strings.SplitN(fqdn, ".", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}

	return fqdn, ""
}
