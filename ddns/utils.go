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

	if zone != "" && inZone(hostname, zone) {
		return hostname
	}

	if zone == "" {
		return hostname
	}

	return strings.Join([]string{hostname, zone}, ".")
}

// inZone tells whether name is zone or a name of it, whatever the case of their ASCII letters:
// DNS tells none of those apart, and every other byte it compares as it is.
func inZone(name, zone string) bool {
	name, zone = lowerASCII(name), lowerASCII(zone)
	return name == zone || strings.HasSuffix(name, "."+zone)
}

// lowerASCII is s with its ASCII letters in lower case, and every other byte as it was. Not
// strings.ToLower, which makes one same character of every byte that is no UTF-8, so that two
// names that differ would be the same.
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// RelativeName returns the name of hostname within zone, for the providers that take it so: "" for
// the zone itself. As FQDN, it takes a hostname given with its zone.
func RelativeName(hostname, zone string) string {
	fqdn := FQDN(hostname, zone)
	zone = strings.Trim(zone, ".")
	if zone == "" {
		return fqdn
	}
	if len(fqdn) == len(zone) {
		return ""
	}
	return fqdn[:len(fqdn)-len(zone)-1]
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
