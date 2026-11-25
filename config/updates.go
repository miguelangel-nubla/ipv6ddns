package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/miekg/dns"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/resolver"
)

// Updates are the dynamic updates a resolver takes, by RFC 2136: of the clients that hold one of
// the keys, each within its permissions. See docs/resolver.md.
type Updates struct {
	// The networks or addresses the keys may send from, of those that give none. Default: the
	// resolver's allow.
	Allow StringList `json:"allow,omitempty"`
	// Required. The TSIG keys, by their names, as the clients give them.
	Keys map[string]UpdateKey `json:"keys,omitempty"`
}

// UpdateKey is a TSIG key, and what its holder may change.
type UpdateKey struct {
	// Required. Base64, as tsig-keygen writes it.
	Secret string `json:"secret,omitempty"`
	// hmac-sha256, hmac-sha384 or hmac-sha512. Default: hmac-sha256.
	Algorithm string `json:"algorithm,omitempty"`
	// The networks or addresses it may send from. Default: the updates' allow.
	Allow StringList `json:"allow,omitempty"`
	// Required. What it may change: each one of the kinds.
	Permissions []Permission `json:"permissions,omitempty"`

	// The key, checked, without its grants, which the worker makes of the permissions.
	Spec resolver.UpdateKey `json:"-"`
}

// Permission is one thing a key may change: one of its fields, set.
type Permission struct {
	Challenges *ChallengesPermission `json:"challenges,omitempty"`
	Addresses  *AddressesPermission  `json:"addresses,omitempty"`
	Names      *NamesPermission      `json:"names,omitempty"`
}

// The kinds of permission, as the configuration writes them.
const (
	PermissionChallenges = "challenges"
	PermissionAddresses  = "addresses"
	PermissionNames      = "names"
)

// Kind is the kind of the permission: the one field set.
func (p Permission) Kind() string {
	switch {
	case p.Challenges != nil:
		return PermissionChallenges
	case p.Addresses != nil:
		return PermissionAddresses
	default:
		return PermissionNames
	}
}

// ChallengesPermission is the TXT records of the DNS challenge of ACME, of some names, written
// through a credential: what certbot, lego and acme.sh change, to get a certificate.
type ChallengesPermission struct {
	// Required. The credential of the public zone of the names, which writes the records.
	Credential string `json:"credential,omitempty"`
	// Required. The names of the certificates, relative to the zone of the credential, as acme's:
	// nas.lan, or *.apps.
	Names StringList `json:"names,omitempty"`
}

// AddressesPermission is the addresses of a push source, sent as the A and AAAA records of a
// name: what a host updating its own address with nsupdate changes.
type AddressesPermission struct {
	// Required. The push source the addresses go to.
	Source string `json:"source,omitempty"`
	// Required. The zone of the name, which the client gives its updates.
	Zone string `json:"zone,omitempty"`
	// The name the client updates, relative to the zone. Default: the source's name.
	Name string `json:"name,omitempty"`
}

// NamesPermission is the names of the hosts of a zone, sent with their addresses: what a DHCP
// server's dynamic DNS changes.
type NamesPermission struct {
	// Required. The zone of the names, as the DHCP server gives it.
	Zone string `json:"zone,omitempty"`
}

// The algorithms of a key, as the configuration writes them, and as TSIG names them.
var updateAlgorithms = map[string]string{
	"hmac-sha256": dns.HmacSHA256,
	"hmac-sha384": dns.HmacSHA384,
	"hmac-sha512": dns.HmacSHA512,
}

// minSecret is the shortest secret a key may have, in bytes: half of what tsig-keygen makes for
// hmac-sha256, which RFC 8945 asks at the least.
const minSecret = 16

// claims are what the keys of every resolver may change, to tell two keys that would change the
// same: by what, the key's path and the permission's. One key may claim a name twice, as a
// certificate's name and its wildcard, which share a challenge.
type claims map[string][2]string

func (cl claims) claim(what, key, path string) error {
	if other, ok := cl[what]; ok && other[0] != key {
		return fmt.Errorf("%s: %s is %s's already: a name can be changed by one key alone", path, strings.SplitN(what, " ", 2)[1], other[1])
	}
	if _, ok := cl[what]; !ok {
		cl[what] = [2]string{key, path}
	}
	return nil
}

// setUpUpdates checks the updates of a resolver, and sets their specs: once the certificates and
// the sources are read.
func (c *Config) setUpUpdates(path string, r *Resolver, spec *resolver.Config, all claims) error {
	u := r.Updates
	if u == nil {
		return nil
	}
	path += ".updates"
	if len(spec.Listen) == 0 && !slices.ContainsFunc(spec.Encrypted, func(e resolver.EncryptedListen) bool { return e.Transport == resolver.TransportTLS }) {
		return fmt.Errorf("%s: updates come over plain DNS or DNS over TLS, and the resolver listens on neither: add an entry of listen without a scheme, as 192.168.1.0/24", path)
	}
	if len(u.Keys) == 0 {
		return fmt.Errorf("%s.keys is missing: give the TSIG keys that may send updates, each with its secret and its permissions", path)
	}
	for _, a := range u.Allow {
		p, err := parseNetwork(a)
		if err != nil {
			return fmt.Errorf("%s.allow: %w", path, err)
		}
		spec.UpdateAllow = append(spec.UpdateAllow, p)
	}
	for _, name := range slices.Sorted(maps.Keys(u.Keys)) {
		k := u.Keys[name]
		keyPath := path + ".keys." + name
		if !resolver.KeyName(strings.ToLower(dns.Fqdn(name))) {
			return fmt.Errorf("%s: %q is not a name a TSIG key can have: letters, digits, hyphens and underscores, in labels separated by dots, as nas or nas.lan", path+".keys", name)
		}
		key := resolver.UpdateKey{Name: name}
		switch secret, err := base64.StdEncoding.DecodeString(k.Secret); {
		case k.Secret == "":
			return fmt.Errorf("%s.secret is missing: give the key's secret, in base64, as tsig-keygen writes it: tsig-keygen -a hmac-sha256 %s", keyPath, name)
		case err != nil:
			return fmt.Errorf("%s.secret is not base64, as tsig-keygen writes it", keyPath)
		case len(secret) < minSecret:
			return fmt.Errorf("%s.secret has %d bytes, and must have %d at least: tsig-keygen makes one of 32", keyPath, len(secret), minSecret)
		}
		key.Secret = k.Secret
		algorithm := strings.ToLower(strings.TrimSuffix(k.Algorithm, "."))
		if algorithm == "" {
			algorithm = "hmac-sha256"
		}
		var ok bool
		if key.Algorithm, ok = updateAlgorithms[algorithm]; !ok {
			return fmt.Errorf("%s.algorithm: %s isn't one a key may have: hmac-sha256, hmac-sha384 or hmac-sha512", keyPath, k.Algorithm)
		}
		for _, a := range k.Allow {
			p, err := parseNetwork(a)
			if err != nil {
				return fmt.Errorf("%s.allow: %w", keyPath, err)
			}
			key.Allow = append(key.Allow, p)
		}
		if len(k.Permissions) == 0 {
			return fmt.Errorf("%s.permissions is missing: give what the key may change: challenges, addresses or names", keyPath)
		}
		for i, p := range k.Permissions {
			if err := c.checkPermission(keyPath, fmt.Sprintf("%s.permissions[%d]", keyPath, i), p, all); err != nil {
				return err
			}
		}
		k.Spec = key
		u.Keys[name] = k
	}
	return nil
}

// checkPermission checks a permission, and claims what it may change.
func (c *Config) checkPermission(key, path string, p Permission, all claims) error {
	set := 0
	for _, s := range []bool{p.Challenges != nil, p.Addresses != nil, p.Names != nil} {
		if s {
			set++
		}
	}
	if set != 1 {
		return fmt.Errorf("%s: give one of challenges, addresses and names, each a permission of its own", path)
	}
	switch {
	case p.Challenges != nil:
		ch := p.Challenges
		path += ".challenges"
		credential, ok := c.Credentials[ch.Credential]
		switch {
		case ch.Credential == "":
			return fmt.Errorf("%s.credential is missing: give the credential of the public zone of the names, which writes the TXT records", path)
		case !ok:
			return fmt.Errorf("%s.credential: there is no credential %s", path, ch.Credential)
		case credential.Provider == ResolverProvider:
			return fmt.Errorf("%s.credential: %s is a zone of the resolver, which the authority can't ask: give the credential of the public zone of the names", path, ch.Credential)
		case len(ch.Names) == 0:
			return fmt.Errorf("%s.names is missing: give the names of the certificates, relative to the zone of the credential, as nas.lan or *.apps", path)
		}
		zone := settingsZone(credential.RawSettings)
		for _, n := range ch.Names {
			base, ok := challengeBase(n)
			if !ok {
				return fmt.Errorf("%s.names: %q is not a name: a wildcard is only its first label, as *.apps", path, n)
			}
			full := challengeName(ch.Credential, zone, base)
			if cert := c.acmeChallenge(ch.Credential, zone, full); cert != "" {
				return fmt.Errorf("%s.names: %s is a name of certificates.%s, whose challenge ipv6ddns writes itself", path, n, cert)
			}
			if err := all.claim("challenge "+full, key, path+".names"); err != nil {
				return err
			}
		}
		return nil
	case p.Addresses != nil:
		a := p.Addresses
		path += ".addresses"
		source, ok := c.Sources[a.Source]
		switch {
		case a.Source == "":
			return fmt.Errorf("%s.source is missing: give the push source the addresses go to", path)
		case !ok:
			return fmt.Errorf("%s.source: there is no source %s: add it under sources, with type: push", path, a.Source)
		case source.Type != SourcePush:
			return fmt.Errorf("%s.source: %s is a source of type %s: the addresses sent go to a source of type push", path, a.Source, source.Type)
		case strings.Trim(a.Zone, ".") == "":
			return fmt.Errorf("%s.zone is missing: give the zone of the name the client updates, as example.com", path)
		}
		name := a.Name
		if name == "" {
			name = a.Source
		}
		full := resolver.Name(name, a.Zone)
		if _, ok := dns.IsDomainName(full); !ok || strings.ContainsAny(full, " *") {
			return fmt.Errorf("%s.name: %q is not a name", path, name)
		}
		return all.claim("addresses "+strings.TrimSuffix(full, "."), key, path)
	default:
		n := p.Names
		path += ".names"
		zone := strings.Trim(n.Zone, ".")
		if zone == "" {
			return fmt.Errorf("%s.zone is missing: give the zone of the names, as the DHCP server gives it, as lan.example.com", path)
		}
		if _, ok := dns.IsDomainName(zone); !ok || strings.ContainsAny(zone, " *") {
			return fmt.Errorf("%s.zone: %q is not a zone", path, n.Zone)
		}
		return all.claim("names "+strings.ToLower(zone), key, path)
	}
}

// acmeChallenge is the certificate of ipv6ddns's own, of the credential, one of whose names has
// the challenge full: none, for none.
func (c *Config) acmeChallenge(credential, zone, full string) string {
	for _, cert := range slices.Sorted(maps.Keys(c.Certificates)) {
		a := c.Certificates[cert].ACME
		if a == nil || a.Credential != credential {
			continue
		}
		for _, n := range a.Names {
			if base, ok := challengeBase(n); ok && challengeName(credential, zone, base) == full {
				return cert
			}
		}
	}
	return ""
}

// challengeBase is the name a certificate's challenge is of: the name, or a wildcard's parent,
// in lower case.
func challengeBase(name string) (string, bool) {
	base := strings.ToLower(strings.Trim(name, "."))
	base = strings.TrimPrefix(base, "*.")
	if base == "" || strings.ContainsAny(base, "* ") {
		return "", false
	}
	if _, ok := dns.IsDomainName(base); !ok {
		return "", false
	}
	return base, true
}

// challengeName is how the configuration tells the challenge of a name of a credential's: its
// full name, by the zone of the settings when they have one; and of the credential, when not.
func challengeName(credential, zone, base string) string {
	if zone == "" {
		return credential + ": " + base
	}
	return strings.TrimSuffix(resolver.Name(base, zone), ".")
}

// settingsZone is the zone of a credential's settings, when they say one.
func settingsZone(raw json.RawMessage) string {
	var s struct {
		Zone string `json:"zone"`
	}
	_ = json.Unmarshal(raw, &s)
	return s.Zone
}
