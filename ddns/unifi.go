package ddns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/duration"
	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/miguelangel-nubla/ipv6disc/pkg/unifi"
)

// UniFi keeps the addresses of a name as local DNS records of a UniFi gateway, its "DNS
// Records", through the UniFi Network API: of a UniFi OS console or UniFi OS Server, with an API
// key or a user, or of a self-hosted Network Application, with a user. A record is a name and one
// address: a name with several addresses has one record for each.
type UniFi struct {
	Address        string            `json:"address"`
	TLSFingerprint string            `json:"tls_fingerprint"`
	APIKey         string            `json:"api_key"`
	Username       string            `json:"username"`
	Password       string            `json:"password"`
	Site           string            `json:"site"`
	Zone           string            `json:"zone"`
	TTL            duration.Duration `json:"ttl"`

	// The client of the Network API, which keeps a user's session between updates.
	client *unifi.Client
}

// unifiMaxTTL is the longest TTL the Network API takes for an A or AAAA record.
const unifiMaxTTL = 24 * time.Hour

func init() {
	RegisterProvider("unifi", NewUniFi)
}

func NewUniFi(settings json.RawMessage) (Service, error) {
	var service UniFi
	if err := decodeSettings(settings, "unifi", &service); err != nil {
		return nil, err
	}
	if err := fingerprintNeedsTLS(service.Address, service.TLSFingerprint); err != nil {
		return nil, err
	}
	if service.TTL.Duration > unifiMaxTTL {
		return nil, fmt.Errorf("ttl: %s is longer than UniFi takes, %s", service.TTL.Duration, unifiMaxTTL)
	}
	client, err := unifi.New(unifi.Config{
		Address: service.Address, APIKey: service.APIKey, Username: service.Username, Password: service.Password, Site: service.Site,
	}, serverTLSConfig(urlHost(service.Address), service.TLSFingerprint), httpTimeout)
	if err != nil {
		return nil, err
	}
	service.client, service.Site = client, client.Site()
	return &service, nil
}

// unifiRecord is a local DNS record as the Network API has it. Other fields, as the priority of
// an SRV record, are left out: the API takes a record without them.
type unifiRecord struct {
	ID         string `json:"_id,omitempty"`
	Enabled    bool   `json:"enabled"`
	Key        string `json:"key"`
	RecordType string `json:"record_type"`
	Value      string `json:"value"`
	TTL        int    `json:"ttl"`
}

func (u *UniFi) Update(hostname string, addrCollection *ipv6disc.AddrCollection) error {
	fqdn := u.Domain(hostname)
	ttl := int(u.TTL.Seconds())

	var records []unifiRecord
	if err := u.call(http.MethodGet, "", nil, &records); err != nil {
		return fmt.Errorf("failed to list the DNS records: %w", err)
	}

	desired := desiredRecords(addrCollection)

	// The A and AAAA records of the name, by their address. One of another type, as a CNAME, is
	// the user's own, and so is a disabled one: its address stays as it is, and gets no record
	// beside it.
	current := make(map[string][]unifiRecord)
	disabled := make(map[string]bool)
	for _, record := range records {
		if lowerASCII(strings.Trim(record.Key, ".")) != fqdn || (record.RecordType != "A" && record.RecordType != "AAAA") {
			continue
		}
		ip, ok := canonicalIP(record.Value)
		if !ok {
			continue
		}
		if !record.Enabled {
			disabled[ip] = true
			continue
		}
		current[ip] = append(current[ip], record)
	}

	for ip, entries := range current {
		rtype, wanted := desired[ip]
		if wanted && len(entries) == 1 && entries[0].RecordType == rtype {
			if entries[0].TTL != ttl {
				fixed := entries[0]
				fixed.TTL = ttl
				if err := u.call(http.MethodPut, "/"+url.PathEscape(fixed.ID), fixed, nil); err != nil {
					return fmt.Errorf("failed to set the TTL of the record of %s to %s: %w", fqdn, ip, err)
				}
			}
			continue
		}
		for _, entry := range entries {
			if err := u.call(http.MethodDelete, "/"+url.PathEscape(entry.ID), nil, nil); err != nil {
				return fmt.Errorf("failed to delete the record of %s to %s: %w", fqdn, ip, err)
			}
		}
		// Of an address the name keeps, said more than once: it is added again, once.
		delete(current, ip)
	}

	for ip, rtype := range desired {
		if _, exists := current[ip]; exists || disabled[ip] {
			continue
		}
		record := unifiRecord{Enabled: true, Key: fqdn, RecordType: rtype, Value: ip, TTL: ttl}
		if err := u.call(http.MethodPost, "", record, nil); err != nil {
			return fmt.Errorf("failed to add the record of %s to %s: %w", fqdn, ip, err)
		}
	}
	return nil
}

// call asks the site's DNS records, at the path under them, with body when there is one, and
// reads the answer into out when there is where to. Not there at all, they may be of a UniFi
// Network too old to have them.
func (u *UniFi) call(method, path string, body, out any) error {
	err := u.client.Call(context.Background(), method, "/static-dns"+path, body, out)
	var refused *unifi.Error
	if errors.As(err, &refused) && refused.Status == http.StatusNotFound {
		return fmt.Errorf("%w, or the UniFi Network is older than 8.2.93, the first with DNS records", err)
	}
	return err
}

// Domain is the name as UniFi keeps it: in lower case, without the final dot.
func (u *UniFi) Domain(hostname string) string {
	return lowerASCII(FQDN(hostname, u.Zone))
}
