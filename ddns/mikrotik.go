package ddns

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/go-routeros/routeros/v3"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/duration"
	"github.com/miguelangel-nubla/ipv6disc"
)

type Mikrotik struct {
	Address        string            `json:"address"`
	UseTLS         bool              `json:"use_tls"`
	TLSFingerprint string            `json:"tls_fingerprint"`
	Username       string            `json:"username"`
	Password       string            `json:"password"`
	Zone           string            `json:"zone"`
	TTL            duration.Duration `json:"ttl"`
}

func init() {
	RegisterProvider("mikrotik", NewMikrotik)
}

func NewMikrotik(settings json.RawMessage) (Service, error) {
	var service Mikrotik
	if err := decodeSettings(settings, "mikrotik", &service); err != nil {
		return nil, err
	}
	return &service, nil
}

func (m *Mikrotik) Update(hostname string, addrCollection *ipv6disc.AddrCollection) error {
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()

	var client *routeros.Client
	var err error
	if m.UseTLS {
		address := withDefaultPort(m.Address, "8729")
		// A fingerprint pins the certificate. Without one the system must trust it, and the
		// error tells its fingerprint.
		tlsConfig := pinnedTLSConfig(m.TLSFingerprint)
		if m.TLSFingerprint == "" {
			host, _, _ := net.SplitHostPort(address)
			tlsConfig = verifiedOrPinnedTLSConfig(host, "")
		}
		client, err = routeros.DialTLSContext(ctx, address, m.Username, m.Password, tlsConfig)
	} else {
		client, err = routeros.DialContext(ctx, withDefaultPort(m.Address, "8728"), m.Username, m.Password)
	}
	if err != nil {
		return fmt.Errorf("failed to connect to Mikrotik: %w", err)
	}
	defer client.Close()

	fqdn := FQDN(hostname, m.Zone)

	// Fetch existing records for this hostname
	reply, err := client.RunContext(ctx, "/ip/dns/static/print", "?name="+fqdn)
	if err != nil {
		return fmt.Errorf("failed to fetch DNS records: %v", err)
	}

	type dnsRecord struct {
		id  string
		ttl string
	}
	currentIPs := make(map[string]dnsRecord) // IP -> Record
	for _, re := range reply.Re {
		id := re.Map[".id"]
		addr := re.Map["address"]
		recordType := re.Map["type"]
		ttl := re.Map["ttl"]

		// Only A and AAAA records. RouterOS can leave out the type of an A record, its default.
		if recordType != "" && recordType != "A" && recordType != "AAAA" {
			continue
		}

		if ip, ok := canonicalIP(addr); ok {
			currentIPs[ip] = dnsRecord{id: id, ttl: ttl}
		}
	}

	desiredIPs := desiredRecords(addrCollection)

	// Create missing records
	for ip, recordType := range desiredIPs {
		if _, exists := currentIPs[ip]; !exists {
			_, err := client.RunContext(ctx, "/ip/dns/static/add", "=name="+fqdn, "=address="+ip, "=type="+recordType, "=ttl="+m.TTL.String())
			if err != nil {
				return fmt.Errorf("failed to add DNS record %s -> %s: %w", fqdn, ip, err)
			}
		}
	}

	// Remove obsolete records
	for ip, record := range currentIPs {
		if _, keep := desiredIPs[ip]; !keep {
			_, err := client.RunContext(ctx, "/ip/dns/static/remove", "=.id="+record.id)
			if err != nil {
				return fmt.Errorf("failed to remove DNS record %s -> %s: %v", fqdn, ip, err)
			}
		} else {
			// Update TTL if needed
			currentTTL, err := time.ParseDuration(record.ttl)
			// If parsing fails we force update to be safe.
			if err != nil || currentTTL != m.TTL.Duration {
				_, err := client.RunContext(ctx, "/ip/dns/static/set", "=.id="+record.id, "=ttl="+m.TTL.String())
				if err != nil {
					return fmt.Errorf("failed to update DNS record TTL %s -> %s: %v", fqdn, ip, err)
				}
			}
		}
	}

	return nil
}

func (m *Mikrotik) Domain(hostname string) string {
	return FQDN(hostname, m.Zone)
}
