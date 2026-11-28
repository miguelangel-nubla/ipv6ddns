package ddns

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
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
	// It would connect without TLS, and send the password in the clear with nothing checked.
	if service.TLSFingerprint != "" && !service.UseTLS {
		return nil, errors.New("invalid settings: tls_fingerprint needs use_tls: true: without TLS there is no certificate to check")
	}
	return &service, nil
}

// connect logs in to the router. The connection has the deadline of ctx: the RouterOS client
// reads the replies, that of the login too, with none.
func (m *Mikrotik) connect(ctx context.Context) (*routeros.Client, error) {
	var conn net.Conn
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
		conn, err = (&tls.Dialer{Config: tlsConfig}).DialContext(ctx, "tcp", address)
	} else {
		conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", withDefaultPort(m.Address, "8728"))
	}
	if err != nil {
		return nil, err
	}
	// The client reads with no deadline of its own: without this one, a router that says nothing
	// would hold the update.
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			conn.Close()
			return nil, err
		}
	}
	client, err := routeros.NewClient(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if err := client.LoginContext(ctx, m.Username, m.Password); err != nil {
		client.Close()
		return nil, err
	}
	return client, nil
}

// routerOSDuration reads a time as RouterOS prints it: 5m, 1d, 1w2d3h4m5s, and 00:05:00 or
// 1d00:05:00 on some versions.
func routerOSDuration(s string) (time.Duration, bool) {
	var total time.Duration
	if i := strings.IndexByte(s, ':'); i >= 0 {
		// The hh:mm:ss ends it, after the weeks and days.
		start := strings.LastIndexAny(s[:i], "wd") + 1
		var h, m, sec int
		if n, err := fmt.Sscanf(s[start:], "%d:%d:%d", &h, &m, &sec); n != 3 || err != nil {
			return 0, false
		}
		total = time.Duration(h)*time.Hour + time.Duration(m)*time.Minute + time.Duration(sec)*time.Second
		s = s[:start]
	}
	for s != "" {
		digits := 0
		for digits < len(s) && s[digits] >= '0' && s[digits] <= '9' {
			digits++
		}
		n, err := strconv.Atoi(s[:digits])
		if err != nil {
			return 0, false
		}
		s = s[digits:]
		unit := time.Duration(0)
		switch {
		case strings.HasPrefix(s, "ms"):
			unit, s = time.Millisecond, s[2:]
		case strings.HasPrefix(s, "w"):
			unit, s = 7*24*time.Hour, s[1:]
		case strings.HasPrefix(s, "d"):
			unit, s = 24*time.Hour, s[1:]
		case strings.HasPrefix(s, "h"):
			unit, s = time.Hour, s[1:]
		case strings.HasPrefix(s, "m"):
			unit, s = time.Minute, s[1:]
		case strings.HasPrefix(s, "s"):
			unit, s = time.Second, s[1:]
		default:
			return 0, false
		}
		total += time.Duration(n) * unit
	}
	return total, true
}

func (m *Mikrotik) Update(hostname string, addrCollection *ipv6disc.AddrCollection) error {
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()

	client, err := m.connect(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to Mikrotik: %w", err)
	}
	defer client.Close()

	fqdn := FQDN(hostname, m.Zone)

	// Fetch existing records for this hostname. The name is part of a word of the API, which is
	// sent with its length: whatever the name has, it ends no word and starts no other.
	reply, err := client.RunContext(ctx, "/ip/dns/static/print", "?name="+fqdn)
	if err != nil {
		return fmt.Errorf("failed to fetch DNS records: %w", err)
	}

	type dnsRecord struct {
		id  string
		ttl string
	}
	currentIPs := make(map[string]dnsRecord) // IP -> Record
	// The other records of an address that has one: removed, as those of an address not wanted.
	var duplicates []string
	// The addresses of disabled records: the router's, left as they are, and the address has
	// one, so none is added.
	disabledIPs := make(map[string]bool)
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
			if re.Map["disabled"] == "true" {
				disabledIPs[ip] = true
				continue
			}
			if _, duplicate := currentIPs[ip]; duplicate {
				duplicates = append(duplicates, id)
				continue
			}
			currentIPs[ip] = dnsRecord{id: id, ttl: ttl}
		}
	}

	desiredIPs := desiredRecords(addrCollection)

	// Create missing records
	for ip, recordType := range desiredIPs {
		if _, exists := currentIPs[ip]; !exists && !disabledIPs[ip] {
			_, err := client.RunContext(ctx, "/ip/dns/static/add", "=name="+fqdn, "=address="+ip, "=type="+recordType, "=ttl="+m.TTL.String())
			if err != nil {
				return fmt.Errorf("failed to add DNS record %s -> %s: %w", fqdn, ip, err)
			}
		}
	}

	for _, id := range duplicates {
		if _, err := client.RunContext(ctx, "/ip/dns/static/remove", "=.id="+id); err != nil {
			return fmt.Errorf("failed to remove duplicate DNS record %s: %w", fqdn, err)
		}
	}

	// Remove obsolete records
	for ip, record := range currentIPs {
		if _, keep := desiredIPs[ip]; !keep {
			_, err := client.RunContext(ctx, "/ip/dns/static/remove", "=.id="+record.id)
			if err != nil {
				return fmt.Errorf("failed to remove DNS record %s -> %s: %w", fqdn, ip, err)
			}
		} else {
			// Update TTL if needed
			currentTTL, ok := routerOSDuration(record.ttl)
			// If parsing fails we force update to be safe.
			if !ok || currentTTL != m.TTL.Duration {
				_, err := client.RunContext(ctx, "/ip/dns/static/set", "=.id="+record.id, "=ttl="+m.TTL.String())
				if err != nil {
					return fmt.Errorf("failed to update DNS record TTL %s -> %s: %w", fqdn, ip, err)
				}
			}
		}
	}

	return nil
}

func (m *Mikrotik) Domain(hostname string) string {
	return FQDN(hostname, m.Zone)
}
