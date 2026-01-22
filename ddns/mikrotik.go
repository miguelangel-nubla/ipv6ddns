package ddns

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/go-routeros/routeros/v3"
	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/xeipuuv/gojsonschema"
)

type Mikrotik struct {
	Address        string        `json:"address"`
	Username       string        `json:"username"`
	Password       string        `json:"password"`
	Zone           string        `json:"zone"`
	TTL            time.Duration `json:"ttl"`
	UseTLS         bool          `json:"use_tls"`
	TLSFingerprint string        `json:"tls_fingerprint"`
}

func init() {
	RegisterProvider("mikrotik", NewMikrotik)
}

func NewMikrotik(settings ProviderSettings) Service {
	var service Mikrotik
	mikrotikValidateConfig(settings.(json.RawMessage))
	json.Unmarshal(settings.(json.RawMessage), &service)
	return &service
}

func mikrotikValidateConfig(config json.RawMessage) {
	var configSchema = []byte(`
	{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "object",
		"properties": {
			"address": {
				"type": "string",
				"minLength": 1
			},
			"username": {
				"type": "string",
				"minLength": 1
			},
			"password": {
				"type": "string"
			},
			"zone": {
				"type": "string"
			},
			"ttl": {
				"type": "string",
				"pattern": "^([0-9]+(\\.[0-9]+)?(ns|us|µs|ms|s|m|h))+$"
			},
			"use_tls": {
				"type": "boolean"
			},
			"tls_fingerprint": {
				"type": "string",
				"pattern": "^[a-fA-F0-9]{64}$"
			}
		},
		"required": [
			"address",
			"username",
			"password",
			"ttl"
		]
	}
	`)

	schemaLoader := gojsonschema.NewBytesLoader(configSchema)
	dataLoader := gojsonschema.NewBytesLoader([]byte(config))

	result, err := gojsonschema.Validate(schemaLoader, dataLoader)
	if err != nil {
		panic(err.Error())
	}

	if !result.Valid() {
		fmt.Printf("Mikrotik configuration is not valid.\nErrors:\n")
		for _, desc := range result.Errors() {
			fmt.Printf("- %s\n", desc)
		}
		os.Exit(1)
	}
}

func (m *Mikrotik) Update(hostname string, addrCollection *ipv6disc.AddrCollection) error {
	var client *routeros.Client
	var err error

	if m.UseTLS {
		tlsConfig := &tls.Config{}
		if m.TLSFingerprint != "" {
			tlsConfig.InsecureSkipVerify = true
			tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
				for _, cert := range cs.PeerCertificates {
					hash := sha256.Sum256(cert.Raw)
					if hex.EncodeToString(hash[:]) == m.TLSFingerprint {
						return nil
					}
				}
				return fmt.Errorf("certificate fingerprint mismatch")
			}
		}
		client, err = routeros.DialTLS(m.Address, m.Username, m.Password, tlsConfig)
	} else {
		client, err = routeros.Dial(m.Address, m.Username, m.Password)
	}

	if err != nil {
		return fmt.Errorf("failed to connect to Mikrotik: %v", err)
	}
	defer client.Close()

	fqdn := FQDN(hostname, m.Zone)

	// Fetch existing records for this hostname
	reply, err := client.Run("/ip/dns/static/print", "?name="+fqdn)
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

		// Filter only A and AAAA records
		if recordType != "A" && recordType != "AAAA" {
			continue
		}

		if _, err := netip.ParseAddr(addr); err == nil {
			currentIPs[addr] = dnsRecord{id: id, ttl: ttl}
		}
	}

	desiredIPs := make(map[string]bool)
	for _, addr := range addrCollection.Get() {
		ip := addr.WithZone("").String()
		desiredIPs[ip] = true
	}

	// Create missing records
	for ip := range desiredIPs {
		if _, exists := currentIPs[ip]; !exists {
			// Determine type
			recordType := "A"
			if addr, err := netip.ParseAddr(ip); err == nil && addr.Is6() {
				recordType = "AAAA"
			}

			_, err := client.Run("/ip/dns/static/add", "=name="+fqdn, "=address="+ip, "=type="+recordType, "=ttl="+m.TTL.String())
			if err != nil {
				return fmt.Errorf("failed to add DNS record %s -> %s: %v", fqdn, ip, err)
			}
		}
	}

	// Remove obsolete records
	for ip, record := range currentIPs {
		if _, keep := desiredIPs[ip]; !keep {
			_, err := client.Run("/ip/dns/static/remove", "=.id="+record.id)
			if err != nil {
				return fmt.Errorf("failed to remove DNS record %s -> %s: %v", fqdn, ip, err)
			}
		} else {
			// Update TTL if needed
			currentTTL, err := time.ParseDuration(record.ttl)
			// If parsing fails we force update to be safe.
			if err != nil || currentTTL != m.TTL {
				_, err := client.Run("/ip/dns/static/set", "=.id="+record.id, "=ttl="+m.TTL.String())
				if err != nil {
					return fmt.Errorf("failed to update DNS record TTL %s -> %s: %v", fqdn, ip, err)
				}
			}
		}
	}

	return nil
}

func (m *Mikrotik) PrettyPrint(prefix string) ([]byte, error) {
	return json.MarshalIndent(m, prefix, "    ")
}

func (m *Mikrotik) UnmarshalJSON(b []byte) error {
	type Alias Mikrotik
	aux := &struct {
		TTL interface{} `json:"ttl"`
		*Alias
	}{
		Alias: (*Alias)(m),
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}

	switch value := aux.TTL.(type) {
	case float64:
		m.TTL = time.Duration(value) * time.Second
		return nil
	case string:
		var err error
		m.TTL, err = time.ParseDuration(value)
		if err != nil {
			return err
		}
		return nil
	default:
		return errors.New("ttl invalid duration")
	}
}

func (m *Mikrotik) MarshalJSON() ([]byte, error) {
	type Alias Mikrotik
	return json.Marshal(&struct {
		TTL int64 `json:"ttl"`
		*Alias
	}{
		TTL:   int64(m.TTL.Seconds()),
		Alias: (*Alias)(m),
	})
}

func (m *Mikrotik) Domain(hostname string) string {
	return FQDN(hostname, m.Zone)
}
