package ddns

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/duration"
	"github.com/miguelangel-nubla/ipv6disc"
)

type OpenWrt struct {
	Address  string            `json:"address"`
	Username string            `json:"username"`
	Password string            `json:"password"`
	SSHKey   string            `json:"ssh_key"`
	Zone     string            `json:"zone"`
	TTL      duration.Duration `json:"ttl"`
}

func init() {
	RegisterProvider("openwrt", NewOpenWrt)
}

func NewOpenWrt(settings json.RawMessage) (Service, error) {
	var service OpenWrt
	if err := decodeSettings(settings, openwrtSettingsSchema, &service); err != nil {
		return nil, err
	}
	return &service, nil
}

const openwrtSettingsSchema = `
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
			"ssh_key": {
				"type": "string"
			},
			"zone": {
				"type": "string"
			},
			"ttl": {
				"type": "string",
				"pattern": "^([0-9]+(\\.[0-9]+)?(ns|us|µs|ms|s|m|h))+$"
			}
		},
		"required": [
			"address",
			"username",
			"zone",
			"ttl"
		]
	}
	`

func (o *OpenWrt) Update(hostname string, addrCollection *ipv6disc.AddrCollection) error {
	client, err := dialSSH(o.Address, o.Username, o.Password, o.SSHKey)
	if err != nil {
		return err
	}
	defer client.Close()

	// -X names the anonymous sections cfgXXXXXX rather than @domain[N], whose numbers shift when
	// one is deleted.
	output, err := runSSH(client, "uci -X show dhcp")
	if err != nil {
		return err
	}

	fqdn := FQDN(hostname, o.Zone)

	// The address of each of the name's domain sections.
	existingIPs := make(map[string]string) // IP -> section
	var idsToDelete []string
	for id, record := range uciDomains(string(output)) {
		if record.name != fqdn {
			continue
		}
		ip, ok := canonicalIP(record.ip)
		if !ok {
			continue
		}
		if _, duplicate := existingIPs[ip]; duplicate {
			idsToDelete = append(idsToDelete, id)
			continue
		}
		existingIPs[ip] = id
	}

	desiredIPs := desiredRecords(addrCollection)

	for ip, id := range existingIPs {
		if _, ok := desiredIPs[ip]; !ok {
			idsToDelete = append(idsToDelete, id)
		}
	}

	var ipsToAdd []string
	for ip := range desiredIPs {
		if _, exists := existingIPs[ip]; !exists {
			ipsToAdd = append(ipsToAdd, ip)
		}
	}

	if len(idsToDelete) == 0 && len(ipsToAdd) == 0 {
		return nil
	}

	for _, id := range idsToDelete {
		if _, err := runSSH(client, fmt.Sprintf("uci delete dhcp.%s", id)); err != nil {
			return err
		}
	}

	for _, ip := range ipsToAdd {
		// A named section, the same for the same name and address.
		hash := sha256.Sum256([]byte(fqdn + ip))
		id := "ipv6ddns_" + hex.EncodeToString(hash[:])[:8]

		for _, cmd := range []string{
			fmt.Sprintf("uci set dhcp.%s=domain", id),
			fmt.Sprintf("uci set dhcp.%s.name=%s", id, shellQuote(fqdn)),
			fmt.Sprintf("uci set dhcp.%s.ip=%s", id, shellQuote(ip)),
		} {
			if _, err := runSSH(client, cmd); err != nil {
				return err
			}
		}
	}

	if _, err := runSSH(client, "uci commit dhcp"); err != nil {
		return err
	}
	if _, err := runSSH(client, "/etc/init.d/dnsmasq reload"); err != nil {
		return err
	}

	return nil
}

type uciDomain struct {
	name string
	ip   string
}

// uciDomains reads the domain sections, the DNS records of dnsmasq, out of `uci -X show dhcp`, by
// section ID. Its lines are:
//
//	dhcp.cfg0af37d=domain
//	dhcp.cfg0af37d.name='host.lan'
//	dhcp.cfg0af37d.ip='192.168.1.10'
//
// The other sections, such as the static leases of hosts, have names and addresses too.
func uciDomains(output string) map[string]uciDomain {
	types := make(map[string]string)
	options := make(map[string]map[string]string)
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		value = strings.Trim(value, "'")
		path := strings.Split(key, ".")
		if len(path) < 2 || path[0] != "dhcp" {
			continue
		}
		id := path[1]
		switch len(path) {
		case 2:
			types[id] = value
		case 3:
			if options[id] == nil {
				options[id] = make(map[string]string)
			}
			options[id][path[2]] = value
		}
	}

	domains := make(map[string]uciDomain)
	for id, sectionType := range types {
		if sectionType == "domain" {
			domains[id] = uciDomain{name: options[id]["name"], ip: options[id]["ip"]}
		}
	}
	return domains
}

// shellQuote makes s a single-quoted shell word.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func (o *OpenWrt) Domain(hostname string) string {
	return FQDN(hostname, o.Zone)
}
