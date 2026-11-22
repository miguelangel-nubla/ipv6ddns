package ddns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/duration"
	"github.com/miguelangel-nubla/ipv6disc"
)

type OpnsenseUnbound struct {
	Address        string            `json:"address"`
	TLSFingerprint string            `json:"tls_fingerprint"`
	Key            string            `json:"key"`
	Secret         string            `json:"secret"`
	Zone           string            `json:"zone"`
	TTL            duration.Duration `json:"ttl"`

	// A change was sent and Unbound is not known to have been reconfigured with it: the next
	// update reconfigures, whatever it finds, as the overrides read show it made. Read and set
	// during an update, one at a time.
	pending bool
}

func init() {
	RegisterProvider("opnsense_unbound", NewOpnsenseUnbound)
}

func NewOpnsenseUnbound(settings json.RawMessage) (Service, error) {
	var service OpnsenseUnbound
	if err := decodeSettings(settings, "opnsense_unbound", &service); err != nil {
		return nil, err
	}
	return &service, nil
}

func (u *OpnsenseUnbound) Update(hostname string, addrCollection *ipv6disc.AddrCollection) error {
	client := newHTTPClient(verifiedOrPinnedTLSConfig(urlHost(u.Address), u.TLSFingerprint))

	// 1. Fetch existing Host Overrides
	existingOverrides, err := u.getOverrides(client)
	if err != nil {
		return fmt.Errorf("failed to fetch existing Host Overrides: %w", err)
	}

	fqdn := FQDN(hostname, u.Zone)
	desiredIPs := desiredRecords(addrCollection)

	// Filter existing overrides for this FQDN
	hostPart, domainPart := SplitFQDN(fqdn)

	ttl := fmt.Sprintf("%d", int(u.TTL.Seconds()))

	currentIPs := make(map[string][]string) // IP -> list of UUIDs
	staleTTL := make(map[string]bool)       // by UUID
	for _, row := range existingOverrides {
		if row.Hostname != hostPart || row.Domain != domainPart {
			continue
		}
		// The type is the first word: AAAA, or up to OPNsense 25.1 its description,
		// "AAAA (IPv6 address)". An MX of the name is not one of these records.
		rrType := ""
		if fields := strings.Fields(row.RR); len(fields) > 0 {
			rrType = strings.ToUpper(fields[0])
		}
		if rrType != "A" && rrType != "AAAA" {
			continue
		}
		if ip, ok := canonicalIP(row.Server); ok {
			currentIPs[ip] = append(currentIPs[ip], row.UUID)
			// A version that doesn't tell the TTL has none to compare.
			if rowTTL := strings.TrimSpace(row.TTL); rowTTL != "" && rowTTL != ttl {
				staleTTL[row.UUID] = true
			}
		}
	}

	// 2. Manage IPs
	// Add missing IPs and clean up duplicates for existing ones
	for ip := range desiredIPs {
		uuids, exists := currentIPs[ip]
		if !exists {
			u.pending = true
			err := u.addOverride(client, hostPart, domainPart, ip)
			if err != nil {
				return fmt.Errorf("failed to add override %s -> %s: %w", fqdn, ip, err)
			}
		} else {
			// Duplicate records exist for this IP, remove extra ones
			for i := 1; i < len(uuids); i++ {
				u.pending = true
				err := u.deleteOverride(client, uuids[i])
				if err != nil {
					return fmt.Errorf("failed to delete duplicate override %s -> %s (UUID: %s): %w", fqdn, ip, uuids[i], err)
				}
			}
			// And the one kept has the TTL set.
			if staleTTL[uuids[0]] {
				u.pending = true
				if err := u.saveOverride(client, "setHostOverride/"+uuids[0], hostPart, domainPart, ip); err != nil {
					return fmt.Errorf("failed to set the TTL of override %s -> %s: %w", fqdn, ip, err)
				}
			}
		}
	}

	// 3. Remove obsolete IPs
	for ip, uuids := range currentIPs {
		if _, keep := desiredIPs[ip]; !keep {
			for _, uuid := range uuids {
				u.pending = true
				err := u.deleteOverride(client, uuid)
				if err != nil {
					return fmt.Errorf("failed to delete override %s -> %s: %w", fqdn, ip, err)
				}
			}
		}
	}

	// 4. Reconfigure, after the changes of this update or of one that failed before it: a
	// change sent, whether or not its answer came, counts as made.
	if u.pending {
		if err := u.reconfigure(client); err != nil {
			return fmt.Errorf("failed to reconfigure Unbound: %w", err)
		}
		u.pending = false
	}

	return nil
}

// Helper types for OPNsense API
type unboundOverrideRow struct {
	UUID     string `json:"uuid"`
	Enabled  string `json:"enabled"`
	Hostname string `json:"hostname"`
	Domain   string `json:"domain"`
	// The type, A, AAAA or MX: up to OPNsense 25.1, with its description, "AAAA (IPv6 address)".
	RR     string `json:"rr"`
	Server string `json:"server"` // This is the IP address
	// In seconds: empty when the version doesn't tell it.
	TTL         string `json:"ttl"`
	Description string `json:"description"`
}

type unboundSearchResponse struct {
	Rows []unboundOverrideRow `json:"rows"`
}

type opnsenseResponse struct {
	Result string `json:"result"`
	Status string `json:"status"`
}

func (u *OpnsenseUnbound) getOverrides(client *http.Client) ([]unboundOverrideRow, error) {
	url := fmt.Sprintf("%s/api/unbound/settings/searchHostOverride", strings.TrimRight(u.Address, "/"))
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(u.Key, u.Secret)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var searchResp unboundSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return nil, err
	}

	return searchResp.Rows, nil
}

func (u *OpnsenseUnbound) addOverride(client *http.Client, hostname, domain, ip string) error {
	return u.saveOverride(client, "addHostOverride", hostname, domain, ip)
}

// saveOverride posts an override to action: addHostOverride for a new one, setHostOverride/<uuid>
// to replace that one.
func (u *OpnsenseUnbound) saveOverride(client *http.Client, action, hostname, domain, ip string) error {
	url := fmt.Sprintf("%s/api/unbound/settings/%s", strings.TrimRight(u.Address, "/"), action)

	recordType := "A"
	if addr, err := netip.ParseAddr(ip); err == nil && addr.Is6() {
		recordType = "AAAA"
	}

	payload := map[string]interface{}{
		"host": map[string]string{
			"enabled":     "1",
			"hostname":    hostname,
			"domain":      domain,
			"rr":          recordType,
			"server":      ip,
			"ttl":         fmt.Sprintf("%d", int(u.TTL.Seconds())),
			"description": "Managed by ipv6ddns",
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.SetBasicAuth(u.Key, u.Secret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var apiResp opnsenseResponse
	if err := json.Unmarshal(body, &apiResp); err == nil {
		if apiResp.Result != "saved" && apiResp.Result != "deleted" && apiResp.Status != "ok" {
			return fmt.Errorf("%s failed: %s", action, string(body))
		}
	} else {
		return fmt.Errorf("%s failed to parse response: %s", action, string(body))
	}

	return nil
}

func (u *OpnsenseUnbound) deleteOverride(client *http.Client, uuid string) error {
	url := fmt.Sprintf("%s/api/unbound/settings/delHostOverride/%s", strings.TrimRight(u.Address, "/"), uuid)

	req, err := http.NewRequest("POST", url, bytes.NewBufferString("{}"))
	if err != nil {
		return err
	}
	req.SetBasicAuth(u.Key, u.Secret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var apiResp opnsenseResponse
	if err := json.Unmarshal(body, &apiResp); err == nil {
		if apiResp.Result != "saved" && apiResp.Result != "deleted" && apiResp.Status != "ok" {
			return fmt.Errorf("delHostOverride failed: %s", string(body))
		}
	} else {
		return fmt.Errorf("delHostOverride failed to parse response: %s", string(body))
	}

	return nil
}

func (u *OpnsenseUnbound) reconfigure(client *http.Client) error {
	url := fmt.Sprintf("%s/api/unbound/service/reconfigure", strings.TrimRight(u.Address, "/"))

	req, err := http.NewRequest("POST", url, bytes.NewBufferString("{}"))
	if err != nil {
		return err
	}
	req.SetBasicAuth(u.Key, u.Secret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("reconfigure failed with status %d: %s", resp.StatusCode, string(body))
	}

	var apiResp opnsenseResponse
	if err := json.Unmarshal(body, &apiResp); err == nil {
		if apiResp.Result != "saved" && apiResp.Result != "deleted" && apiResp.Status != "ok" {
			return fmt.Errorf("reconfigure failed: %s", string(body))
		}
	} else {
		return fmt.Errorf("reconfigure failed to parse response: %s", string(body))
	}

	return nil
}

func (c *OpnsenseUnbound) Domain(hostname string) string {
	return FQDN(hostname, c.Zone)
}
