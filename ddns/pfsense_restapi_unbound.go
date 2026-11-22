package ddns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/duration"
	"github.com/miguelangel-nubla/ipv6disc"
)

type PfsenseRestapiUnbound struct {
	Address        string `json:"address"`
	TLSFingerprint string `json:"tls_fingerprint"`
	Key            string `json:"key"`
	Zone           string `json:"zone"`
	// pfSense's host overrides have no TTL of their own: it is read for the schema, and unused.
	TTL duration.Duration `json:"ttl"`

	// A change was sent and Unbound is not known to have applied it: the next update applies,
	// whatever it finds, as the overrides read show it made. Read and set during an update, one
	// at a time.
	pending bool
}

func init() {
	RegisterProvider("pfsense_restapi_unbound", NewPfsenseRestapiUnbound)
}

func NewPfsenseRestapiUnbound(settings json.RawMessage) (Service, error) {
	var service PfsenseRestapiUnbound
	if err := decodeSettings(settings, "pfsense_restapi_unbound", &service); err != nil {
		return nil, err
	}
	return &service, nil
}

func (u *PfsenseRestapiUnbound) Update(hostname string, addrCollection *ipv6disc.AddrCollection) error {
	// One update of a pfSense at a time, from reading the overrides to changing one. The ID of
	// an override is its position in the list, which moves when one before it is deleted: with
	// two updates at once, the second would change or delete the override of another name.
	defer lockDevice("pfsense", u.Address)()

	client := newHTTPClient(verifiedOrPinnedTLSConfig(urlHost(u.Address), u.TLSFingerprint))

	// Note: pfSense does not support wildcard DNS entries (e.g., *.example.com)
	// Validate that the hostname does not contain wildcards
	fqdn := FQDN(hostname, u.Zone)
	if strings.Contains(fqdn, "*") {
		return fmt.Errorf("pfSense does not support wildcard DNS entries: %s", fqdn)
	}

	// 1. Fetch existing Host Overrides
	existingOverrides, err := u.getOverrides(client)
	if err != nil {
		return fmt.Errorf("failed to fetch existing Host Overrides: %v", err)
	}

	// 2. Identify the relevant existing override for this hostname
	desiredIPs := desiredRecords(addrCollection)

	hostPart, domainPart := SplitFQDN(fqdn)

	// Look for an existing override matching host and domain.
	// pfSense enforces uniqueness for this combination.
	var existingRecord *pfsenseRestapiOverrideRow
	for i := range existingOverrides {
		if existingOverrides[i].Host == hostPart && existingOverrides[i].Domain == domainPart {
			existingRecord = &existingOverrides[i]
			break
		}
	}

	// 3. Manage IPs
	desiredIPSlice := make([]string, 0, len(desiredIPs))
	for ip := range desiredIPs {
		desiredIPSlice = append(desiredIPSlice, ip)
	}

	// Helper to compare IP slices (insensitive to order)
	ipsMatch := func(a, b []string) bool {
		if len(a) != len(b) {
			return false
		}
		m := make(map[string]bool)
		for _, x := range a {
			m[x] = true
		}
		for _, x := range b {
			if !m[x] {
				return false
			}
		}
		return true
	}

	if existingRecord == nil {
		// No existing record, add New
		if len(desiredIPSlice) > 0 {
			u.pending = true
			err := u.addOverride(client, hostPart, domainPart, desiredIPSlice)
			if err != nil {
				return fmt.Errorf("failed to add override %s: %v", fqdn, err)
			}
		}
	} else {
		// Record exists, update or delete
		idStr := fmt.Sprintf("%v", existingRecord.ID)
		var currentIPs []string
		for _, ip := range existingRecord.IP {
			if ip, ok := canonicalIP(ip); ok {
				currentIPs = append(currentIPs, ip)
			}
		}
		if !ipsMatch(currentIPs, desiredIPSlice) {
			u.pending = true
			if len(desiredIPSlice) > 0 {
				err := u.updateOverride(client, idStr, hostPart, domainPart, desiredIPSlice)
				if err != nil {
					return fmt.Errorf("failed to update override %s (ID: %s): %v", fqdn, idStr, err)
				}
			} else {
				// No IPs desired anymore, delete
				err := u.deleteOverride(client, idStr)
				if err != nil {
					return fmt.Errorf("failed to delete override %s (ID: %s): %w", fqdn, idStr, err)
				}
			}
		}
	}

	// 4. Apply, the changes of this update or of one that failed before it: a change sent,
	// whether or not its answer came, counts as made.
	if u.pending {
		if err := u.applyChanges(client); err != nil {
			return fmt.Errorf("failed to apply Unbound changes: %v", err)
		}
		u.pending = false
	}

	return nil
}

// Helper types for pfSense API
type pfsenseRestapiOverrideRow struct {
	ID     interface{} `json:"id"`
	Host   string      `json:"host"`
	Domain string      `json:"domain"`
	IP     []string    `json:"ip"`
	Descr  string      `json:"descr"`
}

type pfsenseRestapiResponse struct {
	Status  string          `json:"status"`
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func (u *PfsenseRestapiUnbound) getOverrides(client *http.Client) ([]pfsenseRestapiOverrideRow, error) {
	url := fmt.Sprintf("%s/api/v2/services/dns_resolver/host_overrides", strings.TrimRight(u.Address, "/"))
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", u.Key)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var apiResp pfsenseRestapiResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}

	if apiResp.Status != "success" && apiResp.Code != 200 {
		return nil, fmt.Errorf("API error: %s", apiResp.Message)
	}

	var rows []pfsenseRestapiOverrideRow
	if err := json.Unmarshal(apiResp.Data, &rows); err != nil {
		return nil, err
	}

	return rows, nil
}

func (u *PfsenseRestapiUnbound) addOverride(client *http.Client, host, domain string, ips []string) error {
	url := fmt.Sprintf("%s/api/v2/services/dns_resolver/host_override", strings.TrimRight(u.Address, "/"))

	payload := map[string]interface{}{
		"host":   host,
		"domain": domain,
		"ip":     ips,
		"descr":  "Managed by ipv6ddns",
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", u.Key)
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

	var apiResp pfsenseRestapiResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return fmt.Errorf("failed to parse API response: %s", string(body))
	}

	if apiResp.Status != "ok" && apiResp.Status != "success" {
		if apiResp.Message != "" {
			return fmt.Errorf("API error: %s (Full response: %s)", apiResp.Message, string(body))
		}
		return fmt.Errorf("API error: %s", string(body))
	}

	return nil
}

func (u *PfsenseRestapiUnbound) updateOverride(client *http.Client, id, host, domain string, ips []string) error {
	url := fmt.Sprintf("%s/api/v2/services/dns_resolver/host_override", strings.TrimRight(u.Address, "/"))

	payload := map[string]interface{}{
		"id":     id,
		"host":   host,
		"domain": domain,
		"ip":     ips,
		"descr":  "Managed by ipv6ddns",
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PATCH", url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", u.Key)
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

	var apiResp pfsenseRestapiResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return fmt.Errorf("failed to parse API response: %s", string(body))
	}

	if apiResp.Status != "success" && apiResp.Code != 200 {
		return fmt.Errorf("API error: %s", apiResp.Message)
	}

	return nil
}

func (u *PfsenseRestapiUnbound) deleteOverride(client *http.Client, id string) error {
	url := fmt.Sprintf("%s/api/v2/services/dns_resolver/host_override?id=%s", strings.TrimRight(u.Address, "/"), id)

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", u.Key)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var apiResp pfsenseRestapiResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return fmt.Errorf("failed to parse API response: %s", string(body))
	}

	if apiResp.Status != "ok" && apiResp.Status != "success" {
		return fmt.Errorf("API error: %s", apiResp.Message)
	}

	return nil
}

func (u *PfsenseRestapiUnbound) applyChanges(client *http.Client) error {
	url := fmt.Sprintf("%s/api/v2/services/dns_resolver/apply", strings.TrimRight(u.Address, "/"))

	req, err := http.NewRequest("POST", url, bytes.NewBufferString("{}"))
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", u.Key)
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

	var apiResp pfsenseRestapiResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return fmt.Errorf("failed to parse API response: %s", string(body))
	}

	if apiResp.Status != "ok" && apiResp.Status != "success" {
		return fmt.Errorf("API error: %s", apiResp.Message)
	}

	return nil
}

func (c *PfsenseRestapiUnbound) Domain(hostname string) string {
	return FQDN(hostname, c.Zone)
}
