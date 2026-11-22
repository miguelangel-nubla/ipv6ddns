package ddns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
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

// Update changes the host overrides of the name, A and AAAA, one by one, and then reconfigures
// Unbound: those of the name's other types, as an MX, stay.
func (u *OpnsenseUnbound) Update(hostname string, addrCollection *ipv6disc.AddrCollection) error {
	client := newHTTPClient(verifiedOrPinnedTLSConfig(urlHost(u.Address), u.TLSFingerprint))

	var search struct {
		Rows []unboundOverrideRow `json:"rows"`
	}
	if err := u.call(client, http.MethodGet, "settings/searchHostOverride", nil, &search); err != nil {
		return fmt.Errorf("failed to fetch existing Host Overrides: %w", err)
	}

	fqdn := FQDN(hostname, u.Zone)
	hostPart, domainPart := SplitFQDN(fqdn)
	desiredIPs := desiredRecords(addrCollection)
	ttl := strconv.Itoa(int(u.TTL.Seconds()))

	currentIPs := make(map[string][]string) // the UUIDs of each address's overrides
	staleTTL := make(map[string]bool)       // by UUID
	for _, row := range search.Rows {
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

	// Each change sets pending before it is sent: one whose answer doesn't come may be made.
	for ip, recordType := range desiredIPs {
		uuids, exists := currentIPs[ip]
		if !exists {
			u.pending = true
			if err := u.saveOverride(client, "addHostOverride", hostPart, domainPart, recordType, ip); err != nil {
				return fmt.Errorf("failed to add override %s -> %s: %w", fqdn, ip, err)
			}
			continue
		}
		// An address has one override: the others are deleted.
		for _, uuid := range uuids[1:] {
			u.pending = true
			if err := u.deleteOverride(client, uuid); err != nil {
				return fmt.Errorf("failed to delete duplicate override %s -> %s (UUID: %s): %w", fqdn, ip, uuid, err)
			}
		}
		// And the one kept has the TTL set.
		if staleTTL[uuids[0]] {
			u.pending = true
			if err := u.saveOverride(client, "setHostOverride/"+uuids[0], hostPart, domainPart, recordType, ip); err != nil {
				return fmt.Errorf("failed to set the TTL of override %s -> %s: %w", fqdn, ip, err)
			}
		}
	}

	for ip, uuids := range currentIPs {
		if _, keep := desiredIPs[ip]; keep {
			continue
		}
		for _, uuid := range uuids {
			u.pending = true
			if err := u.deleteOverride(client, uuid); err != nil {
				return fmt.Errorf("failed to delete override %s -> %s: %w", fqdn, ip, err)
			}
		}
	}

	// The changes of this update, or of one that failed before it, are served once Unbound is
	// reconfigured.
	if u.pending {
		if err := u.call(client, http.MethodPost, "service/reconfigure", struct{}{}, nil); err != nil {
			return fmt.Errorf("failed to reconfigure Unbound: %w", err)
		}
		u.pending = false
	}

	return nil
}

// unboundOverrideRow is a host override, as searchHostOverride lists it.
type unboundOverrideRow struct {
	UUID     string `json:"uuid"`
	Enabled  string `json:"enabled"`
	Hostname string `json:"hostname"`
	Domain   string `json:"domain"`
	// The type, A, AAAA or MX: up to OPNsense 25.1, with its description, "AAAA (IPv6 address)".
	RR string `json:"rr"`
	// The address.
	Server string `json:"server"`
	// In seconds: empty when the version doesn't tell it.
	TTL         string `json:"ttl"`
	Description string `json:"description"`
}

// saveOverride posts the override of an address to action: addHostOverride for a new one,
// setHostOverride/<uuid> to replace that one.
func (u *OpnsenseUnbound) saveOverride(client *http.Client, action, hostname, domain, recordType, ip string) error {
	return u.call(client, http.MethodPost, "settings/"+action, map[string]any{
		"host": map[string]string{
			"enabled":     "1",
			"hostname":    hostname,
			"domain":      domain,
			"rr":          recordType,
			"server":      ip,
			"ttl":         strconv.Itoa(int(u.TTL.Seconds())),
			"description": "Managed by ipv6ddns",
		},
	}, nil)
}

func (u *OpnsenseUnbound) deleteOverride(client *http.Client, uuid string) error {
	return u.call(client, http.MethodPost, "settings/delHostOverride/"+uuid, struct{}{}, nil)
}

// call sends a request of Unbound's API, at path under /api/unbound/, with body as JSON when not
// nil. A GET's answer is read into out; that of any other method must say it was done, as
// "saved", "deleted" or the status "ok", which out then needn't read.
func (u *OpnsenseUnbound) call(client *http.Client, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, strings.TrimRight(u.Address, "/")+"/api/unbound/"+path, reader)
	if err != nil {
		return err
	}
	req.SetBasicAuth(u.Key, u.Secret)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	answer, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%s: reading the answer: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: status %d: %s", path, resp.StatusCode, answer)
	}
	if method == http.MethodGet {
		if err := json.Unmarshal(answer, out); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		return nil
	}
	var done struct {
		Result string `json:"result"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(answer, &done); err != nil {
		return fmt.Errorf("%s: an answer that isn't JSON: %s", path, answer)
	}
	if done.Result != "saved" && done.Result != "deleted" && done.Status != "ok" {
		return fmt.Errorf("%s failed: %s", path, answer)
	}
	return nil
}

func (u *OpnsenseUnbound) Domain(hostname string) string {
	return FQDN(hostname, u.Zone)
}
