package ddns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
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

// Update makes the name's host override have the addresses, of both families: pfSense keeps one
// override of a name, with all its addresses. Then it applies the changes.
func (u *PfsenseRestapiUnbound) Update(hostname string, addrCollection *ipv6disc.AddrCollection) error {
	// One update of a pfSense at a time, from reading the overrides to changing one. The ID of
	// an override is its position in the list, which moves when one before it is deleted: with
	// two updates at once, the second would change or delete the override of another name.
	defer lockDevice("pfsense", u.Address)()

	client := newHTTPClient(verifiedOrPinnedTLSConfig(urlHost(u.Address), u.TLSFingerprint))

	fqdn := FQDN(hostname, u.Zone)
	if strings.Contains(fqdn, "*") {
		return fmt.Errorf("pfSense does not support wildcard DNS entries: %s", fqdn)
	}

	var overrides []pfsenseRestapiOverrideRow
	if err := u.call(client, http.MethodGet, "host_overrides", nil, &overrides); err != nil {
		return fmt.Errorf("failed to fetch existing Host Overrides: %w", err)
	}

	hostPart, domainPart := SplitFQDN(fqdn)
	desired := slices.Sorted(maps.Keys(desiredRecords(addrCollection)))

	// pfSense has one override of a host and domain at most.
	var existing *pfsenseRestapiOverrideRow
	for i := range overrides {
		if overrides[i].Host == hostPart && overrides[i].Domain == domainPart {
			existing = &overrides[i]
			break
		}
	}

	// Each change sets pending before it is sent: one whose answer doesn't come may be made.
	switch {
	case existing == nil:
		if len(desired) > 0 {
			u.pending = true
			if err := u.call(client, http.MethodPost, "host_override", u.override(nil, hostPart, domainPart, desired), nil); err != nil {
				return fmt.Errorf("failed to add override %s: %w", fqdn, err)
			}
		}
	case !slices.Equal(existing.addresses(), desired):
		id := existing.id()
		u.pending = true
		if len(desired) > 0 {
			if err := u.call(client, http.MethodPatch, "host_override", u.override(&id, hostPart, domainPart, desired), nil); err != nil {
				return fmt.Errorf("failed to update override %s (ID: %s): %w", fqdn, id, err)
			}
		} else if err := u.call(client, http.MethodDelete, "host_override?id="+url.QueryEscape(id), nil, nil); err != nil {
			return fmt.Errorf("failed to delete override %s (ID: %s): %w", fqdn, id, err)
		}
	}

	// The changes of this update, or of one that failed before it, are served once applied.
	if u.pending {
		if err := u.call(client, http.MethodPost, "apply", struct{}{}, nil); err != nil {
			return fmt.Errorf("failed to apply Unbound changes: %w", err)
		}
		u.pending = false
	}

	return nil
}

// pfsenseRestapiOverrideRow is a host override, as the API lists it.
type pfsenseRestapiOverrideRow struct {
	// Its position in the list: a number, as the API tells it.
	ID     json.RawMessage `json:"id"`
	Host   string          `json:"host"`
	Domain string          `json:"domain"`
	IP     []string        `json:"ip"`
	Descr  string          `json:"descr"`
}

// id is the override's ID as the API takes it back: its number as written, never 1e+06.
func (r pfsenseRestapiOverrideRow) id() string {
	return strings.Trim(string(r.ID), `"`)
}

// addresses are the override's addresses, canonical and sorted: one twice is twice, and makes
// the override written again.
func (r pfsenseRestapiOverrideRow) addresses() []string {
	var ips []string
	for _, ip := range r.IP {
		if ip, ok := canonicalIP(ip); ok {
			ips = append(ips, ip)
		}
	}
	slices.Sort(ips)
	return ips
}

// override is the body of an override to add, or with its id to replace.
func (u *PfsenseRestapiUnbound) override(id *string, host, domain string, ips []string) map[string]any {
	body := map[string]any{"host": host, "domain": domain, "ip": ips, "descr": "Managed by ipv6ddns"}
	if id != nil {
		body["id"] = *id
	}
	return body
}

// call sends a request of the DNS resolver's API, at path under
// /api/v2/services/dns_resolver/, with body as JSON when not nil, and reads the data of its
// answer into out when not nil. The answer must say it succeeded: its status ok or success, or its
// code 200.
func (u *PfsenseRestapiUnbound) call(client *http.Client, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, strings.TrimRight(u.Address, "/")+"/api/v2/services/dns_resolver/"+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", u.Key)
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
		return fmt.Errorf("reading the answer: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, answer)
	}
	var apiResp struct {
		Status  string          `json:"status"`
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(answer, &apiResp); err != nil {
		return fmt.Errorf("failed to parse API response: %s", answer)
	}
	if apiResp.Status != "ok" && apiResp.Status != "success" && apiResp.Code != http.StatusOK {
		if apiResp.Message != "" {
			return fmt.Errorf("API error: %s", apiResp.Message)
		}
		return fmt.Errorf("API error: %s", answer)
	}
	if out != nil {
		if err := json.Unmarshal(apiResp.Data, out); err != nil {
			return fmt.Errorf("the API's data: %w", err)
		}
	}
	return nil
}

func (u *PfsenseRestapiUnbound) Domain(hostname string) string {
	return FQDN(hostname, u.Zone)
}
