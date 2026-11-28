package ddns

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/duration"
	"github.com/miguelangel-nubla/ipv6disc"
)

type Technitium struct {
	Address        string            `json:"address"`
	TLSFingerprint string            `json:"tls_fingerprint"`
	Token          string            `json:"token"`
	Zone           string            `json:"zone"`
	TTL            duration.Duration `json:"ttl"`
}

func init() {
	RegisterProvider("technitium", NewTechnitium)
}

func NewTechnitium(settings json.RawMessage) (Service, error) {
	var service Technitium
	if err := decodeSettings(settings, "technitium", &service); err != nil {
		return nil, err
	}
	if err := fingerprintNeedsTLS(service.Address, service.TLSFingerprint); err != nil {
		return nil, err
	}
	return &service, nil
}

type technitiumResponse struct {
	Status       string `json:"status"`
	ErrorMessage string `json:"errorMessage"`
	Response     struct {
		Records []struct {
			Type     string          `json:"type"`
			TTL      int             `json:"ttl"`
			Disabled bool            `json:"disabled"`
			RData    json.RawMessage `json:"rData"`
		} `json:"records"`
	} `json:"response"`
}

type technitiumRDataIP struct {
	IPAddress string `json:"ipAddress"`
}

func (t *Technitium) Update(hostname string, addrCollection *ipv6disc.AddrCollection) error {
	client := newHTTPClient(verifiedOrPinnedTLSConfig(urlHost(t.Address), t.TLSFingerprint))

	fqdn := FQDN(hostname, t.Zone)

	// 1. Get current records
	currentIPs, err := t.getRecords(client, fqdn)
	if err != nil {
		return fmt.Errorf("failed to get records: %w", err)
	}

	desiredIPs := desiredRecords(addrCollection)

	ttl := int(t.TTL.Seconds())

	// A disabled record is as any other: Technitium enables the disabled records of a name's
	// type whenever a record of that type is added, so it can't be kept disabled beside the
	// name's records. Deleted when its address is not wanted, and enabled when it is.
	for ip, record := range currentIPs {
		_, needed := desiredIPs[ip]
		switch {
		case !needed:
			if err := t.request(client, "delete", fqdn, record.rrType, ip, 0); err != nil {
				return fmt.Errorf("failed to delete record %s (%s): %w", fqdn, ip, err)
			}
		case record.disabled || (ttl > 0 && record.ttl != ttl):
			// Kept, enabled, with the TTL set, or the one it had.
			keep := record.ttl
			if ttl > 0 {
				keep = ttl
			}
			if err := t.request(client, "update", fqdn, record.rrType, ip, keep); err != nil {
				return fmt.Errorf("failed to update record %s (%s): %w", fqdn, ip, err)
			}
		}
	}

	// Add records that are in desired but not current
	for ip, recordType := range desiredIPs {
		if _, exists := currentIPs[ip]; !exists {
			if err := t.request(client, "add", fqdn, recordType, ip, ttl); err != nil {
				return fmt.Errorf("failed to add record %s (%s): %w", fqdn, ip, err)
			}
		}
	}

	return nil
}

// technitiumRecord is an A or AAAA record of a name.
type technitiumRecord struct {
	rrType   string
	ttl      int
	disabled bool
}

func (t *Technitium) getRecords(client *http.Client, domain string) (map[string]technitiumRecord, error) {
	u, err := url.Parse(t.Address)
	if err != nil {
		return nil, err
	}
	u.Path, _ = url.JoinPath(u.Path, "/api/zones/records/get")
	q := u.Query()
	q.Set("token", t.Token)
	q.Set("domain", domain)
	q.Set("zone", t.Zone)
	u.RawQuery = q.Encode()

	apiResp, err := technitiumCall(client, u)
	if err != nil {
		return nil, err
	}

	currentIPs := make(map[string]technitiumRecord)
	for _, rec := range apiResp.Response.Records {
		if rec.Type == "A" || rec.Type == "AAAA" {
			var rData technitiumRDataIP
			if err := json.Unmarshal(rec.RData, &rData); err == nil {
				if ip, ok := canonicalIP(rData.IPAddress); ok {
					currentIPs[ip] = technitiumRecord{rrType: rec.Type, ttl: rec.TTL, disabled: rec.Disabled}
				}
			}
		}
	}

	return currentIPs, nil
}

// request runs an action of the records API, add, update or delete, on the record of the address
// ip. The ttl is for add and update.
func (t *Technitium) request(client *http.Client, action, domain, recordType, ip string, ttl int) error {
	u, err := url.Parse(t.Address)
	if err != nil {
		return err
	}
	u.Path, _ = url.JoinPath(u.Path, "/api/zones/records/"+action)
	q := u.Query()
	q.Set("token", t.Token)
	q.Set("domain", domain)
	q.Set("zone", t.Zone)
	q.Set("type", recordType)
	q.Set("ipAddress", ip)
	if action != "delete" {
		q.Set("ttl", strconv.Itoa(ttl))
	}
	switch action {
	case "add":
		q.Set("overwrite", "false") // The others of the name stay: the ones not wanted are deleted one by one
	case "update":
		// The record is kept, of its address, and enabled if it was disabled.
		q.Set("newIpAddress", ip)
		q.Set("disable", "false")
	}
	u.RawQuery = q.Encode()

	_, err = technitiumCall(client, u)
	return err
}

// technitiumCall asks the API at u, whose query has the token, and returns its answer: an error
// when it is none of the API's, with the HTTP status, as from a wrong address or a proxy between,
// or one that refuses, with its status and message. No error has the URL, nor so the token.
func technitiumCall(client *http.Client, u *url.URL) (technitiumResponse, error) {
	var apiResp technitiumResponse
	resp, err := client.Get(u.String())
	if err != nil {
		return apiResp, withoutURL(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return apiResp, fmt.Errorf("HTTP %s: reading the answer: %w", resp.Status, err)
	}
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return apiResp, fmt.Errorf("HTTP %s: not an answer of Technitium's API: %w", resp.Status, err)
	}
	if apiResp.Status != "ok" {
		if apiResp.ErrorMessage == "" {
			return apiResp, fmt.Errorf("API status %q, HTTP %s", apiResp.Status, resp.Status)
		}
		return apiResp, fmt.Errorf("API status %q: %s", apiResp.Status, apiResp.ErrorMessage)
	}
	return apiResp, nil
}

func (t *Technitium) Domain(hostname string) string {
	return FQDN(hostname, t.Zone)
}
