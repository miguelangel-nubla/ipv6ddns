package ddns

import (
	"encoding/json"
	"errors"
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
	return &service, nil
}

type technitiumResponse struct {
	Status       string `json:"status"`
	ErrorMessage string `json:"errorMessage"`
	Response     struct {
		Records []struct {
			Type  string          `json:"type"`
			TTL   int             `json:"ttl"`
			RData json.RawMessage `json:"rData"`
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

	// 3. Calculate Diff
	// Delete records that are not in desired
	for ip, record := range currentIPs {
		if _, needed := desiredIPs[ip]; !needed {
			if err := t.request(client, "delete", fqdn, record.rrType, ip, 0); err != nil {
				return fmt.Errorf("failed to delete record %s (%s): %w", fqdn, ip, err)
			}
		} else if ttl > 0 && record.ttl != ttl {
			// Kept, with the TTL set.
			if err := t.request(client, "update", fqdn, record.rrType, ip, ttl); err != nil {
				return fmt.Errorf("failed to set the TTL of record %s (%s): %w", fqdn, ip, err)
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
	rrType string
	ttl    int
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

	resp, err := client.Get(u.String())
	if err != nil {
		return nil, withoutURL(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var apiResp technitiumResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, err
	}

	if apiResp.Status != "ok" {
		return nil, errors.New(apiResp.ErrorMessage)
	}

	currentIPs := make(map[string]technitiumRecord)
	for _, rec := range apiResp.Response.Records {
		if rec.Type == "A" || rec.Type == "AAAA" {
			var rData technitiumRDataIP
			if err := json.Unmarshal(rec.RData, &rData); err == nil {
				if ip, ok := canonicalIP(rData.IPAddress); ok {
					currentIPs[ip] = technitiumRecord{rrType: rec.Type, ttl: rec.TTL}
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
	if action == "add" {
		q.Set("overwrite", "false") // The others of the name stay: the ones not wanted are deleted one by one
	}
	u.RawQuery = q.Encode()

	resp, err := client.Get(u.String())
	if err != nil {
		return withoutURL(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var apiResp technitiumResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return err
	}

	if apiResp.Status != "ok" {
		return errors.New(apiResp.ErrorMessage)
	}

	return nil
}

func (t *Technitium) Domain(hostname string) string {
	return FQDN(hostname, t.Zone)
}
