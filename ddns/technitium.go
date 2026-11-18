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
	if err := decodeSettings(settings, technitiumSettingsSchema, &service); err != nil {
		return nil, err
	}
	return &service, nil
}

const technitiumSettingsSchema = `
	{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "object",
		"additionalProperties": false,
		"properties": {
			"address": {
				"type": "string",
				"minLength": 1
			},
			"tls_fingerprint": {
				"type": "string",
				"pattern": "^([a-fA-F0-9]{64})?$"
			},
			"token": {
				"type": "string",
				"minLength": 1
			},
			"zone": {
				"type": "string",
				"minLength": 1
			},
			"ttl": {
				"type": "string",
				"pattern": "^([0-9]+(\\.[0-9]+)?(ns|us|µs|ms|s|m|h))+$"
			}
		},
		"required": [
			"address",
			"token",
			"zone",
			"ttl"
		]
	}
	`

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
		return fmt.Errorf("failed to get records: %v", err)
	}

	desiredIPs := desiredRecords(addrCollection)

	// 3. Calculate Diff
	// Delete records that are not in desired
	for ip, recordType := range currentIPs {
		if _, needed := desiredIPs[ip]; !needed {
			if err := t.deleteRecord(client, fqdn, recordType, ip); err != nil {
				return fmt.Errorf("failed to delete record %s (%s): %v", fqdn, ip, err)
			}
		}
	}

	// Add records that are in desired but not current
	for ip, recordType := range desiredIPs {
		if _, exists := currentIPs[ip]; !exists {
			if err := t.addRecord(client, fqdn, recordType, ip); err != nil {
				return fmt.Errorf("failed to add record %s (%s): %v", fqdn, ip, err)
			}
		}
	}

	return nil
}

func (t *Technitium) getRecords(client *http.Client, domain string) (map[string]string, error) {
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

	currentIPs := make(map[string]string)
	for _, rec := range apiResp.Response.Records {
		if rec.Type == "A" || rec.Type == "AAAA" {
			var rData technitiumRDataIP
			if err := json.Unmarshal(rec.RData, &rData); err == nil {
				if ip, ok := canonicalIP(rData.IPAddress); ok {
					currentIPs[ip] = rec.Type
				}
			}
		}
	}

	return currentIPs, nil
}

func (t *Technitium) addRecord(client *http.Client, domain, recordType, ip string) error {
	u, err := url.Parse(t.Address)
	if err != nil {
		return err
	}
	u.Path, _ = url.JoinPath(u.Path, "/api/zones/records/add")
	q := u.Query()
	q.Set("token", t.Token)
	q.Set("domain", domain)
	q.Set("zone", t.Zone)
	q.Set("type", recordType)
	q.Set("ipAddress", ip)
	q.Set("ttl", strconv.Itoa(int(t.TTL.Seconds())))
	q.Set("overwrite", "false") // We manage duplicates manually by deleting first
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

func (t *Technitium) deleteRecord(client *http.Client, domain, recordType, ip string) error {
	u, err := url.Parse(t.Address)
	if err != nil {
		return err
	}
	u.Path, _ = url.JoinPath(u.Path, "/api/zones/records/delete")
	q := u.Query()
	q.Set("token", t.Token)
	q.Set("domain", domain)
	q.Set("zone", t.Zone)
	q.Set("type", recordType)
	q.Set("ipAddress", ip)
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
