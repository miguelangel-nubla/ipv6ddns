package ddns

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/xeipuuv/gojsonschema"
)

type Technitium struct {
	Address        string        `json:"address"`
	TLSFingerprint string        `json:"tls_fingerprint"`
	Token          string        `json:"token"`
	Zone           string        `json:"zone"`
	TTL            time.Duration `json:"ttl"`
}

func init() {
	RegisterProvider("technitium", NewTechnitium)
}

func NewTechnitium(settings ProviderSettings) Service {
	var service Technitium
	technitiumValidateConfig(settings.(json.RawMessage))
	json.Unmarshal(settings.(json.RawMessage), &service)
	return &service
}

func technitiumValidateConfig(config json.RawMessage) {
	var configSchema = []byte(`
	{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "object",
		"properties": {
			"address": {
				"type": "string",
				"minLength": 1
			},
			"tls_fingerprint": {
				"type": "string",
				"pattern": "^[a-fA-F0-9]{64}$"
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
	`)

	schemaLoader := gojsonschema.NewBytesLoader(configSchema)
	dataLoader := gojsonschema.NewBytesLoader([]byte(config))

	result, err := gojsonschema.Validate(schemaLoader, dataLoader)
	if err != nil {
		panic(err.Error())
	}

	if !result.Valid() {
		fmt.Printf("Technitium configuration is not valid.\nErrors:\n")
		for _, desc := range result.Errors() {
			fmt.Printf("- %s\n", desc)
		}
		os.Exit(1)
	}
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
	tlsConfig := &tls.Config{}

	// Use custom verification to support fallback to fingerprint
	tlsConfig.InsecureSkipVerify = true
	tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
		// 1. Try standard certificate verification first
		opts := x509.VerifyOptions{
			DNSName:       cs.ServerName,
			Intermediates: x509.NewCertPool(),
		}
		for _, cert := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(cert)
		}

		_, err := cs.PeerCertificates[0].Verify(opts)
		if err == nil {
			// Standard validation succeeded
			return nil
		}

		// 2. If standard verification failed, calculate fingerprint for the leaf certificate (first in chain)
		if len(cs.PeerCertificates) == 0 {
			return fmt.Errorf("certificate verification failed: no certificates presented")
		}

		leafCert := cs.PeerCertificates[0]
		hash := sha256.Sum256(leafCert.Raw)
		fp := hex.EncodeToString(hash[:])

		// 3. If tls_fingerprint is provided, check if it matches
		if t.TLSFingerprint != "" {
			if fp == t.TLSFingerprint {
				// Fingerprint matched
				return nil
			}
			fmt.Printf("Certificate fingerprint mismatch. Expected: %s, Found: %s\n", t.TLSFingerprint, fp)
		}

		// Both methods failed
		return fmt.Errorf("certificate verification failed: %w (Fingerprint: %s)", err, fp)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 30 * time.Second,
	}

	fqdn := FQDN(hostname, t.Zone)

	// 1. Get current records
	currentIPs, err := t.getRecords(client, fqdn)
	if err != nil {
		return fmt.Errorf("failed to get records: %v", err)
	}

	// 2. Identify desired IPs
	desiredIPs := make(map[string]string) // IP -> Type("A" or "AAAA")
	for _, addr := range addrCollection.Get() {
		recordType := "AAAA"
		if addr.Addr.Is4() {
			recordType = "A"
		}
		ip := addr.WithZone("").String()
		desiredIPs[ip] = recordType
	}

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
		} else {
			// Optional: Update TTL if needed.
			// Current implementation simplifies by only adding missing ones.
			// To strictly enforce TTL, we could call updateRecord here.
			// Let's stick to add/delete for now unless we track TTL in currentIPs.
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
		return nil, err
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
				if _, err := netip.ParseAddr(rData.IPAddress); err == nil {
					currentIPs[rData.IPAddress] = rec.Type
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
		return err
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
		return err
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

func (t *Technitium) PrettyPrint(prefix string) ([]byte, error) {
	return json.MarshalIndent(t, prefix, "    ")
}

func (t *Technitium) UnmarshalJSON(b []byte) error {
	type Alias Technitium
	aux := &struct {
		TTL interface{} `json:"ttl"`
		*Alias
	}{
		Alias: (*Alias)(t),
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}

	switch value := aux.TTL.(type) {
	case float64:
		t.TTL = time.Duration(value) * time.Second
		return nil
	case string:
		var err error
		t.TTL, err = time.ParseDuration(value)
		if err != nil {
			return err
		}
		return nil
	default:
		return errors.New("ttl invalid duration")
	}
}

func (t *Technitium) MarshalJSON() ([]byte, error) {
	type Alias Technitium
	return json.Marshal(&struct {
		TTL int64 `json:"ttl"`
		*Alias
	}{
		TTL:   int64(t.TTL.Seconds()),
		Alias: (*Alias)(t),
	})
}

func (t *Technitium) Domain(hostname string) string {
	return FQDN(hostname, t.Zone)
}
