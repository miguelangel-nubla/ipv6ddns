package ddns

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/xeipuuv/gojsonschema"
)

type OpnsenseUnbound struct {
	Address        string        `json:"address"`
	Key            string        `json:"key"`
	Secret         string        `json:"secret"`
	Zone           string        `json:"zone"`
	TTL            time.Duration `json:"ttl"`
	TLSFingerprint string        `json:"tls_fingerprint"`
}

func init() {
	RegisterProvider("opnsense_unbound", NewOpnsenseUnbound)
}

func NewOpnsenseUnbound(settings ProviderSettings) Service {
	var service OpnsenseUnbound
	opnsenseUnboundValidateConfig(settings.(json.RawMessage))
	json.Unmarshal(settings.(json.RawMessage), &service)
	return &service
}

func opnsenseUnboundValidateConfig(config json.RawMessage) {
	var configSchema = []byte(`
	{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "object",
		"properties": {
			"address": {
				"type": "string",
				"minLength": 1
			},
			"key": {
				"type": "string",
				"minLength": 1
			},
			"secret": {
				"type": "string",
				"minLength": 1
			},
			"zone": {
				"type": "string"
			},
			"ttl": {
				"type": "string",
				"pattern": "^([0-9]+(\\.[0-9]+)?(ns|us|µs|ms|s|m|h))+$"
			},
			"tls_fingerprint": {
				"type": "string",
				"pattern": "^[a-fA-F0-9]{64}$"
			}
		},
		"required": [
			"address",
			"key",
			"secret",
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
		fmt.Printf("OpnsenseUnbound configuration is not valid.\nErrors:\n")
		for _, desc := range result.Errors() {
			fmt.Printf("- %s\n", desc)
		}
		os.Exit(1)
	}
}

func (u *OpnsenseUnbound) Update(hostname string, addrCollection *ipv6disc.AddrCollection) error {
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
		if u.TLSFingerprint != "" {
			if fp == u.TLSFingerprint {
				// Fingerprint matched
				return nil
			}
			fmt.Printf("Certificate fingerprint mismatch. Expected: %s, Found: %s\n", u.TLSFingerprint, fp)
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

	// 1. Fetch existing Host Overrides
	existingOverrides, err := u.getOverrides(client)
	if err != nil {
		return fmt.Errorf("failed to fetch existing Host Overrides: %v", err)
	}

	fqdn := FQDN(hostname, u.Zone)
	desiredIPs := make(map[string]bool)
	for _, addr := range addrCollection.Get() {
		ip := addr.WithZone("").String()
		desiredIPs[ip] = true
	}

	// Filter existing overrides for this FQDN
	hostPart, domainPart := SplitFQDN(fqdn)

	currentIPs := make(map[string][]string) // IP -> list of UUIDs
	for _, row := range existingOverrides {
		if row.Hostname == hostPart && row.Domain == domainPart {
			upperRR := strings.ToUpper(row.RR)
			if upperRR == "AAAA" || upperRR == "A" {
				currentIPs[row.Server] = append(currentIPs[row.Server], row.UUID)
			}
		}
	}

	changesMade := false

	// 2. Manage IPs
	// Add missing IPs and clean up duplicates for existing ones
	for ip := range desiredIPs {
		uuids, exists := currentIPs[ip]
		if !exists {
			err := u.addOverride(client, hostPart, domainPart, ip)
			if err != nil {
				return fmt.Errorf("failed to add override %s -> %s: %v", fqdn, ip, err)
			}
			changesMade = true
		} else if len(uuids) > 1 {
			// Duplicate records exist for this IP, remove extra ones
			for i := 1; i < len(uuids); i++ {
				err := u.deleteOverride(client, uuids[i])
				if err != nil {
					fmt.Printf("Warning: failed to delete duplicate override %s -> %s (UUID: %s): %v\n", fqdn, ip, uuids[i], err)
				} else {
					changesMade = true
				}
			}
		}
	}

	// 3. Remove obsolete IPs
	for ip, uuids := range currentIPs {
		if _, keep := desiredIPs[ip]; !keep {
			for _, uuid := range uuids {
				err := u.deleteOverride(client, uuid)
				if err != nil {
					return fmt.Errorf("failed to delete override %s -> %s: %v", fqdn, ip, err)
				}
				changesMade = true
			}
		}
	}

	// 4. Trigger Reconfigure if changes made
	if changesMade {
		if err := u.reconfigure(client); err != nil {
			return fmt.Errorf("failed to reconfigure Unbound: %v", err)
		}
	}

	return nil
}

// Helper types for OPNsense API
type unboundOverrideRow struct {
	UUID        string `json:"uuid"`
	Enabled     string `json:"enabled"`
	Hostname    string `json:"hostname"`
	Domain      string `json:"domain"`
	RR          string `json:"rr"`     // a, aaaa, mx
	Server      string `json:"server"` // This is the IP address
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

	fmt.Printf("getOverrides found %d rows\n", len(searchResp.Rows))
	for _, row := range searchResp.Rows {
		fmt.Printf("  Row: UUID=%s, Hostname=%s, Domain=%s, RR=%s, Server=%s\n", row.UUID, row.Hostname, row.Domain, row.RR, row.Server)
	}

	return searchResp.Rows, nil
}

func (u *OpnsenseUnbound) addOverride(client *http.Client, hostname, domain, ip string) error {
	url := fmt.Sprintf("%s/api/unbound/settings/addHostOverride", strings.TrimRight(u.Address, "/"))

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
	fmt.Printf("addHostOverride response: %s\n", string(body))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var apiResp opnsenseResponse
	if err := json.Unmarshal(body, &apiResp); err == nil {
		if apiResp.Result != "saved" && apiResp.Result != "deleted" && apiResp.Status != "ok" {
			return fmt.Errorf("addHostOverride failed: %s", string(body))
		}
	} else {
		return fmt.Errorf("addHostOverride failed to parse response: %s", string(body))
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
	fmt.Printf("delHostOverride response: %s\n", string(body))
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

	fmt.Printf("reconfigure response: %s\n", string(body))

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

func (u *OpnsenseUnbound) PrettyPrint(prefix string) ([]byte, error) {
	return json.MarshalIndent(u, prefix, "    ")
}

func (u *OpnsenseUnbound) UnmarshalJSON(b []byte) error {
	type Alias OpnsenseUnbound
	aux := &struct {
		TTL interface{} `json:"ttl"`
		*Alias
	}{
		Alias: (*Alias)(u),
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}

	switch value := aux.TTL.(type) {
	case float64:
		u.TTL = time.Duration(value) * time.Second
		return nil
	case string:
		var err error
		u.TTL, err = time.ParseDuration(value)
		if err != nil {
			return err
		}
		return nil
	default:
		return fmt.Errorf("ttl invalid duration: %v", aux.TTL)
	}
}

func (u *OpnsenseUnbound) MarshalJSON() ([]byte, error) {
	type Alias OpnsenseUnbound
	return json.Marshal(&struct {
		TTL int64 `json:"ttl"`
		*Alias
	}{
		TTL:   int64(u.TTL.Seconds()),
		Alias: (*Alias)(u),
	})
}

func (c *OpnsenseUnbound) Domain(hostname string) string {
	return FQDN(hostname, c.Zone)
}
