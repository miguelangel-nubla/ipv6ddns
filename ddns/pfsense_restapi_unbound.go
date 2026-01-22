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
	"os"
	"strings"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/xeipuuv/gojsonschema"
)

type PfsenseRestapiUnbound struct {
	Address        string        `json:"address"`
	TLSFingerprint string        `json:"tls_fingerprint"`
	Key            string        `json:"key"`
	Zone           string        `json:"zone"`
	TTL            time.Duration `json:"ttl"`
}

func init() {
	RegisterProvider("pfsense_restapi_unbound", NewPfsenseRestapiUnbound)
}

func NewPfsenseRestapiUnbound(settings ProviderSettings) Service {
	var service PfsenseRestapiUnbound
	pfsenseRestapiUnboundValidateConfig(settings.(json.RawMessage))
	json.Unmarshal(settings.(json.RawMessage), &service)
	return &service
}

func pfsenseRestapiUnboundValidateConfig(config json.RawMessage) {
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
			"key": {
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
			"key",
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
		fmt.Printf("PfsenseRestapiUnbound configuration is not valid.\nErrors:\n")
		for _, desc := range result.Errors() {
			fmt.Printf("- %s\n", desc)
		}
		os.Exit(1)
	}
}

func (u *PfsenseRestapiUnbound) setupClient() *http.Client {
	tlsConfig := &tls.Config{}
	tlsConfig.InsecureSkipVerify = true
	tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
		opts := x509.VerifyOptions{
			DNSName:       cs.ServerName,
			Intermediates: x509.NewCertPool(),
		}
		for _, cert := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(cert)
		}

		_, err := cs.PeerCertificates[0].Verify(opts)
		if err == nil {
			return nil
		}

		if len(cs.PeerCertificates) == 0 {
			return fmt.Errorf("certificate verification failed: no certificates presented")
		}

		leafCert := cs.PeerCertificates[0]
		hash := sha256.Sum256(leafCert.Raw)
		fp := hex.EncodeToString(hash[:])

		if u.TLSFingerprint != "" {
			if fp == u.TLSFingerprint {
				return nil
			}
			fmt.Printf("Certificate fingerprint mismatch. Expected: %s, Found: %s\n", u.TLSFingerprint, fp)
		}

		return fmt.Errorf("certificate verification failed: %w (Fingerprint: %s)", err, fp)
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 30 * time.Second,
	}
}

func (u *PfsenseRestapiUnbound) Update(hostname string, addrCollection *ipv6disc.AddrCollection) error {
	client := u.setupClient()

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
	desiredIPs := make(map[string]bool)
	for _, addr := range addrCollection.Get() {
		ip := addr.WithZone("").String()
		desiredIPs[ip] = true
	}

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

	changesMade := false

	if existingRecord == nil {
		// No existing record, add New
		if len(desiredIPSlice) > 0 {
			err := u.addOverride(client, hostPart, domainPart, desiredIPSlice)
			if err != nil {
				return fmt.Errorf("failed to add override %s: %v", fqdn, err)
			}
			changesMade = true
		}
	} else {
		// Record exists, update or delete
		idStr := fmt.Sprintf("%v", existingRecord.ID)
		if !ipsMatch(existingRecord.IP, desiredIPSlice) {
			if len(desiredIPSlice) > 0 {
				err := u.updateOverride(client, idStr, hostPart, domainPart, desiredIPSlice)
				if err != nil {
					return fmt.Errorf("failed to update override %s (ID: %s): %v", fqdn, idStr, err)
				}
				changesMade = true
			} else {
				// No IPs desired anymore, delete
				err := u.deleteOverride(client, idStr)
				if err != nil {
					fmt.Printf("Warning: failed to delete override %s (ID: %s): %v\n", fqdn, idStr, err)
				} else {
					changesMade = true
				}
			}
		}
	}

	// 4. Apply Changes if made
	if changesMade {
		if err := u.applyChanges(client); err != nil {
			return fmt.Errorf("failed to apply Unbound changes: %v", err)
		}
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
		"ttl":    fmt.Sprintf("%d", int(u.TTL.Seconds())),
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
		"ttl":    fmt.Sprintf("%d", int(u.TTL.Seconds())),
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

func (u *PfsenseRestapiUnbound) PrettyPrint(prefix string) ([]byte, error) {
	return json.MarshalIndent(u, prefix, "    ")
}

func (u *PfsenseRestapiUnbound) UnmarshalJSON(b []byte) error {
	type Alias PfsenseRestapiUnbound
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

func (u *PfsenseRestapiUnbound) MarshalJSON() ([]byte, error) {
	type Alias PfsenseRestapiUnbound
	return json.Marshal(&struct {
		TTL int64 `json:"ttl"`
		*Alias
	}{
		TTL:   int64(u.TTL.Seconds()),
		Alias: (*Alias)(u),
	})
}

func (c *PfsenseRestapiUnbound) Domain(hostname string) string {
	return FQDN(hostname, c.Zone)
}
