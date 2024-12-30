package ddns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cloudflare/cloudflare-go"
	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/xeipuuv/gojsonschema"
)

type Cloudflare struct {
	APIToken string        `json:"api_token"`
	Zone     string        `json:"zone"`
	TTL      time.Duration `json:"ttl"`
	Proxied  bool          `json:"proxied"`
}

func init() {
	RegisterProvider("cloudflare", NewCloudflare)
}

func NewCloudflare(settings ProviderSettings) Service {
	var service Cloudflare
	cloudflareValidateConfig(settings.(json.RawMessage))
	json.Unmarshal(settings.(json.RawMessage), &service)
	return &service
}

func cloudflareValidateConfig(config json.RawMessage) {
	var configSchema = []byte(`
	{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "object",
		"properties": {
			"api_token": {
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
			},
			"proxied": {
				"type": "boolean"
			}
		},
		"required": [
			"api_token",
			"zone",
			"ttl",
			"proxied"
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
		fmt.Printf("Cloudflare configuration is not valid.\nErrors:\n")
		for _, desc := range result.Errors() {
			fmt.Printf("- %s\n", desc)
		}
		os.Exit(1)
	}
}

func (c *Cloudflare) Update(hostname string, addrCollection *ipv6disc.AddrCollection) error {
	// Initialize the Cloudflare API with the provided API token
	api, err := cloudflare.NewWithAPIToken(c.APIToken)
	if err != nil {
		return fmt.Errorf("failed to initialize: %v", err)
	}

	// Get Zone ID
	zoneID, err := api.ZoneIDByName(c.Zone)
	if err != nil {
		return fmt.Errorf("failed to read zone ID: %v", err)
	}

	// Create a new *ResourceContainer for the zone
	rc := cloudflare.ZoneIdentifier(zoneID)

	// Get current DNS records from Cloudflare
	params := cloudflare.ListDNSRecordsParams{
		Name: c.Domain(hostname),
	}
	currentRecords, _, err := api.ListDNSRecords(context.Background(), rc, params)
	if err != nil {
		return fmt.Errorf("failed to list DNS records for %s: %s", hostname, err)
	}

	// Build a set of current IP addresses in Cloudflare
	currentIPs := make(map[string]string)
	for _, record := range currentRecords {
		if record.Type == "AAAA" || record.Type == "A" {
			currentIPs[record.Content] = record.Type
		}
	}

	// Build a set of desired IP addresses
	desiredIPs := make(map[string]string)
	for _, addr := range addrCollection.Get() {
		recordType := "AAAA"
		if addr.Addr.Is4() {
			recordType = "A"
		}
		desiredIPs[addr.WithZone("").String()] = recordType
	}

	// Create records as necessary
	for ip, recordType := range desiredIPs {
		_, exists := currentIPs[ip]
		if !exists {
			newRecord := cloudflare.CreateDNSRecordParams{
				Type:    recordType,
				Name:    c.Domain(hostname),
				Content: ip,
				TTL:     int(c.TTL.Seconds()),
				Proxied: &c.Proxied,
			}
			_, err := api.CreateDNSRecord(context.Background(), rc, newRecord)
			if err != nil {
				return fmt.Errorf("failed to create %s DNS record for %s: %v", hostname, ip, err)
			}
		}
	}

	// Update or delete records as necessary
	for _, record := range currentRecords {
		if record.Type != "AAAA" && record.Type != "A" {
			continue
		}

		ip := record.Content
		_, exists := desiredIPs[ip]
		if !exists {
			err := api.DeleteDNSRecord(context.Background(), rc, record.ID)
			if err != nil {
				return fmt.Errorf("failed to delete %s DNS record for %s: %v", hostname, ip, err)
			}
		} else {
			// Update the DNS record if TTL or Proxied is different
			if record.TTL != int(c.TTL.Seconds()) || *record.Proxied != c.Proxied {
				updateRecord := cloudflare.UpdateDNSRecordParams{
					ID:      record.ID,
					TTL:     int(c.TTL.Seconds()),
					Proxied: &c.Proxied,
				}
				_, err := api.UpdateDNSRecord(context.Background(), rc, updateRecord)
				if err != nil {
					return fmt.Errorf("failed to update %s DNS record for %s: %v", hostname, ip, err)
				}
			}
		}
	}

	return nil
}

func (c *Cloudflare) PrettyPrint(prefix string) ([]byte, error) {
	return json.MarshalIndent(c, prefix, "    ")
}

func (d *Cloudflare) UnmarshalJSON(b []byte) error {
	type Alias Cloudflare
	aux := &struct {
		TTL interface{} `json:"ttl"`
		*Alias
	}{
		Alias: (*Alias)(d),
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}

	switch value := aux.TTL.(type) {
	case float64:
		d.TTL = time.Duration(value) * time.Second
		return nil
	case string:
		var err error
		d.TTL, err = time.ParseDuration(value)
		if err != nil {
			return err
		}
		return nil
	default:
		return errors.New("ttl invalid duration")
	}
}

func (d *Cloudflare) MarshalJSON() ([]byte, error) {
	type Alias Cloudflare
	return json.Marshal(&struct {
		TTL int64 `json:"ttl"`
		*Alias
	}{
		TTL:   int64(d.TTL.Seconds()),
		Alias: (*Alias)(d),
	})
}

func (c *Cloudflare) Domain(hostname string) string {
	hostname = strings.Trim(hostname, ".")
	zone := strings.Trim(c.Zone, ".")
	return strings.Join([]string{hostname, zone}, ".")
}
