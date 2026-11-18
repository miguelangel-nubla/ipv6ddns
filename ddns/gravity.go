package ddns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/miguelangel-nubla/ipv6ddns/ddns/gravity"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/duration"
	"github.com/miguelangel-nubla/ipv6disc"
)

type Gravity struct {
	Server string `json:"server"`
	APIKey string `json:"api_key"`
	Zone   string `json:"zone"`
	// Gravity has no TTL per record: it is read for the schema, and unused.
	TTL duration.Duration `json:"ttl"`
}

func init() {
	RegisterProvider("gravity", NewGravity)
}

func NewGravity(settings json.RawMessage) (Service, error) {
	var service Gravity
	if err := decodeSettings(settings, gravitySettingsSchema, &service); err != nil {
		return nil, err
	}
	return &service, nil
}

const gravitySettingsSchema = `
	{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "object",
		"additionalProperties": false,
		"properties": {
			"server": {
				"type": "string",
				"minLength": 1
			},
			"api_key": {
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
		    "server",
			"api_key",
			"zone",
			"ttl"
		]
	}
	`

func (g *Gravity) Update(hostname string, addrCollection *ipv6disc.AddrCollection) error {
	requestEditors := []gravity.RequestEditorFn{
		func(ctx context.Context, req *http.Request) error {
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", g.APIKey))
			return nil
		},
	}
	apiClient, err := gravity.NewClientWithResponses(g.Server, gravity.WithHTTPClient(newHTTPClient(nil)))
	if err != nil {
		return fmt.Errorf("failed to create gravity client: %v", err)
	}

	params := gravity.DnsGetRecordsParams{
		Zone:     &g.Zone,
		Hostname: &hostname,
	}
	currentRecords, err := apiClient.DnsGetRecordsWithResponse(context.Background(), &params, requestEditors...)
	if err != nil {
		return fmt.Errorf("failed to call current records: %v", err)
	}

	if currentRecords.JSON200 == nil {
		return fmt.Errorf("failed to get current records: %v", currentRecords.Status())
	}

	if currentRecords.JSON200.Records == nil {
		records := make([]gravity.DnsAPIRecord, 0)
		currentRecords.JSON200.Records = &records
	}

	// Build a set of current IP addresses
	currentIPs := make(map[string]string)
	for _, record := range *currentRecords.JSON200.Records {
		if record.Type != "AAAA" && record.Type != "A" {
			continue
		}
		ip, ok := canonicalIP(record.Data)
		if !ok {
			return fmt.Errorf("invalid existing record found: %s", record.Data)
		}
		currentIPs[ip] = record.Type
	}

	// Build a set of desired IP addresses
	desiredIPs := desiredRecords(addrCollection)

	// Create records as necessary
	for ip, recordType := range desiredIPs {
		_, exists := currentIPs[ip]
		if !exists {
			uid := uuid.New().String()
			response, err := apiClient.DnsPutRecordsWithResponse(
				context.Background(),
				&gravity.DnsPutRecordsParams{
					Zone:     g.Zone,
					Hostname: hostname,
					Uid:      &uid,
				},
				gravity.DnsPutRecordsJSONRequestBody{
					Type: recordType,
					Data: ip,
				},
				requestEditors...,
			)
			if err != nil {
				return fmt.Errorf("failed to call create DNS record: %v", err)
			}

			if response.StatusCode() < 200 || response.StatusCode() >= 300 {
				return fmt.Errorf("failed to create DNS record: %v", response.Status())
			}
		}
	}

	// Update or delete records as necessary
	for _, record := range *currentRecords.JSON200.Records {
		if record.Type != "AAAA" && record.Type != "A" {
			continue
		}

		ip, _ := canonicalIP(record.Data)
		_, exists := desiredIPs[ip]
		if !exists {
			// Delete the DNS record
			response, err := apiClient.DnsDeleteRecordsWithResponse(
				context.Background(),
				&gravity.DnsDeleteRecordsParams{
					Zone:     g.Zone,
					Hostname: hostname,
					Type:     record.Type,
					Uid:      record.Uid,
				},
				requestEditors...,
			)
			if err != nil {
				return fmt.Errorf("failed to call delete DNS record: %v", err)
			}

			if response.StatusCode() < 200 || response.StatusCode() >= 300 {
				return fmt.Errorf("failed to delete DNS record: %v", response.Status())
			}
		}
	}

	return nil
}

func (g *Gravity) Domain(hostname string) string {
	return FQDN(hostname, g.Zone)
}
