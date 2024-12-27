package ddns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/ddns/gravity"
	"github.com/xeipuuv/gojsonschema"
)

type Gravity struct {
	Server   string        `json:"server"`
	APIKey   string        `json:"api_key"`
	ZoneName string        `json:"zone_name"`
	TTL      time.Duration `json:"ttl"`
}

func init() {
	RegisterProvider("gravity", NewGravity)
}

func NewGravity(settings ProviderSettings) Service {
	var service Gravity
	gravityValidateConfig(settings.(json.RawMessage))
	json.Unmarshal(settings.(json.RawMessage), &service)
	return &service
}

func gravityValidateConfig(config json.RawMessage) {
	var configSchema = []byte(`
	{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "object",
		"properties": {
			"server": {
				"type": "string",
				"minLength": 1
			},
			"api_key": {
				"type": "string",
				"minLength": 1
			},
			"zone_name": {
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
			"zone_name",
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
		fmt.Printf("Gravity configuration is not valid.\nErrors:\n")
		for _, desc := range result.Errors() {
			fmt.Printf("- %s\n", desc)
		}
		os.Exit(1)
	}
}

func (g *Gravity) Update(domain string, hosts []string) error {
	requestEditors := []gravity.RequestEditorFn{
		func(ctx context.Context, req *http.Request) error {
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", g.APIKey))
			return nil
		},
	}
	apiClient, err := gravity.NewClientWithResponses(g.Server)
	if err != nil {
		return fmt.Errorf("failed to create gravity client: %v", err)
	}

	// Get current records
	params := gravity.DnsGetRecordsParams{
		Zone:     &g.ZoneName,
		Hostname: &domain,
	}
	currentRecords, err := apiClient.DnsGetRecordsWithResponse(context.Background(), &params, requestEditors...)
	if err != nil {
		return fmt.Errorf("failed to call current records: %v", err)
	}

	if currentRecords.JSON200 == nil {
		return fmt.Errorf("failed to get current records: %v", currentRecords.Status())
	}

	// Initialize records if necessary
	if currentRecords.JSON200.Records == nil {
		records := make([]gravity.DnsAPIRecord, 0)
		currentRecords.JSON200.Records = &records
	}

	currentIPs := make(map[string]bool)

	// Build a set of current IP addresses
	for _, record := range *currentRecords.JSON200.Records {
		if record.Type == "AAAA" {
			currentIPs[record.Data] = true
		}
	}

	// Build a set of desired IP addresses
	desiredIPs := make(map[string]bool)
	for _, host := range hosts {
		desiredIPs[host] = true
	}

	// Create, update, or delete records as necessary
	for ip := range desiredIPs {
		if !currentIPs[ip] {
			// Create a new DNS record
			response, err := apiClient.DnsPutRecordsWithResponse(
				context.Background(),
				&gravity.DnsPutRecordsParams{
					Zone:     g.ZoneName,
					Hostname: domain,
				},
				gravity.DnsPutRecordsJSONRequestBody{
					Type: "AAAA",
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

	for _, record := range *currentRecords.JSON200.Records {
		ip := record.Data
		if !desiredIPs[ip] {
			// Delete the DNS record
			response, err := apiClient.DnsDeleteRecordsWithResponse(
				context.Background(),
				&gravity.DnsDeleteRecordsParams{
					Zone:     g.ZoneName,
					Hostname: domain,
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
		} else {
			// Nothing to do for now
		}
	}

	return nil
}

func (g *Gravity) PrettyPrint(prefix string) ([]byte, error) {
	return json.MarshalIndent(g, prefix, "    ")
}

func (g *Gravity) UnmarshalJSON(b []byte) error {
	type Alias Gravity
	aux := &struct {
		TTL interface{} `json:"ttl"`
		*Alias
	}{
		Alias: (*Alias)(g),
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}

	switch value := aux.TTL.(type) {
	case float64:
		g.TTL = time.Duration(value) * time.Second
		return nil
	case string:
		var err error
		g.TTL, err = time.ParseDuration(value)
		if err != nil {
			return err
		}
		return nil
	default:
		return errors.New("ttl invalid duration")
	}
}

func (g *Gravity) MarshalJSON() ([]byte, error) {
	type Alias Gravity
	return json.Marshal(&struct {
		TTL int64 `json:"ttl"`
		*Alias
	}{
		TTL:   int64(g.TTL.Seconds()),
		Alias: (*Alias)(g),
	})
}
