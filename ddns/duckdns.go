package ddns

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/xeipuuv/gojsonschema"
)

type DuckDNS struct {
	APIToken string `json:"api_token"`
}

func init() {
	RegisterProvider("duckdns", NewDuckDNS)
}

func NewDuckDNS(settings ProviderSettings) Service {
	var service DuckDNS
	duckDNSValidateConfig(settings.(json.RawMessage))
	json.Unmarshal(settings.(json.RawMessage), &service)
	return &service
}

func duckDNSValidateConfig(config json.RawMessage) {
	var configSchema = []byte(`
	{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "object",
		"properties": {
			"api_token": {
				"type": "string",
				"pattern": "^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$"
			}
		},
		"required": [
			"api_token"
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
		fmt.Printf("DuckDNS configuration is not valid.\nErrors:\n")
		for _, desc := range result.Errors() {
			fmt.Printf("- %s\n", desc)
		}
		os.Exit(1)
	}
}

func (d *DuckDNS) Update(hostname string, addrCollection *ipv6disc.AddrCollection) error {
	v4 := addrCollection.Filter4().Get()
	var ipv4 string
	if len(v4) == 0 {
		ipv4 = ""
	} else {
		ipv4 = v4[0].String()
	}
	v6 := addrCollection.Filter6().Get()
	var ipv6 string
	if len(v6) == 0 {
		ipv6 = ""
	} else {
		ipv6 = v6[0].WithZone("").String()
	}

	baseURL := "https://www.duckdns.org/update"
	params := url.Values{}
	params.Add("token", d.APIToken)
	params.Add("domains", hostname)
	params.Add("ip", ipv4)
	params.Add("ipv6", ipv6)

	updateURL := fmt.Sprintf("%s?%s", baseURL, params.Encode())
	resp, err := http.Get(updateURL)
	if err != nil {
		return fmt.Errorf("failed to update record: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received non-200 status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	responseBody := string(body)
	if responseBody != "OK" {
		return fmt.Errorf("response body does not contain 'OK': %s", responseBody)
	}

	return nil
}

func (d *DuckDNS) PrettyPrint(prefix string) ([]byte, error) {
	return json.MarshalIndent(d, prefix, "    ")
}

func (d *DuckDNS) Domain(hostname string) string {
	return FQDN(hostname, "duckdns.org")
}
