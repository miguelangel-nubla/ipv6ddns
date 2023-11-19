package ddns

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/xeipuuv/gojsonschema"
)

type Dummy struct{}

func init() {
	RegisterProvider("dummy", NewDummy)
}

func NewDummy(settings ProviderSettings) Service {
	var service Dummy
	DummyValidateConfig(settings.(json.RawMessage))
	json.Unmarshal(settings.(json.RawMessage), &service)
	return &service
}

func DummyValidateConfig(config json.RawMessage) {
	var configSchema = []byte(`
	{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "object",
		"properties": {
			"domain": {
				"type": "string",
				"format": "hostname"
			}
		},
		"required": [
			"domain"
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
		fmt.Printf("Dummy configuration is not valid.\nErrors:\n")
		for _, desc := range result.Errors() {
			fmt.Printf("- %s\n", desc)
		}
		os.Exit(1)
	}
}

func (d *Dummy) Update(domain string, hosts []string) error {
	fmt.Printf("Dummy: Update %s with %v\n", domain, hosts)
	// TODO: Implement dummy update
	return nil
}

func (d *Dummy) PrettyPrint(prefix string) ([]byte, error) {
	return json.MarshalIndent(d, prefix, "    ")
}
