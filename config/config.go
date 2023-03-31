package config

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/xeipuuv/gojsonschema"
)

//go:embed schema.json
var configSchema []byte

type Credential struct {
	Provider    string          `json:"provider"`
	RawSettings json.RawMessage `json:"settings"`
	//Service     ddns.DDNSService `json:"-"`
}

type Task struct {
	Name         string              `json:"name"`
	Subnets      []string            `json:"subnets"`
	MACAddresses []net.HardwareAddr  `json:"mac_address"`
	Endpoints    map[string][]string `json:"endpoints"`
}

type Config struct {
	Tasks       map[string]Task       `json:"tasks"`
	Credentials map[string]Credential `json:"credentials"`
}

func (task *Task) UnmarshalJSON(data []byte) error {
	type Alias Task
	aux := &struct {
		MACAddresses []string `json:"mac_address"`
		*Alias
	}{
		Alias: (*Alias)(task),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	task.MACAddresses = make([]net.HardwareAddr, len(aux.MACAddresses))
	for i, macAddress := range aux.MACAddresses {
		parsedMAC, err := net.ParseMAC(macAddress)
		if err != nil {
			return fmt.Errorf("error parsing MAC address: %v", err)
		}
		task.MACAddresses[i] = parsedMAC
	}

	return nil
}

func (config *Config) PrettyPrint(tabSize int) string {
	indent := func(level int) string {
		return strings.Repeat(" ", level*tabSize)
	}

	var result strings.Builder
	result.WriteString("Config:\n")

	result.WriteString(indent(1) + "Tasks:\n")

	// Sort task names
	taskNames := make([]string, 0, len(config.Tasks))
	for name := range config.Tasks {
		taskNames = append(taskNames, name)
	}
	sort.Strings(taskNames)

	// Iterate over sorted tasks
	for _, name := range taskNames {
		task := config.Tasks[name]
		result.WriteString(indent(2) + name + ":\n")
		macAddresses := make([]string, len(task.MACAddresses))
		for i, mac := range task.MACAddresses {
			macAddresses[i] = mac.String()
		}
		result.WriteString(indent(3) + "MAC Addresses: " + strings.Join(macAddresses, ", ") + "\n")
		result.WriteString(indent(3) + "Subnets: " + strings.Join(task.Subnets, ", ") + "\n")
		result.WriteString(indent(3) + "Domains:\n")

		// Sort endpoint keys
		endpointKeys := make([]string, 0, len(task.Endpoints))
		for endpoint := range task.Endpoints {
			endpointKeys = append(endpointKeys, endpoint)
		}
		sort.Strings(endpointKeys)

		// Iterate over sorted endpoints
		for _, endpoint := range endpointKeys {
			domains := task.Endpoints[endpoint]

			// Sort domain names
			sortedDomainNames := make([]string, len(domains))
			copy(sortedDomainNames, domains)
			sort.Strings(sortedDomainNames)

			// Iterate over sorted domain names
			for _, domainName := range sortedDomainNames {
				result.WriteString(indent(4) + domainName + " (" + endpoint + ")\n")
			}
		}
	}

	result.WriteString(indent(1) + "Credentials:\n")

	// Sort credential aliases
	credentialAliases := make([]string, 0, len(config.Credentials))
	for alias := range config.Credentials {
		credentialAliases = append(credentialAliases, alias)
	}
	sort.Strings(credentialAliases)

	// Iterate over sorted credentials
	for _, alias := range credentialAliases {
		credential := config.Credentials[alias]
		result.WriteString(indent(2) + "Endpoint: " + alias + ":\n")
		result.WriteString(indent(3) + "Provider: " + credential.Provider + "\n")
		result.WriteString(indent(3) + "Settings: ")
		by, _ := json.MarshalIndent(credential.RawSettings, indent(4), "    ")
		result.Write(by)
		result.WriteString("\n")
	}

	return result.String()
}

func validateConfig(configFile string) {
	schemaLoader := gojsonschema.NewBytesLoader(configSchema)
	dataLoader := gojsonschema.NewReferenceLoader("file://" + configFile)

	result, err := gojsonschema.Validate(schemaLoader, dataLoader)
	if err != nil {
		panic(err.Error())
	}

	if !result.Valid() {
		fmt.Printf("The JSON data is NOT valid. Errors:\n")
		for _, desc := range result.Errors() {
			fmt.Printf("- %s\n", desc)
		}
		os.Exit(1)
	}
}

func NewConfig(filename string) *Config {
	validateConfig(filename)

	jsonFile, err := os.Open(filename)
	if err != nil {
		fmt.Println(err)
	}
	defer jsonFile.Close()

	byteValue, _ := io.ReadAll(jsonFile)

	var config Config
	json.Unmarshal(byteValue, &config)

	return &config
}
