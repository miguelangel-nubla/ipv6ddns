package config

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/xeipuuv/gojsonschema"
)

//go:embed schema.json
var configSchema []byte

type Config struct {
	Tasks       map[string]Task       `json:"tasks"`
	Credentials map[string]Credential `json:"credentials"`
}

func (c *Config) PrettyPrint(prefix string) string {
	var result strings.Builder

	fmt.Fprintf(&result, "%sConfig:\n", prefix)
	fmt.Fprintf(&result, "%s    Tasks:\n", prefix)

	// Sort task names
	taskNames := make([]string, 0, len(c.Tasks))
	for name := range c.Tasks {
		taskNames = append(taskNames, name)
	}
	sort.Strings(taskNames)

	// Iterate over sorted tasks
	for _, name := range taskNames {
		task := c.Tasks[name]
		result.WriteString(prefix + "        " + name + ":\n")

		if task.IPv4 != nil {
			result.WriteString(task.IPv4.PrettyPrint(prefix + "            "))
		}

		macAddresses := make([]string, len(task.MACAddresses))
		for i, mac := range task.MACAddresses {
			macAddresses[i] = mac.String()
		}
		result.WriteString(prefix + "            MAC Addresses: " + strings.Join(macAddresses, ", ") + "\n")
		subnets := make([]string, len(task.Subnets))
		for i, subnet := range task.Subnets {
			subnets[i] = subnet.String()
		}
		result.WriteString(prefix + "            Subnets: " + strings.Join(subnets, ", ") + "\n")
		result.WriteString(prefix + "            Hostnames:\n")

		// Sort endpoint keys
		endpointKeys := make([]string, 0, len(task.Endpoints))
		for endpoint := range task.Endpoints {
			endpointKeys = append(endpointKeys, endpoint)
		}
		sort.Strings(endpointKeys)

		// Iterate over sorted endpoints
		for _, endpointKey := range endpointKeys {
			hostnames := task.Endpoints[endpointKey]

			// Sort hostnames
			sortedHostnames := make([]string, len(hostnames))
			copy(sortedHostnames, hostnames)
			sort.Strings(sortedHostnames)

			// Iterate over sorted hostnames
			for _, hostname := range sortedHostnames {
				result.WriteString(prefix + "                " + hostname + " (" + endpointKey + ")\n")
			}
		}
	}

	result.WriteString(prefix + "    Credentials:\n")

	// Sort credential aliases
	credentialAliases := make([]string, 0, len(c.Credentials))
	for alias := range c.Credentials {
		credentialAliases = append(credentialAliases, alias)
	}
	sort.Strings(credentialAliases)

	// Iterate over sorted credentials
	for _, alias := range credentialAliases {
		credential := c.Credentials[alias]
		result.WriteString(prefix + "        Endpoint: " + alias + "\n")
		result.WriteString(prefix + "            Provider: " + credential.Provider + "\n")
		result.WriteString(prefix + "            Debounce time: " + credential.DebounceTime.String() + "\n")
		result.WriteString(prefix + "            Settings: ")
		bytes, _ := json.MarshalIndent(credential.RawSettings, "            ", "    ")
		result.Write(bytes)
		result.WriteString("\n")
	}

	return result.String()
}

func validateConfig(configFile string) {
	schemaLoader := gojsonschema.NewBytesLoader(configSchema)
	dataLoader := gojsonschema.NewReferenceLoader("file://" + configFile)

	result, err := gojsonschema.Validate(schemaLoader, dataLoader)
	if err != nil {
		log.Fatal(err.Error())
	}

	if !result.Valid() {
		fmt.Printf("The JSON data is NOT valid. Errors:\n")
		for _, desc := range result.Errors() {
			fmt.Printf("- %s\n", desc)
		}
		os.Exit(1)
	}
}

func NewConfig(filename string) (config Config, err error) {
	validateConfig(filename)

	jsonFile, err := os.Open(filename)
	if err != nil {
		fmt.Println(err)
	}
	defer jsonFile.Close()

	byteValue, _ := io.ReadAll(jsonFile)
	err = json.Unmarshal(byteValue, &config)
	return config, err
}
