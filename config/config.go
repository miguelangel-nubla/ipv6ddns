package config

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
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

func (config *Config) PrettyPrint(prefix string) string {
	var result strings.Builder

	fmt.Fprintf(&result, "%sConfig:\n", prefix)
	fmt.Fprintf(&result, "%s    Tasks:\n", prefix)

	// Sort task names
	taskNames := make([]string, 0, len(config.Tasks))
	for name := range config.Tasks {
		taskNames = append(taskNames, name)
	}
	sort.Strings(taskNames)

	// Iterate over sorted tasks
	for _, name := range taskNames {
		task := config.Tasks[name]
		result.WriteString(prefix + "        " + name + ":\n")
		macAddresses := make([]string, len(task.MACAddresses))
		for i, mac := range task.MACAddresses {
			macAddresses[i] = mac.String()
		}
		result.WriteString(prefix + "            MAC Addresses: " + strings.Join(macAddresses, ", ") + "\n")
		result.WriteString(prefix + "            Subnets: " + strings.Join(task.Subnets, ", ") + "\n")
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
	credentialAliases := make([]string, 0, len(config.Credentials))
	for alias := range config.Credentials {
		credentialAliases = append(credentialAliases, alias)
	}
	sort.Strings(credentialAliases)

	// Iterate over sorted credentials
	for _, alias := range credentialAliases {
		credential := config.Credentials[alias]
		result.WriteString(prefix + "        Endpoint: " + alias + "\n")
		result.WriteString(prefix + "            Provider: " + credential.Provider + "\n")
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

func NewConfig(filename string) Config {
	validateConfig(filename)

	jsonFile, err := os.Open(filename)
	if err != nil {
		fmt.Println(err)
	}
	defer jsonFile.Close()

	byteValue, _ := io.ReadAll(jsonFile)

	var config Config
	json.Unmarshal(byteValue, &config)

	return config
}
