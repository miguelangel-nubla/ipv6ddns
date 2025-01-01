package config

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/xeipuuv/gojsonschema"
)

//go:embed schema.json
var configSchema []byte

type IPv4Handler struct {
	Interval time.Duration `json:"interval"`
	Command  string        `json:"command"`
	Args     []string      `json:"args"`
}

type Credential struct {
	Provider     string          `json:"provider"`
	DebounceTime time.Duration   `json:"debounce_time"`
	RetryTime    time.Duration   `json:"retry_time"`
	RawSettings  json.RawMessage `json:"settings"`
}

func (c *Credential) UnmarshalJSON(b []byte) error {
	type Alias Credential
	aux := &struct {
		DebounceTime interface{} `json:"debounce_time"`
		RetryTime    interface{} `json:"retry_time"`
		*Alias
	}{
		Alias: (*Alias)(c),
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}

	if aux.DebounceTime == nil {
		c.DebounceTime = 10 * time.Second
		return nil
	}
	if aux.RetryTime == nil {
		c.RetryTime = 60 * time.Second
		return nil
	}

	switch value := aux.DebounceTime.(type) {
	case float64:
		c.DebounceTime = time.Duration(value) * time.Second
	case string:
		var err error
		c.DebounceTime, err = time.ParseDuration(value)
		if err != nil {
			return err
		}
	default:
		return errors.New("invalid debounce time")
	}

	switch value := aux.RetryTime.(type) {
	case float64:
		c.RetryTime = time.Duration(value) * time.Second
	case string:
		var err error
		c.RetryTime, err = time.ParseDuration(value)
		if err != nil {
			return err
		}
	default:
		return errors.New("invalid retry time")
	}

	return nil
}

type Task struct {
	Name         string              `json:"name"`
	Subnets      []string            `json:"subnets"`
	MACAddresses []net.HardwareAddr  `json:"mac_address"`
	Endpoints    map[string][]string `json:"endpoints"`
	IPv4         IPv4Handler         `json:"ipv4,omitempty"`
}

type Config struct {
	Tasks       map[string]Task       `json:"tasks"`
	Credentials map[string]Credential `json:"credentials"`
}

func (t *Task) UnmarshalJSON(data []byte) error {
	type Alias Task
	aux := &struct {
		MACAddresses []string `json:"mac_address"`
		*Alias
	}{
		Alias: (*Alias)(t),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	t.MACAddresses = make([]net.HardwareAddr, len(aux.MACAddresses))
	for i, macAddress := range aux.MACAddresses {
		parsedMAC, err := net.ParseMAC(macAddress)
		if err != nil {
			return fmt.Errorf("error parsing MAC address: %v", err)
		}
		t.MACAddresses[i] = parsedMAC
	}

	return nil
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
