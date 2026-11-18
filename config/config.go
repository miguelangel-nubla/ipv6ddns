package config

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/miguelangel-nubla/ipv6disc/pkg/plugins"
	"github.com/xeipuuv/gojsonschema"
	"sigs.k8s.io/yaml"
)

//go:embed schema.json
var configSchema []byte

type Config struct {
	BaseDir     string                `json:"-"`
	Tasks       map[string]Task       `json:"tasks"`
	Credentials map[string]Credential `json:"credentials"`
	Discovery   Discovery             `json:"discovery"`
}

type Discovery struct {
	Listen bool `json:"listen"`
	Active bool `json:"active"`
	// Ask for the EUI-64 addresses the task filters want, rather than wait to see them.
	SolicitEUI64 bool                    `json:"solicit_eui64"`
	Plugins      map[string]PluginConfig `json:"plugins"`
}

// PluginConfig is a discovery plugin: its params in one string, as ipv6disc takes them, or in
// fields.
type PluginConfig struct {
	Type   string `json:"type"`
	Params string `json:"params,omitempty"`

	Interval string `json:"interval,omitempty"`
	Address  string `json:"address,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	// linux and freebsd.
	IdentityFile string `json:"identity_file,omitempty"`
	HostKey      string `json:"host_key,omitempty"`
	// mikrotik.
	UseTLS         bool   `json:"use_tls,omitempty"`
	TLSFingerprint string `json:"tls_fingerprint,omitempty"`
}

// PluginParams returns the params of the plugin in one string, for plugins.Create: its fields
// joined, escaped so that any value can hold a comma.
func (p PluginConfig) PluginParams() (string, error) {
	if p.Params != "" {
		return p.Params, nil
	}
	var values []string
	switch p.Type {
	case "linux", "freebsd":
		if p.UseTLS || p.TLSFingerprint != "" {
			return "", fmt.Errorf("a %s plugin has no use_tls or tls_fingerprint: they are mikrotik's", p.Type)
		}
		values = []string{p.Interval, p.Address, p.Username, p.Password, p.IdentityFile, p.HostKey}
	case "mikrotik":
		if p.IdentityFile != "" || p.HostKey != "" {
			return "", fmt.Errorf("a mikrotik plugin has no identity_file or host_key: they are linux's and freebsd's")
		}
		values = []string{p.Interval, p.Address, p.Username, p.Password, "", p.TLSFingerprint}
		if p.UseTLS {
			values[4] = "true"
		}
	default:
		return "", fmt.Errorf("unknown plugin type %s", p.Type)
	}
	// The optional values last: those left empty are left out.
	for len(values) > 4 && values[len(values)-1] == "" {
		values = values[:len(values)-1]
	}
	return plugins.JoinParams(values...), nil
}

func (c *Config) PrettyPrint(prefix string, hideSensible bool) string {
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
			result.WriteString(task.IPv4.PrettyPrint(prefix+"            ", hideSensible))
		}

		for _, filter := range task.Filters {
			result.WriteString(prefix + "            - Filter Set:\n")
			if filter.MAC.Address != "" || len(filter.MAC.Mask) > 0 || len(filter.MAC.Type) > 0 {
				result.WriteString(prefix + "                MAC:\n")
				if filter.MAC.Address != "" {
					result.WriteString(prefix + "                    Address: " + filter.MAC.Address + "\n")
				}
				if len(filter.MAC.Mask) > 0 {
					result.WriteString(prefix + "                    Mask: " + strings.Join(filter.MAC.Mask, ", ") + "\n")
				}
				if len(filter.MAC.Type) > 0 {
					result.WriteString(prefix + "                    Type: " + strings.Join(filter.MAC.Type, ", ") + "\n")
				}
			}

			if filter.IP.Prefix.IsValid() || filter.IP.Suffix != "" || len(filter.IP.Mask) > 0 || len(filter.IP.Type) > 0 {
				result.WriteString(prefix + "                IP:\n")
				if filter.IP.Prefix.IsValid() {
					result.WriteString(prefix + "                    Prefix: " + filter.IP.Prefix.String() + "\n")
				}
				if filter.IP.Suffix != "" {
					result.WriteString(prefix + "                    Suffix: " + filter.IP.Suffix + "\n")
				}
				if len(filter.IP.Mask) > 0 {
					result.WriteString(prefix + "                    Mask: " + strings.Join(filter.IP.Mask, ", ") + "\n")
				}
				if len(filter.IP.Type) > 0 {
					result.WriteString(prefix + "                    Type: " + strings.Join(filter.IP.Type, ", ") + "\n")
				}
			}

			if len(filter.Source) > 0 {
				result.WriteString(prefix + "                Source: " + strings.Join(filter.Source, ", ") + "\n")
			}
		}

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
				if hostname == "" {
					hostname = "@"
				}
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
		if hideSensible {
			result.WriteString("<sensible data hidden>\n")
		} else {
			bytes, _ := json.MarshalIndent(credential.RawSettings, "            ", "    ")
			result.Write(bytes)
			result.WriteString("\n")
		}
	}

	result.WriteString(prefix + "    Discovery:\n")
	result.WriteString(prefix + "        Listen: " + fmt.Sprintf("%t", c.Discovery.Listen) + "\n")
	result.WriteString(prefix + "        Active: " + fmt.Sprintf("%t", c.Discovery.Active) + "\n")
	result.WriteString(prefix + "        Solicit EUI-64: " + fmt.Sprintf("%t", c.Discovery.SolicitEUI64) + "\n")
	if len(c.Discovery.Plugins) > 0 {
		result.WriteString(prefix + "        Plugins:\n")

		// Sort plugin keys
		pluginKeys := make([]string, 0, len(c.Discovery.Plugins))
		for k := range c.Discovery.Plugins {
			pluginKeys = append(pluginKeys, k)
		}
		sort.Strings(pluginKeys)

		for _, name := range pluginKeys {
			plugin := c.Discovery.Plugins[name]
			result.WriteString(prefix + "            " + name + ":\n")
			result.WriteString(prefix + "                Type: " + plugin.Type + "\n")
			if !hideSensible {
				params, err := plugin.PluginParams()
				if err != nil {
					params = err.Error()
				}
				result.WriteString(prefix + "                Params: " + params + "\n")
			} else {
				result.WriteString(prefix + "                Params: <sensible data hidden>\n")
			}
		}
	}

	return result.String()
}

func validateConfig(configData []byte) error {
	result, err := gojsonschema.Validate(gojsonschema.NewBytesLoader(configSchema), gojsonschema.NewBytesLoader(configData))
	if err != nil {
		return err
	}

	if !result.Valid() {
		var errs strings.Builder
		errs.WriteString("the configuration is not valid:")
		for _, desc := range result.Errors() {
			fmt.Fprintf(&errs, "\n- %s", desc)
		}
		return errors.New(errs.String())
	}
	return nil
}

func NewConfig(filename string) (config Config, err error) {
	byteValue, err := os.ReadFile(filename)
	if err != nil {
		return config, err
	}

	if strings.HasSuffix(filename, ".yaml") || strings.HasSuffix(filename, ".yml") {
		byteValue, err = yaml.YAMLToJSON(byteValue)
		if err != nil {
			return config, err
		}
	}

	byteValue, err = expandSecrets(byteValue, filepath.Dir(filename))
	if err != nil {
		return config, err
	}

	if err := validateConfig(byteValue); err != nil {
		return config, err
	}

	// Set defaults
	config.Discovery.Listen = true
	config.Discovery.Active = true

	if err := json.Unmarshal(byteValue, &config); err != nil {
		return config, err
	}

	for name, plugin := range config.Discovery.Plugins {
		if _, err := plugin.PluginParams(); err != nil {
			return config, fmt.Errorf("plugin %s: %w", name, err)
		}
	}

	for name, task := range config.Tasks {
		task.Name = name
		config.Tasks[name] = task
		for endpoint := range task.Endpoints {
			if _, ok := config.Credentials[endpoint]; !ok {
				return config, fmt.Errorf("task %s: no credential %s for its endpoint", name, endpoint)
			}
		}
	}

	config.BaseDir = filepath.Dir(filename)

	return config, nil
}
