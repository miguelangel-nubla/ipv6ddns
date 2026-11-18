package config

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/duration"
	"github.com/miguelangel-nubla/ipv6disc/pkg/plugins"
	// The plugin types, which say their fields.
	_ "github.com/miguelangel-nubla/ipv6disc/pkg/plugins/all"
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
	Sources     map[string]Source     `json:"sources,omitempty"`

	// The settings that are flags too: a flag given wins. Lifetime is how long a discovered
	// address stays after it was last seen, unless its family says.
	Lifetime        duration.Duration `json:"lifetime"`
	LogLevel        string            `json:"log_level,omitempty"`
	WebserverListen StringList        `json:"webserver_listen,omitempty"`

	// What in the configuration to change, as a deprecated setting: NewConfig sets them, to log.
	Warnings []string `json:"-"`
}

type Discovery struct {
	// How each family is discovered. Default: IPv6 by listening and active probes, no IPv4.
	// Filters take IPv4 addresses only with ip.family 4.
	IPv6    Family                  `json:"ipv6"`
	IPv4    Family                  `json:"ipv4"`
	Plugins map[string]PluginConfig `json:"plugins"`
	// The interfaces the local discovery runs on, and those it doesn't: names or patterns, as
	// "docker*". None means all. The plugins aren't concerned.
	Interfaces        StringList `json:"interfaces,omitempty"`
	ExcludeInterfaces StringList `json:"exclude_interfaces,omitempty"`
	// How often the active discovery probes every host. Default: a third of the lifetime.
	Rediscover duration.Duration `json:"rediscover"`

	// Deprecated: ipv6.listen, ipv6.active and ipv6.solicit. NewConfig moves them there.
	Listen       *bool `json:"listen,omitempty"`
	Active       *bool `json:"active,omitempty"`
	SolicitEUI64 *bool `json:"solicit_eui64,omitempty"`
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
	values := make(map[string]string)
	for name, value := range map[string]string{
		"interval": p.Interval, "address": p.Address, "username": p.Username, "password": p.Password,
		"identity_file": p.IdentityFile, "host_key": p.HostKey, "tls_fingerprint": p.TLSFingerprint,
	} {
		if value != "" {
			values[name] = value
		}
	}
	if p.UseTLS {
		values["use_tls"] = "true"
	}
	if p.Params != "" {
		if len(values) > 0 {
			return "", errors.New("give the params, or their fields, not both")
		}
		return p.Params, nil
	}
	// The plugin type says what its fields are, and their order.
	return plugins.FieldParams(p.Type, values)
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

		if len(task.Sources) > 0 {
			result.WriteString(prefix + "            Sources: " + strings.Join(task.Sources, ", ") + "\n")
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

	if len(c.Sources) > 0 {
		result.WriteString(prefix + "    Sources:\n")
		for _, name := range slices.Sorted(maps.Keys(c.Sources)) {
			result.WriteString(prefix + "        " + name + ": " + c.Sources[name].describe(hideSensible) + "\n")
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
	for _, family := range []struct {
		name string
		f    Family
	}{{"IPv6", c.Discovery.IPv6}, {"IPv4", c.Discovery.IPv4}} {
		if !family.f.Enabled {
			result.WriteString(prefix + "        " + family.name + ": off\n")
			continue
		}
		fmt.Fprintf(&result, "%s        %s: listen %t, active %t, solicit %t", prefix, family.name, family.f.Listen, family.f.Active, family.f.Solicit)
		if family.f.Lifetime.Duration > 0 {
			fmt.Fprintf(&result, ", lifetime %s", family.f.Lifetime.Duration)
		}
		result.WriteString("\n")
	}
	if len(c.Discovery.Interfaces) > 0 {
		fmt.Fprintf(&result, "%s        Interfaces: %s\n", prefix, strings.Join(c.Discovery.Interfaces, ", "))
	}
	if len(c.Discovery.ExcludeInterfaces) > 0 {
		fmt.Fprintf(&result, "%s        Excluded interfaces: %s\n", prefix, strings.Join(c.Discovery.ExcludeInterfaces, ", "))
	}
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
		for _, desc := range specificErrors(result.Errors()) {
			// A duration's pattern, in words.
			if desc.Type() == "pattern" && strings.Contains(desc.Description(), "ns|us") {
				fmt.Fprintf(&errs, "\n- %s: not a duration, as 90s, 1m30s or 1h", desc.Field())
				continue
			}
			fmt.Fprintf(&errs, "\n- %s", desc)
		}
		return errors.New(errs.String())
	}
	return nil
}

// combinatorErrors are the errors saying only that a part of a combination failed: noise beside
// the error of that part.
var combinatorErrors = map[string]bool{
	"number_one_of": true, "number_any_of": true, "number_all_of": true,
	"condition_then": true, "condition_else": true,
}

// specificErrors leaves out the combinator errors, unless there is nothing else.
func specificErrors(all []gojsonschema.ResultError) []gojsonschema.ResultError {
	var specific []gojsonschema.ResultError
	for _, e := range all {
		if !combinatorErrors[e.Type()] {
			specific = append(specific, e)
		}
	}
	if len(specific) == 0 {
		return all
	}
	return specific
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
	config.Discovery = DefaultDiscovery()
	config.Lifetime = duration.Duration{Duration: DefaultLifetime}

	if err := json.Unmarshal(byteValue, &config); err != nil {
		return config, err
	}

	var pluginWarnings []string
	for _, name := range slices.Sorted(maps.Keys(config.Discovery.Plugins)) {
		plugin := config.Discovery.Plugins[name]
		params, err := plugin.PluginParams()
		if err == nil {
			// The plugin type's own checks, as when it is made: nothing runs yet.
			_, err = plugins.Create(plugin.Type, name, params, DefaultLifetime)
		}
		if err != nil {
			return config, fmt.Errorf("plugin %s: %w", name, err)
		}
		if plugin.Params != "" {
			pluginWarnings = append(pluginWarnings, fmt.Sprintf("discovery.plugins.%s.params is deprecated, and goes in v1.0: give its fields, as interval, address, username", name))
		}
	}

	discoveryWarnings, err := config.Discovery.setUpDiscovery()
	if err != nil {
		return config, err
	}
	config.Warnings, err = config.setUpSources()
	if err != nil {
		return config, err
	}
	config.Warnings = slices.Concat(discoveryWarnings, pluginWarnings, config.Warnings)

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
