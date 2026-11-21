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

	disc "github.com/miguelangel-nubla/ipv6disc/pkg/config"
	"github.com/xeipuuv/gojsonschema"
	"sigs.k8s.io/yaml"
)

//go:embed schema.json
var configSchema []byte

// Schema returns the JSON schema of the configuration.
func Schema() []byte { return configSchema }

type Config struct {
	BaseDir     string                `json:"-"`
	Tasks       map[string]Task       `json:"tasks"`
	Credentials map[string]Credential `json:"credentials"`
	Discovery   Discovery             `json:"discovery"`
	Sources     map[string]Source     `json:"sources,omitempty"`
	// A device of Home Assistant's ESPHome integration: off without it.
	HomeAssistant *HomeAssistant `json:"homeassistant,omitempty"`
	// DNS servers for the network's clients, by name, which answer the zones of the resolver
	// credentials.
	Resolvers map[string]Resolver `json:"resolvers,omitempty"`

	// The level of the log: info without it.
	LogLevel  string    `json:"log_level,omitempty"`
	Webserver Webserver `json:"webserver,omitzero"`

	// What in the configuration to change, as a deprecated setting: NewConfig sets them, to log.
	Warnings []string `json:"-"`
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
		result.WriteString(prefix + "            Debounce: " + credential.Debounce.String() + "\n")

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
	d := c.Discovery
	fmt.Fprintf(&result, "%s        Lifetime: %s\n", prefix, d.Lifetime)
	for _, family := range []struct {
		name string
		f    disc.Family
	}{{"IPv6", d.IPv6}, {"IPv4", d.IPv4}} {
		if !family.f.Enabled {
			result.WriteString(prefix + "        " + family.name + ": off\n")
			continue
		}
		fmt.Fprintf(&result, "%s        %s: listen %t, active %t", prefix, family.name, family.f.Listen, family.f.Active)
		if family.f.Lifetime > 0 {
			fmt.Fprintf(&result, ", lifetime %s", family.f.Lifetime)
		}
		result.WriteString("\n")
	}
	var solicited []string
	if d.Solicit.IPv6 {
		solicited = append(solicited, "IPv6")
	}
	if d.Solicit.IPv4 {
		solicited = append(solicited, "IPv4")
	}
	if len(solicited) > 0 {
		fmt.Fprintf(&result, "%s        Solicit: %s\n", prefix, strings.Join(solicited, ", "))
	}
	if d.Hostnames.Enabled {
		result.WriteString(prefix + "        Hostnames: kept")
		if d.Hostnames.Lifetime > 0 {
			fmt.Fprintf(&result, ", lifetime %s", d.Hostnames.Lifetime)
		}
		result.WriteString("\n")
	}
	if len(d.Interfaces) > 0 {
		fmt.Fprintf(&result, "%s        Interfaces: %s\n", prefix, strings.Join(d.Interfaces, ", "))
	}
	if len(d.ExcludeInterfaces) > 0 {
		fmt.Fprintf(&result, "%s        Excluded interfaces: %s\n", prefix, strings.Join(d.ExcludeInterfaces, ", "))
	}
	if len(d.Plugins) > 0 {
		result.WriteString(prefix + "        Plugins:\n")
		for _, name := range slices.Sorted(maps.Keys(d.Plugins)) {
			plugin := d.Plugins[name]
			result.WriteString(prefix + "            " + name + ":\n")
			result.WriteString(prefix + "                Type: " + plugin.Type + "\n")
			if !hideSensible {
				params, err := plugin.Params()
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
			// A filter's patterns too: the MAC, and the VALUE/MASK pairs.
			if desc.Type() == "pattern" && strings.HasSuffix(desc.Field(), ".mac.address") {
				fmt.Fprintf(&errs, "\n- %s: not a MAC address, as 00:11:22:33:44:55", desc.Field())
				continue
			}
			if desc.Type() == "pattern" && strings.Contains(desc.Field(), ".mask.") {
				fmt.Fprintf(&errs, "\n- %s: not VALUE/MASK, both written whole, as ::1/::ffff:ffff:ffff:ffff: the mask is no prefix length", desc.Field())
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
		// Strict: a key given twice, as a task's name after a copy, is an error, rather than the
		// last one alone being kept.
		byteValue, err = yaml.YAMLToJSONStrict(byteValue)
		if err != nil {
			return config, err
		}
	}

	byteValue, err = expandSecrets(byteValue, filepath.Dir(filename))
	if err != nil {
		return config, err
	}

	if err := checkHomeAssistant(byteValue); err != nil {
		return config, err
	}
	if err := checkResolvers(byteValue); err != nil {
		return config, err
	}
	if err := checkDiscovery(byteValue); err != nil {
		return config, err
	}
	if err := validateConfig(byteValue); err != nil {
		return config, err
	}

	// Set defaults
	config.Discovery = DefaultDiscovery()

	if err := json.Unmarshal(byteValue, &config); err != nil {
		return config, err
	}

	// Read, and valid, by checkDiscovery: its warnings.
	discoveryWarnings, _ := config.Discovery.validate()
	config.Warnings, err = config.setUpSources()
	if err != nil {
		return config, err
	}
	config.Warnings = slices.Concat(familyWarnings(byteValue), discoveryWarnings, config.Warnings)
	if err := config.setUpHomeAssistant(); err != nil {
		return config, err
	}
	if err := config.setUpWebserver(); err != nil {
		return config, err
	}
	for _, name := range slices.Sorted(maps.Keys(config.Credentials)) {
		// A failing provider is tried again at every retry: with none it would be without a pause.
		if retry := config.Credentials[name].Retry; retry.Duration < MinRetry {
			return config, fmt.Errorf("credentials.%s: invalid retry %s: at least %s", name, retry.Duration, MinRetry)
		}
		if debounce := config.Credentials[name].Debounce; debounce.Duration < 0 {
			return config, fmt.Errorf("credentials.%s: invalid debounce %s: not negative", name, debounce.Duration)
		}
		for _, old := range config.Credentials[name].deprecated {
			newName := map[string]string{"debounce_time": "debounce", "retry_time": "retry"}[old]
			config.Warnings = append(config.Warnings, fmt.Sprintf("credentials.%s.%s is deprecated, and goes in v1.0: it is %s", name, old, newName))
		}
	}

	for _, name := range slices.Sorted(maps.Keys(config.Tasks)) {
		task := config.Tasks[name]
		task.Name = name
		if err := task.checkFilters(); err != nil {
			return config, fmt.Errorf("task %s: %w", name, err)
		}
		config.Tasks[name] = task
		for endpoint := range task.Endpoints {
			if _, ok := config.Credentials[endpoint]; !ok {
				return config, fmt.Errorf("task %s: no credential %s for its endpoint", name, endpoint)
			}
		}
	}

	if err := config.checkTemplates(); err != nil {
		return config, err
	}

	if err := config.setUpResolvers(); err != nil {
		return config, err
	}

	config.BaseDir = filepath.Dir(filename)

	return config, nil
}
