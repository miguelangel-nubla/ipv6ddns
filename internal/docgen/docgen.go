// Package docgen makes the reference pages of the documentation from the schemas: the
// configuration's, and the providers' settings. `go test ./internal/docgen -update` writes them,
// and the test tells when they are behind.
package docgen

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/ddns"
	"github.com/miguelangel-nubla/ipv6disc/pkg/plugins"
)

// Pages are the generated pages, by path from the repository's root.
func Pages() (map[string]string, error) {
	configuration, err := Configuration()
	if err != nil {
		return nil, err
	}
	providers, err := Providers()
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"docs/reference/configuration.md": configuration,
		"docs/reference/providers.md":     providers,
	}, nil
}

const generated = "<!-- Generated from the schemas by `go test ./internal/docgen -update`: edit them, not this page. -->\n\n"

// node is a JSON schema, as far as the pages use it.
type node struct {
	Ref                  string           `json:"$ref"`
	Type                 any              `json:"type"`
	Description          string           `json:"description"`
	Default              any              `json:"default"`
	Enum                 []any            `json:"enum"`
	Const                any              `json:"const"`
	Properties           map[string]*node `json:"properties"`
	Required             []string         `json:"required"`
	AdditionalProperties any              `json:"additionalProperties"`
	Items                *node            `json:"items"`
	OneOf                []*node          `json:"oneOf"`
	If                   *node            `json:"if"`
	Else                 *node            `json:"else"`
	Defs                 map[string]*node `json:"$defs"`
}

func parse(b []byte) (*node, error) {
	var n node
	if err := json.Unmarshal(b, &n); err != nil {
		return nil, err
	}
	return &n, nil
}

// order returns the keys of the object at path in raw, in the order the file has them: a map
// would lose it. A path element of an array is its index.
func order(raw []byte, path ...string) []string {
	cur := json.RawMessage(raw)
	for _, p := range path {
		if index, err := strconv.Atoi(p); err == nil {
			var list []json.RawMessage
			if json.Unmarshal(cur, &list) != nil || index >= len(list) {
				return nil
			}
			cur = list[index]
			continue
		}
		var m map[string]json.RawMessage
		if json.Unmarshal(cur, &m) != nil {
			return nil
		}
		cur = m[p]
	}
	dec := json.NewDecoder(bytes.NewReader(cur))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil
	}
	var keys []string
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return keys
		}
		keys = append(keys, t.(string))
		var skip json.RawMessage
		if dec.Decode(&skip) != nil {
			return keys
		}
	}
	return keys
}

// typeOf says in words what a schema takes.
func typeOf(n *node, defs map[string]*node) string {
	switch n.Ref {
	case "#/$defs/duration", "#/$defs/discoveryDuration":
		return "duration"
	case "#/$defs/durationString", "#/$defs/discoveryDurationString":
		return "duration string"
	case "#/$defs/stringList", "#/$defs/discoveryStringList":
		return "list, or comma separated"
	case "#/$defs/discoveryPlugin":
		return "[plugin](#discovery-plugins)"
	}
	if len(n.Enum) > 0 {
		var values []string
		for _, v := range n.Enum {
			values = append(values, fmt.Sprintf("`%v`", v))
		}
		return strings.Join(values, ", ")
	}
	if len(n.OneOf) > 0 {
		var alts []string
		for _, alt := range n.OneOf {
			if t := typeOf(alt, defs); !slices.Contains(alts, t) {
				alts = append(alts, t)
			}
		}
		return strings.Join(alts, " or ")
	}
	switch t := n.Type.(type) {
	case string:
		switch t {
		case "array":
			if n.Items != nil {
				return "list of " + typeOf(n.Items, defs)
			}
			return "list"
		case "integer", "number":
			return "number"
		}
		return t
	case []any:
		var ts []string
		for _, v := range t {
			ts = append(ts, fmt.Sprint(v))
		}
		return strings.Join(ts, " or ")
	}
	return ""
}

func cell(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "|", `\|`), "\n", " ")
}

// table writes the properties of an object schema, in the order of keys: with their defaults,
// in a column, where the schema has them apart from the descriptions, as ipv6disc's does.
func table(b *strings.Builder, n *node, keys []string, defs map[string]*node) {
	defaults := false
	for _, key := range keys {
		defaults = defaults || n.Properties[key] != nil && n.Properties[key].Default != nil
	}
	if defaults {
		b.WriteString("| Key | Takes | Default | |\n|---|---|---|---|\n")
	} else {
		b.WriteString("| Key | Takes | |\n|---|---|---|\n")
	}
	for _, key := range keys {
		p := n.Properties[key]
		if p == nil {
			continue
		}
		desc := p.Description
		switch {
		case slices.Contains(n.Required, key):
			desc = "**Required.** " + desc
		// What an object needs without the key its condition is of: the Home Assistant device's
		// key without key_provisioning.
		case n.If != nil && len(n.If.Required) == 1 && n.Else != nil && slices.Contains(n.Else.Required, key):
			desc = fmt.Sprintf("**Required**, without `%s`. %s", n.If.Required[0], desc)
		}
		if defaults {
			value := "-"
			if p.Default != nil {
				value = fmt.Sprintf("`%v`", p.Default)
			}
			fmt.Fprintf(b, "| `%s` | %s | %s | %s |\n", key, cell(typeOf(p, defs)), value, cell(desc))
			continue
		}
		fmt.Fprintf(b, "| `%s` | %s | %s |\n", key, cell(typeOf(p, defs)), cell(desc))
	}
	b.WriteString("\n")
}

// Configuration is the reference of the configuration file.
func Configuration() (string, error) {
	raw := config.Schema()
	root, err := parse(raw)
	if err != nil {
		return "", err
	}
	defs := root.Defs
	var b strings.Builder
	b.WriteString("# Configuration reference\n\n" + generated)
	b.WriteString("The configuration file is YAML, or JSON. Every string takes `${NAME}`, an environment variable, and `${file:PATH}`, a file's content: see [secrets](../configuration.md#secrets). A duration is `90s`, `1m30s`, `1h`, or a number of seconds. A key the schema doesn't have is an error. The schema is [`config/schema.json`](../../config/schema.json).\n\n")

	b.WriteString("## Top level\n\n")
	table(&b, root, order(raw, "properties"), defs)

	// A section: a plain title, for its anchor, and the key path under it.
	section := func(title, keyPath, intro string, n *node, path ...string) {
		fmt.Fprintf(&b, "## %s\n\n`%s`\n\n", title, keyPath)
		if intro != "" {
			b.WriteString(intro + "\n\n")
		}
		table(&b, n, order(raw, path...), defs)
	}

	task := root.Properties["tasks"].AdditionalProperties
	taskNode := asNode(task)
	section("Tasks", "tasks.<name>", root.Properties["tasks"].Description, taskNode, "properties", "tasks", "additionalProperties", "properties")
	filter := taskNode.Properties["filter"].Items
	section("Task filters", "tasks.<name>.filter[]", "Each filter set: an address that every rule of one set matches is the task's. See [filtering](../filtering.md).", filter, "properties", "tasks", "additionalProperties", "properties", "filter", "items", "properties")
	for _, key := range []string{"mac", "ip"} {
		section("Filter "+key, "tasks.<name>.filter[]."+key, filter.Properties[key].Description, filter.Properties[key], "properties", "tasks", "additionalProperties", "properties", "filter", "items", "properties", key, "properties")
	}

	credential := asNode(root.Properties["credentials"].AdditionalProperties)
	section("Credentials", "credentials.<name>", root.Properties["credentials"].Description+" The settings of each provider are in the [providers reference](providers.md).", credential, "properties", "credentials", "additionalProperties", "properties")

	resolvers := asNode(root.Properties["resolvers"].AdditionalProperties)
	section("Resolvers", "resolvers.<name>", root.Properties["resolvers"].Description, resolvers, "properties", "resolvers", "additionalProperties", "properties")
	// Its dynamic updates: their keys, and the permissions of each, by kind.
	sub := func(title, keyPath string, n *node, path ...string) {
		fmt.Fprintf(&b, "### %s\n\n`%s`\n\n%s\n\n", title, keyPath, n.Description)
		table(&b, n, order(raw, path...), defs)
	}
	updatesPath := []string{"properties", "resolvers", "additionalProperties", "properties", "updates", "properties"}
	updates := resolvers.Properties["updates"]
	sub("updates", "resolvers.<name>.updates", updates, updatesPath...)
	keysPath := append(slices.Clone(updatesPath), "keys", "additionalProperties", "properties")
	keys := asNode(updates.Properties["keys"].AdditionalProperties)
	keys.Description = updates.Properties["keys"].Description
	sub("keys", "resolvers.<name>.updates.keys.<name>", keys, keysPath...)
	permissionsPath := append(slices.Clone(keysPath), "permissions", "items", "properties")
	permission := keys.Properties["permissions"].Items
	for _, kind := range []string{"challenges", "addresses", "names"} {
		sub("permissions: "+kind, "resolvers.<name>.updates.keys.<name>.permissions[]."+kind, permission.Properties[kind], append(slices.Clone(permissionsPath), kind, "properties")...)
	}

	source := asNode(root.Properties["sources"].AdditionalProperties)
	section("Sources", "sources.<name>", root.Properties["sources"].Description+" See [sources](../sources.md).", source, "properties", "sources", "additionalProperties", "properties")

	webservers := asNode(root.Properties["webservers"].AdditionalProperties)
	section("Web servers", "webservers.<name>", root.Properties["webservers"].Description, webservers, "properties", "webservers", "additionalProperties", "properties")

	listeners := asNode(root.Properties["listeners"].AdditionalProperties)
	section("Listeners", "listeners.<name>", root.Properties["listeners"].Description, listeners, "properties", "listeners", "additionalProperties", "properties")

	// The certificates of the encrypted entries: of the resolvers, the web servers and the listeners.
	tlsDef := defs["tls"]
	fmt.Fprintf(&b, "## Certificates\n\n`certificates.<name>`\n\n%s %s See [encrypted DNS for the clients](../resolver.md#encrypted-dns-for-the-clients).\n\n", root.Properties["certificates"].Description, tlsDef.Description)
	table(&b, tlsDef, order(raw, "$defs", "tls", "properties"), defs)
	acmeDef := tlsDef.Properties["acme"]
	fmt.Fprintf(&b, "### acme\n\n`certificates.<name>.acme`\n\n%s\n\n", acmeDef.Description)
	table(&b, acmeDef, order(raw, "$defs", "tls", "properties", "acme", "properties"), defs)

	ha := root.Properties["homeassistant"]
	section("Home Assistant", "homeassistant", ha.Description+" See [the Home Assistant integration](../home-assistant-integration.md).", ha, "properties", "homeassistant", "properties")

	// The discovery, which is ipv6disc's: its families, its names, its protocols, each with its
	// options, and its plugins; and solicit, which is not.
	discovery := root.Properties["discovery"]
	section("Discovery", "discovery", discovery.Description+" The keys are those of [ipv6disc](https://github.com/miguelangel-nubla/ipv6disc), whose discovery it is, but `solicit`, which is of ipv6ddns: a file of its command's keys is this block. See [discovery](../discovery.md).", discovery, "properties", "discovery", "properties")
	for _, part := range []struct{ title, key string }{
		{"Discovery IPv6", "ipv6"}, {"Discovery IPv4", "ipv4"}, {"Discovery hostnames", "hostnames"}, {"Discovery solicit", "solicit"},
	} {
		n := discovery.Properties[part.key]
		section(part.title, "discovery."+part.key, n.Description, n, "properties", "discovery", "properties", part.key, "properties")
	}

	protocols := discovery.Properties["protocols"]
	b.WriteString("## Discovery protocols\n\n`discovery.protocols`\n\n" + protocols.Description + "\n\n")
	b.WriteString("```yaml\ndiscovery:\n  protocols:\n    mdns:\n      enabled: true\n      ask: false\n    arp-sweep:\n      enabled: false\n```\n\n")
	for _, name := range order(raw, "properties", "discovery", "properties", "protocols", "properties") {
		n := protocols.Properties[name]
		fmt.Fprintf(&b, "### %s\n\n`discovery.protocols.%s`\n\n%s\n\n", name, name, n.Description)
		table(&b, n, order(raw, "properties", "discovery", "properties", "protocols", "properties", name, "properties"), defs)
	}

	b.WriteString("## Discovery plugins\n\n`discovery.plugins.<name>`\n\n" + discovery.Properties["plugins"].Description + " Each type takes its own keys only.\n\n")
	for _, def := range pluginDefs {
		n := defs[def.name]
		fmt.Fprintf(&b, "### %s\n\n%s\n\n", def.title, n.Description)
		// The type is required by the plugin's schema, around the type's.
		n.Required = append(slices.Clone(defs["discoveryPlugin"].Required), n.Required...)
		table(&b, n, order(raw, "$defs", def.name, "properties"), defs)
	}
	return strings.TrimRight(b.String(), "\n") + "\n", nil
}

// pluginDefs are the schema's definitions of the plugins, with a type of each that ipv6disc has.
var pluginDefs = []struct{ name, title, pluginType string }{
	{"discoverySshPlugin", "`linux`, `freebsd`", "linux"},
	{"discoveryMikrotikPlugin", "`mikrotik`", "mikrotik"},
	{"discoveryUnifiPlugin", "`unifi`", "unifi"},
}

// PluginFieldDescriptions are the descriptions of a plugin type's fields, as ipv6disc registers
// them, and its schema has them: the one place they are written.
func PluginFieldDescriptions(pluginType string) (map[string]string, error) {
	fields, err := plugins.Fields(pluginType)
	if err != nil {
		return nil, err
	}
	described := make(map[string]string)
	for _, f := range fields {
		described[f.Name] = f.Description
	}
	return described, nil
}

// asNode reads an additionalProperties that is a schema.
func asNode(v any) *node {
	b, _ := json.Marshal(v)
	n, _ := parse(b)
	return n
}

// Providers is the reference of the providers' settings.
func Providers() (string, error) {
	var b strings.Builder
	b.WriteString("# DNS providers\n\n" + generated)
	b.WriteString("A credential's `provider` is one of these, and its `settings` are those of the provider. An unknown setting is an error. A `ttl` is a duration string, as `5m`. Adding a provider: see [CONTRIBUTING](../../CONTRIBUTING.md).\n\n")
	for _, name := range ddns.Providers() {
		fmt.Fprintf(&b, "- [`%s`](#%s)\n", name, name)
	}
	b.WriteString("\n")
	for _, name := range ddns.Providers() {
		raw, err := ddns.SettingsSchema(name)
		if err != nil {
			return "", err
		}
		n, err := parse(raw)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "## %s\n\n%s\n\n", name, n.Description)
		if ddns.WritesTXT(name) {
			b.WriteString("It writes TXT records too: its credential can write the DNS challenge, of ipv6ddns's [certificates](../resolver.md#a-certificate-from-lets-encrypt) and of [other machines'](../guides/certificates-for-other-machines.md).\n\n")
		}
		table(&b, n, order(raw, "properties"), nil)
	}
	return strings.TrimRight(b.String(), "\n") + "\n", nil
}
