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
	Enum                 []any            `json:"enum"`
	Const                any              `json:"const"`
	Properties           map[string]*node `json:"properties"`
	Required             []string         `json:"required"`
	AdditionalProperties any              `json:"additionalProperties"`
	Items                *node            `json:"items"`
	OneOf                []*node          `json:"oneOf"`
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
	case "#/$defs/duration":
		return "duration"
	case "#/$defs/durationString":
		return "duration string"
	case "#/$defs/stringList":
		return "list, or comma separated"
	case "#/$defs/family":
		return "true, false, or [ways](#discovery-families)"
	case "#/$defs/plugin":
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

// table writes the properties of an object schema, in the order of keys. described gives the
// descriptions the schema leaves to another: the plugins', which ipv6disc has.
func table(b *strings.Builder, n *node, keys []string, defs map[string]*node, described ...map[string]string) {
	b.WriteString("| Key | Takes | |\n|---|---|---|\n")
	for _, key := range keys {
		p := n.Properties[key]
		if p == nil {
			continue
		}
		desc := p.Description
		for _, d := range described {
			if d[key] != "" {
				desc = d[key]
			}
		}
		switch {
		case slices.Contains(n.Required, key):
			desc = "**Required.** " + desc
		case n.Else != nil && slices.Contains(n.Else.Required, key):
			desc = "**Required**, without `params`. " + desc
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
	b.WriteString("The configuration file is YAML, or JSON. Every string takes `${NAME}`, an environment variable, and `${file:PATH}`, a file's content: see [secrets](../configuration.md#secrets). A duration is `90s`, `1m30s`, `1h`, or a number of seconds. A key the schema doesn't have is an error.\n\n")

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
	ipv4 := taskNode.Properties["ipv4"]
	section("Task ipv4, deprecated", "tasks.<name>.ipv4", ipv4.Description, ipv4, "properties", "tasks", "additionalProperties", "properties", "ipv4", "properties")

	credential := asNode(root.Properties["credentials"].AdditionalProperties)
	section("Credentials", "credentials.<name>", root.Properties["credentials"].Description+" The settings of each provider are in the [providers reference](providers.md).", credential, "properties", "credentials", "additionalProperties", "properties")

	source := asNode(root.Properties["sources"].AdditionalProperties)
	section("Sources", "sources.<name>", root.Properties["sources"].Description+" See [sources](../sources.md).", source, "properties", "sources", "additionalProperties", "properties")

	discovery := root.Properties["discovery"]
	section("Discovery", "discovery", discovery.Description+" See [discovery](../discovery.md).", discovery, "properties", "discovery", "properties")

	family := defs["family"].OneOf[1]
	b.WriteString("## Discovery families\n\n`discovery.ipv6`, `discovery.ipv4`\n\n`true` turns the family on with its default ways, `false` off, and an object gives the ways, each defaulting as `true` sets it.\n\n")
	table(&b, family, order(raw, "$defs", "family", "oneOf", "1", "properties"), defs)

	b.WriteString("## Discovery plugins\n\n`discovery.plugins.<name>`\n\n" + discovery.Properties["plugins"].Description + " Each type takes its own keys only.\n\n")
	for _, def := range pluginDefs {
		fmt.Fprintf(&b, "### %s\n\n%s\n\n", def.title, defs[def.name].Description)
		n := defs[def.name]
		// The type is required by the plugin's schema, around the type's.
		n.Required = defs["plugin"].Required
		described, err := PluginFieldDescriptions(def.pluginType)
		if err != nil {
			return "", err
		}
		table(&b, n, order(raw, "$defs", def.name, "properties"), defs, described)
	}
	return strings.TrimRight(b.String(), "\n") + "\n", nil
}

// pluginDefs are the schema's definitions of the plugins, with a type of each that ipv6disc has.
var pluginDefs = []struct{ name, title, pluginType string }{
	{"sshPlugin", "`linux`, `freebsd`", "linux"},
	{"mikrotikPlugin", "`mikrotik`", "mikrotik"},
}

// PluginFieldDescriptions are the descriptions of a plugin type's params, as ipv6disc registers
// them: the one place they are written.
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
		table(&b, n, order(raw, "properties"), nil)
	}
	return strings.TrimRight(b.String(), "\n") + "\n", nil
}
