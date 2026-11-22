package config

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/internal/schematest"
	disc "github.com/miguelangel-nubla/ipv6disc/pkg/config"
)

var update = flag.Bool("update", false, "write the discovery of ipv6disc's schema into schema.json")

func TestSchemaMatchesConfig(t *testing.T) {
	schematest.Check(t, string(configSchema), Config{})
}

// object is a JSON object with its keys in the order they are written: the reference is made in
// the order of the schema's.
type object struct {
	keys   []string
	values map[string]any
}

func (o *object) set(key string, value any) {
	if _, ok := o.values[key]; !ok {
		o.keys = append(o.keys, key)
	}
	o.values[key] = value
}

func (o *object) remove(key string) {
	delete(o.values, key)
	o.keys = slices.DeleteFunc(o.keys, func(k string) bool { return k == key })
}

func (o *object) object(path ...string) *object {
	for _, key := range path {
		o = o.values[key].(*object)
	}
	return o
}

// ordered reads a JSON document, its objects as *object, its numbers as written.
func ordered(t *testing.T, raw []byte) any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value func() any
	value = func() any {
		token, err := decoder.Token()
		if err != nil {
			t.Fatal(err)
		}
		switch token {
		case json.Delim('{'):
			o := &object{values: make(map[string]any)}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					t.Fatal(err)
				}
				o.set(key.(string), value())
			}
			decoder.Token()
			return o
		case json.Delim('['):
			list := []any{}
			for decoder.More() {
				list = append(list, value())
			}
			decoder.Token()
			return list
		}
		return token
	}
	return value()
}

// write writes a value read by ordered as schema.json is written: indented by four spaces.
func write(b *bytes.Buffer, value any, indent string) {
	switch value := value.(type) {
	case *object:
		if len(value.keys) == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteString("{\n")
		for i, key := range value.keys {
			b.WriteString(indent + "    ")
			write(b, key, "")
			b.WriteString(": ")
			write(b, value.values[key], indent+"    ")
			if i < len(value.keys)-1 {
				b.WriteString(",")
			}
			b.WriteString("\n")
		}
		b.WriteString(indent + "}")
	case []any:
		if len(value) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteString("[\n")
		for i, element := range value {
			b.WriteString(indent + "    ")
			write(b, element, indent+"    ")
			if i < len(value)-1 {
				b.WriteString(",")
			}
			b.WriteString("\n")
		}
		b.WriteString(indent + "]")
	default:
		var scalar bytes.Buffer
		encoder := json.NewEncoder(&scalar)
		encoder.SetEscapeHTML(false)
		encoder.Encode(value)
		b.Write(bytes.TrimRight(scalar.Bytes(), "\n"))
	}
}

// plain is a value read by ordered as encoding/json reads it into an any, to compare.
func plain(value any) any {
	switch value := value.(type) {
	case *object:
		m := make(map[string]any, len(value.keys))
		for _, key := range value.keys {
			m[key] = plain(value.values[key])
		}
		return m
	case []any:
		list := make([]any, len(value))
		for i, element := range value {
			list[i] = plain(element)
		}
		return list
	case json.Number:
		f, _ := value.Float64()
		return f
	}
	return value
}

// discoveryDefs is the prefix of ipv6disc's definitions in the schema: its duration says another
// default than ipv6ddns's, and its list takes no numbers, so they are not one.
const discoveryDefs = "discovery"

func discoveryDef(name string) string {
	return discoveryDefs + strings.ToUpper(name[:1]) + name[1:]
}

// renameRefs gives the references to ipv6disc's definitions their names in this schema.
func renameRefs(value any) {
	switch value := value.(type) {
	case *object:
		for _, key := range value.keys {
			if ref, ok := value.values[key].(string); ok && key == "$ref" {
				value.values[key] = "#/$defs/" + discoveryDef(strings.TrimPrefix(ref, "#/$defs/"))
				continue
			}
			renameRefs(value.values[key])
		}
	case []any:
		for _, element := range value {
			renameRefs(element)
		}
	}
}

// solicitSchema is the schema of what the discovery block has of ipv6ddns's own.
const solicitSchema = `{
	"type": "object",
	"additionalProperties": false,
	"description": "Asks for the hosts the filters name by MAC, once a minute, when nothing else finds them. Part of ipv6ddns, not of ipv6disc.",
	"properties": {
		"ipv6": {
			"type": "boolean",
			"description": "For each filter with a mac.address and the eui64 type: a neighbor solicitation for that MAC's EUI-64 address, on each /64 discovery listens on. It needs ipv6.listen, which reads the answers.",
			"default": false
		},
		"ipv4": {
			"type": "boolean",
			"description": "For each filter with a mac.address and ip.family 4: ARP requests to that MAC alone, for the local subnets' addresses inside the filter's ip.prefix. It needs ipv4.enabled, Linux and CAP_NET_RAW.",
			"default": false
		}
	}
}`

// withDiscovery puts into the schema the discovery as ipv6disc's schema has it, in its order,
// and its definitions, renamed; with the lifetime ipv6ddns has by default, and solicit.
func withDiscovery(t *testing.T, schema *object) {
	t.Helper()
	library := ordered(t, disc.Schema()).(*object)
	// What is of the ipv6disc command alone, as DiscoverySchema leaves it out.
	library.object("properties").remove("log_level")
	renameRefs(library)
	defs := library.object("$defs")
	for _, key := range []string{"$schema", "title", "$defs"} {
		library.remove(key)
	}
	library.object("properties", "lifetime").set("default", "1h")
	library.object("properties").set("solicit", ordered(t, []byte(solicitSchema)))
	schema.object("properties").set("discovery", library)

	own := schema.object("$defs")
	for _, key := range slices.Clone(own.keys) {
		if strings.HasPrefix(key, discoveryDefs) {
			own.remove(key)
		}
	}
	for _, key := range defs.keys {
		own.set(discoveryDef(key), defs.values[key])
	}
}

// The discovery of the schema is ipv6disc's, as its DiscoverySchema has it, with solicit: after a
// change of the library's, go test ./config -update, and then ./internal/docgen -update.
func TestSchemaHasTheDiscoveryOfIPv6disc(t *testing.T) {
	schema := ordered(t, configSchema).(*object)
	var before bytes.Buffer
	write(&before, schema, "")
	before.WriteString("\n")
	if !bytes.Equal(before.Bytes(), configSchema) {
		t.Fatal("schema.json is not written as the test writes it: indented by four spaces")
	}

	withDiscovery(t, schema)
	var want bytes.Buffer
	write(&want, schema, "")
	want.WriteString("\n")
	if *update {
		if err := os.WriteFile("schema.json", want.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if !bytes.Equal(want.Bytes(), configSchema) {
		t.Fatal("schema.json is behind ipv6disc's schema of the discovery: go test ./config -update")
	}

	// And what was put there is DiscoverySchema, which the order was not taken from.
	library := ordered(t, disc.DiscoverySchema()).(*object)
	renameRefs(library)
	theirs := plain(library).(map[string]any)
	ours := plain(schema.object("properties", "discovery")).(map[string]any)
	properties := ours["properties"].(map[string]any)
	if properties["solicit"] == nil || properties["lifetime"].(map[string]any)["default"] != "1h" {
		t.Errorf("the discovery has no solicit, or another lifetime than ipv6ddns's: %v", properties["lifetime"])
	}
	delete(properties, "solicit")
	properties["lifetime"].(map[string]any)["default"] = theirs["properties"].(map[string]any)["lifetime"].(map[string]any)["default"]
	ourDefs := make(map[string]any)
	for name, def := range plain(schema.object("$defs")).(map[string]any) {
		if strings.HasPrefix(name, discoveryDefs) {
			ourDefs[name] = def
		}
	}
	theirDefs := make(map[string]any)
	for name, def := range theirs["$defs"].(map[string]any) {
		theirDefs[discoveryDef(name)] = def
	}
	for _, key := range []string{"$schema", "title", "$defs"} {
		delete(theirs, key)
	}
	if !reflect.DeepEqual(ours, theirs) || !reflect.DeepEqual(ourDefs, theirDefs) {
		t.Error("the discovery of schema.json is not ipv6disc's DiscoverySchema")
	}
}

// The defaults the schema says of the discovery are those of DefaultDiscovery: the reference has
// a column of them.
func TestSchemaSaysTheDiscoveryDefaults(t *testing.T) {
	defaults, err := json.Marshal(DefaultDiscovery())
	if err != nil {
		t.Fatal(err)
	}
	var values map[string]any
	if err := json.Unmarshal(defaults, &values); err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(configSchema, &schema); err != nil {
		t.Fatal(err)
	}
	checked := 0
	var walk func(path string, node map[string]any, value any)
	walk = func(path string, node map[string]any, value any) {
		if written, ok := node["default"]; ok {
			checked++
			got := fmt.Sprint(value)
			if node["$ref"] == "#/$defs/"+discoveryDef("duration") {
				d, err := time.ParseDuration(written.(string))
				if err != nil {
					t.Errorf("%s: %v", path, err)
				}
				written = d.String()
			}
			if fmt.Sprint(written) != got {
				t.Errorf("%s: the schema's default is %v, the configuration's %v", path, written, got)
			}
		}
		properties, _ := node["properties"].(map[string]any)
		values, _ := value.(map[string]any)
		for name, property := range properties {
			if _, ok := values[name]; !ok {
				t.Errorf("%s.%s: not in the discovery by default: %v", path, name, values)
				continue
			}
			walk(path+"."+name, property.(map[string]any), values[name])
		}
	}
	walk("discovery", schema["properties"].(map[string]any)["discovery"].(map[string]any), values)
	if checked < 20 {
		t.Errorf("%d defaults looked at", checked)
	}
	if lifetime := values["lifetime"]; lifetime != DefaultLifetime.String() {
		t.Errorf("the lifetime by default: %v", lifetime)
	}
}
