// Package schematest checks that a JSON schema and the Go type its documents decode into agree:
// every property is a field, every field a property, and their types match.
package schematest

import (
	"encoding"
	"encoding/json"
	"reflect"
	"strings"
)

// TB is the part of testing.TB Check uses.
type TB interface {
	Helper()
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
}

// Check reports where schema, a JSON schema, and the type of v disagree.
func Check(t TB, schema string, v any) {
	t.Helper()
	var s map[string]any
	if err := json.Unmarshal([]byte(schema), &s); err != nil {
		t.Fatalf("schema: %v", err)
	}
	check(t, "$", s, reflect.TypeOf(v))
}

var (
	jsonUnmarshaler = reflect.TypeFor[json.Unmarshaler]()
	textUnmarshaler = reflect.TypeFor[encoding.TextUnmarshaler]()
	rawMessage      = reflect.TypeFor[json.RawMessage]()
)

func check(t TB, path string, schema map[string]any, typ reflect.Type) {
	t.Helper()
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}

	properties, hasProperties := schema["properties"].(map[string]any)
	switch {
	case hasProperties:
		fields := jsonFields(typ)
		if fields == nil {
			t.Errorf("%s: the schema has properties, the type %s has no fields", path, typ)
			return
		}
		for name, property := range properties {
			field, ok := fields[name]
			if !ok {
				t.Errorf("%s.%s: a property with no field in %s", path, name, typ)
				continue
			}
			if property, ok := property.(map[string]any); ok {
				check(t, path+"."+name, property, field)
			} else {
				t.Errorf("%s.%s: the property is no schema", path, name)
			}
		}
		for name := range fields {
			if _, ok := properties[name]; !ok {
				t.Errorf("%s.%s: a field of %s the schema doesn't allow", path, name, typ)
			}
		}
		if required, ok := schema["required"].([]any); ok {
			for _, name := range required {
				if _, ok := properties[name.(string)]; !ok {
					t.Errorf("%s: required %v is no property", path, name)
				}
			}
		}

	case schema["additionalProperties"] != nil || schema["patternProperties"] != nil:
		element, _ := schema["additionalProperties"].(map[string]any)
		if patterns, ok := schema["patternProperties"].(map[string]any); ok {
			for _, p := range patterns {
				element, _ = p.(map[string]any)
			}
		}
		if typ.Kind() != reflect.Map {
			t.Errorf("%s: the schema is a map, the type %s isn't", path, typ)
			return
		}
		if element != nil {
			check(t, path+".*", element, typ.Elem())
		}

	default:
		checkLeaf(t, path, schema, typ)
	}
}

func checkLeaf(t TB, path string, schema map[string]any, typ reflect.Type) {
	t.Helper()
	custom := reflect.PointerTo(typ).Implements(jsonUnmarshaler) || reflect.PointerTo(typ).Implements(textUnmarshaler)
	ok := true
	switch schema["type"] {
	case "string":
		ok = typ.Kind() == reflect.String || custom
	case "boolean":
		ok = typ.Kind() == reflect.Bool
	case "integer", "number":
		ok = typ.Kind() >= reflect.Int && typ.Kind() <= reflect.Float64 || custom
	case "array":
		if typ.Kind() != reflect.Slice {
			ok = false
		} else if items, isSchema := schema["items"].(map[string]any); isSchema {
			check(t, path+"[]", items, typ.Elem())
		}
	case "object":
		// An object without properties: any JSON, as json.RawMessage.
		ok = typ == rawMessage || typ.Kind() == reflect.Map || custom
	}
	if !ok {
		t.Errorf("%s: the schema type %v doesn't fit %s", path, schema["type"], typ)
	}
}

// jsonFields returns the types of the fields JSON decodes, by name, or nil for a type that is no
// struct.
func jsonFields(typ reflect.Type) map[string]reflect.Type {
	if typ.Kind() != reflect.Struct {
		return nil
	}
	fields := make(map[string]reflect.Type)
	for _, f := range reflect.VisibleFields(typ) {
		if !f.IsExported() || !decoded(typ, f) {
			continue
		}
		tag := f.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "-" {
			continue
		}
		if f.Anonymous && tag == "" {
			continue // its fields are promoted
		}
		if name == "" {
			name = f.Name
		}
		fields[name] = f.Type
	}
	return fields
}

// decoded tells whether JSON decodes a field of an embedded struct: only when the fields it is
// embedded in have no JSON name of their own.
func decoded(typ reflect.Type, f reflect.StructField) bool {
	for i := 1; i < len(f.Index); i++ {
		if typ.FieldByIndex(f.Index[:i]).Tag.Get("json") != "" {
			return false
		}
	}
	return true
}
