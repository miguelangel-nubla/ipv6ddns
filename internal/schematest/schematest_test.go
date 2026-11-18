package schematest

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

type recorder struct{ errors []string }

func (r *recorder) Helper() {}
func (r *recorder) Errorf(format string, args ...any) {
	r.errors = append(r.errors, fmt.Sprintf(format, args...))
}
func (r *recorder) Fatalf(format string, args ...any) { r.Errorf(format, args...) }

type inner struct {
	Mask []string `json:"mask"`
}

type hidden struct {
	Secret string
}

type config struct {
	hidden   `json:"-"`
	Name     string           `json:"name"`
	Prefix   netip.Prefix     `json:"prefix"`
	Enabled  bool             `json:"enabled"`
	Items    []inner          `json:"items"`
	Tasks    map[string]inner `json:"tasks"`
	Settings json.RawMessage  `json:"settings"`
	//lint:ignore U1000 an unexported field, which the check must skip
	internal string
}

const good = `{"type": "object", "properties": {
	"name": {"type": "string"}, "prefix": {"type": "string"}, "enabled": {"type": "boolean"},
	"items": {"type": "array", "items": {"type": "object", "properties": {"mask": {"type": "array", "items": {"type": "string"}}}}},
	"tasks": {"type": "object", "additionalProperties": {"type": "object", "properties": {"mask": {"type": "array"}}}},
	"settings": {"type": "object"}
}, "required": ["name"]}`

func TestCheck(t *testing.T) {
	var r recorder
	Check(&r, good, config{})
	if len(r.errors) != 0 {
		t.Errorf("a matching schema: %v", r.errors)
	}

	for _, tt := range []struct {
		name, from, to, want string
	}{
		// As Task.Name: a field the schema doesn't allow.
		{"a field missing from the schema", `"name": {"type": "string"}, `, ``, "$.name: a field"},
		{"a property with no field", `"settings": {"type": "object"}`, `"settings": {"type": "object"}, "typo": {"type": "string"}`, "$.typo: a property with no field"},
		{"a type mismatch", `"enabled": {"type": "boolean"}`, `"enabled": {"type": "string"}`, "$.enabled: the schema type string"},
		{"a nested mismatch", `"properties": {"mask": {"type": "array"}}`, `"properties": {"masks": {"type": "array"}}`, "$.tasks.*.masks"},
		{"a required property that isn't one", `"required": ["name"]`, `"required": ["nmae"]`, "required nmae"},
	} {
		var r recorder
		Check(&r, strings.Replace(good, tt.from, tt.to, 1), config{})
		if !strings.Contains(strings.Join(r.errors, "\n"), tt.want) {
			t.Errorf("%s: got %v, want an error with %q", tt.name, r.errors, tt.want)
		}
	}
}
