package duration

import (
	"encoding/json"
	"testing"
	"time"
)

func TestUnmarshalJSON(t *testing.T) {
	for in, want := range map[string]time.Duration{
		`"1m30s"`: 90 * time.Second,
		`90`:      90 * time.Second,
		`0.5`:     500 * time.Millisecond,
		`null`:    time.Hour,
	} {
		d := Duration{time.Hour}
		if err := json.Unmarshal([]byte(in), &d); err != nil || d.Duration != want {
			t.Errorf("%s: got %s, %v, want %s", in, d, err, want)
		}
	}
	for _, in := range []string{`"soon"`, `true`, `[]`} {
		var d Duration
		if err := json.Unmarshal([]byte(in), &d); err == nil {
			t.Errorf("%s: want an error", in)
		}
	}
}
