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
	// 1e12 and such: more seconds than a time.Duration holds.
	for _, in := range []string{`"soon"`, `true`, `[]`, `1e12`, `-1e12`, `1e300`, `9223372036.854775807`} {
		var d Duration
		if err := json.Unmarshal([]byte(in), &d); err == nil {
			t.Errorf("%s: want an error", in)
		}
	}
}
