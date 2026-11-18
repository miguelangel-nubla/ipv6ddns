package duration

import (
	"encoding/json"
	"testing"
)

func FuzzUnmarshalJSON(f *testing.F) {
	for _, s := range []string{`"1h30m"`, `90`, `0.5`, `null`, `"soon"`, `[]`, `"-1s"`, `1e30`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		var d Duration
		if err := json.Unmarshal([]byte(input), &d); err != nil {
			return
		}
		// What it reads, it writes back the same.
		out, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		var again Duration
		if err := json.Unmarshal(out, &again); err != nil || again != d {
			t.Errorf("%s: read %s, written %s, read back %s, %v", input, d, out, again, err)
		}
	})
}
