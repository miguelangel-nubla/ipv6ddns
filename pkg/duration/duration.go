// Package duration reads the durations of the configuration: a Go duration string, or a number of
// seconds.
package duration

import (
	"encoding/json"
	"fmt"
	"time"
)

type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var value any
	if err := json.Unmarshal(b, &value); err != nil {
		return err
	}

	switch value := value.(type) {
	case nil:
		// Keep the default.
	case float64:
		d.Duration = time.Duration(value * float64(time.Second))
	case string:
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return err
		}
		d.Duration = parsed
	default:
		return fmt.Errorf("invalid duration: %s", b)
	}
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}
