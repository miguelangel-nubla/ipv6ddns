// Package duration reads the durations of the configuration: a Go duration string, or a number of
// seconds.
package duration

import (
	"encoding/json"
	"fmt"
	"math"
	"time"
)

// Duration is a time.Duration the configuration gives. Any that reads is taken, a negative one
// too: each key checks the range it takes, as blocklists.<name>.interval, an hour at least.
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
		// Beyond what a time.Duration holds, about 292 years, the conversion depends on the
		// machine: negative on some.
		nanoseconds := value * float64(time.Second)
		if nanoseconds >= math.MaxInt64 || nanoseconds <= math.MinInt64 {
			return fmt.Errorf("invalid duration: %s seconds is out of range", b)
		}
		d.Duration = time.Duration(nanoseconds)
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
