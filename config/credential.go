package config

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/duration"
)

type Credential struct {
	Provider string `json:"provider"`
	// How long the addresses must stay the same before an update.
	Debounce duration.Duration `json:"debounce,omitzero"`
	// How long to wait after a failed update to try again.
	Retry       duration.Duration `json:"retry,omitzero"`
	RawSettings json.RawMessage   `json:"settings"`

	// Deprecated: debounce and retry. UnmarshalJSON moves them there, and NewConfig warns.
	DebounceTime *duration.Duration `json:"debounce_time,omitempty"`
	RetryTime    *duration.Duration `json:"retry_time,omitempty"`
	deprecated   []string
}

// MinRetry is the least time between a failed update and its retry.
const MinRetry = time.Second

func (c *Credential) UnmarshalJSON(b []byte) error {
	type plain Credential
	var credential struct {
		plain
		Debounce *duration.Duration `json:"debounce"`
		Retry    *duration.Duration `json:"retry"`
	}
	if err := json.Unmarshal(b, &credential); err != nil {
		return err
	}
	*c = Credential(credential.plain)
	for _, f := range []struct {
		name, old string
		value     *duration.Duration
		oldValue  **duration.Duration
		into      *duration.Duration
		def       time.Duration
	}{
		{"debounce", "debounce_time", credential.Debounce, &c.DebounceTime, &c.Debounce, 10 * time.Second},
		{"retry", "retry_time", credential.Retry, &c.RetryTime, &c.Retry, time.Minute},
	} {
		switch {
		case f.value != nil && *f.oldValue != nil:
			return fmt.Errorf("%s is the deprecated form of %s: give one of them", f.old, f.name)
		case f.value != nil:
			*f.into = *f.value
		case *f.oldValue != nil:
			*f.into, *f.oldValue = **f.oldValue, nil
			c.deprecated = append(c.deprecated, f.old)
		default:
			f.into.Duration = f.def
		}
	}
	return nil
}
