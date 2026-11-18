package config

import (
	"encoding/json"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/duration"
)

type Credential struct {
	Provider string `json:"provider"`
	// How long the addresses must stay the same before an update.
	DebounceTime duration.Duration `json:"debounce_time,omitempty"`
	// How long to wait after a failed update to try again.
	RetryTime   duration.Duration `json:"retry_time,omitempty"`
	RawSettings json.RawMessage   `json:"settings"`
}

func (c *Credential) UnmarshalJSON(b []byte) error {
	type plain Credential
	credential := plain{
		DebounceTime: duration.Duration{Duration: 10 * time.Second},
		RetryTime:    duration.Duration{Duration: 60 * time.Second},
	}
	if err := json.Unmarshal(b, &credential); err != nil {
		return err
	}
	*c = Credential(credential)
	return nil
}
