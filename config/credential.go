package config

import (
	"encoding/json"
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
}

// MinRetry is the least time between a failed update and its retry.
const MinRetry = time.Second

// UnmarshalJSON reads the credential, with the defaults of what it leaves out: a debounce of 10s,
// or the resolver's, and a retry of a minute.
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
	c.Debounce.Duration = 10 * time.Second
	if c.Provider == ResolverProvider {
		c.Debounce.Duration = DefaultResolverDebounce
	}
	if credential.Debounce != nil {
		c.Debounce = *credential.Debounce
	}
	c.Retry.Duration = time.Minute
	if credential.Retry != nil {
		c.Retry = *credential.Retry
	}
	return nil
}
