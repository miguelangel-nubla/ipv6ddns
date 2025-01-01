package config

import (
	"encoding/json"
	"errors"
	"time"
)

type Credential struct {
	Provider     string          `json:"provider"`
	DebounceTime time.Duration   `json:"debounce_time,omitempty"`
	RetryTime    time.Duration   `json:"retry_time,omitempty"`
	RawSettings  json.RawMessage `json:"settings"`
}

func (c *Credential) UnmarshalJSON(b []byte) error {
	type Alias Credential
	aux := &struct {
		DebounceTime interface{} `json:"debounce_time"`
		RetryTime    interface{} `json:"retry_time"`
		*Alias
	}{
		Alias: (*Alias)(c),
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}

	if aux.DebounceTime == nil {
		c.DebounceTime = 10 * time.Second
		return nil
	}
	if aux.RetryTime == nil {
		c.RetryTime = 60 * time.Second
		return nil
	}

	switch value := aux.DebounceTime.(type) {
	case float64:
		c.DebounceTime = time.Duration(value) * time.Second
	case string:
		var err error
		c.DebounceTime, err = time.ParseDuration(value)
		if err != nil {
			return err
		}
	default:
		return errors.New("invalid debounce time")
	}

	switch value := aux.RetryTime.(type) {
	case float64:
		c.RetryTime = time.Duration(value) * time.Second
	case string:
		var err error
		c.RetryTime, err = time.ParseDuration(value)
		if err != nil {
			return err
		}
	default:
		return errors.New("invalid retry time")
	}

	return nil
}
