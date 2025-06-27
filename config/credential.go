package config

import (
	"encoding/json"
	"errors"
	"fmt"
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
		aux.DebounceTime = "10s"
	}
	if aux.RetryTime == nil {
		aux.RetryTime = "60s"
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
		return errors.New("invalid debounce time: " + fmt.Sprintf("%#v", value))
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
		return errors.New("invalid retry time: " + fmt.Sprintf("%#v", value))
	}

	return nil
}
