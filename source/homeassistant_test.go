package source

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type fakeStates map[string]string

func (f fakeStates) State(entity, attribute string) (string, error) {
	s, ok := f[entity+"/"+attribute]
	if !ok {
		return "", fmt.Errorf("%w for Home Assistant to send the state", ErrWaiting)
	}
	return s, nil
}

func TestHomeAssistantFetcher(t *testing.T) {
	states := fakeStates{
		"sensor.wan/":          "203.0.113.7",
		"sensor.both/":         "203.0.113.7, 2001:db8::1",
		"sensor.router/wan_ip": "198.51.100.2",
		"sensor.down/":         "unavailable",
		"sensor.text/":         "connected",
		"sensor.mapped/":       "::ffff:192.0.2.1",
	}
	for _, c := range []struct{ entity, attribute, want string }{
		{"sensor.wan", "", "[203.0.113.7]"},
		{"sensor.both", "", "[203.0.113.7 2001:db8::1]"},
		{"sensor.router", "wan_ip", "[198.51.100.2]"},
		{"sensor.mapped", "", "[192.0.2.1]"},
		{"sensor.down", "", "waiting: waiting for sensor.down, \"unavailable\" now"},
		{"sensor.text", "", "error: is no address"},
		{"sensor.missing", "", "waiting: sensor.missing: waiting for Home Assistant to send the state"},
	} {
		addrs, err := homeAssistantFetcher(states, c.entity, c.attribute)(context.Background())
		got := fmt.Sprint(addrs)
		switch {
		case errors.Is(err, ErrWaiting):
			got = "waiting: " + err.Error()
		case err != nil:
			got = "error: " + err.Error()
		}
		if prefix, rest, _ := strings.Cut(c.want, ": "); prefix != "error" && prefix != "waiting" && got != c.want ||
			(prefix == "error" || prefix == "waiting") && !strings.HasPrefix(got, prefix+": ") ||
			(prefix == "error" || prefix == "waiting") && !strings.Contains(got, rest) {
			t.Errorf("%s/%s: %s, want %s", c.entity, c.attribute, got, c.want)
		}
	}
}
