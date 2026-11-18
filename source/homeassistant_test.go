package source

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

type fakeStates map[string]string

func (f fakeStates) State(entity, attribute string) (string, bool) {
	s, ok := f[entity+"/"+attribute]
	return s, ok
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
		{"sensor.down", "", "error: has no value"},
		{"sensor.text", "", "error: is no address"},
		{"sensor.missing", "", "error: no state"},
	} {
		addrs, err := homeAssistantFetcher(states, c.entity, c.attribute)(context.Background())
		got := fmt.Sprint(addrs)
		if err != nil {
			got = "error: " + err.Error()
		}
		if !strings.HasPrefix(c.want, "error") && got != c.want || strings.HasPrefix(c.want, "error") && !strings.Contains(got, strings.TrimPrefix(c.want, "error: ")) {
			t.Errorf("%s/%s: %s, want %s", c.entity, c.attribute, got, c.want)
		}
	}
}
