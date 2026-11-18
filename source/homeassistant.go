package source

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
)

// homeAssistantFetcher reads the addresses in the state of a Home Assistant entity, or of its
// attribute: one or more, separated by commas, semicolons or spaces, as "203.0.113.7" or
// "203.0.113.7, 2001:db8::1". unknown and unavailable, Home Assistant's states for no value, are
// an error, as is Home Assistant not being connected: the addresses then expire.
func homeAssistantFetcher(states HomeAssistantStates, entity, attribute string) fetcher {
	what := entity
	if attribute != "" {
		what += ", attribute " + attribute
	}
	return func(context.Context) ([]netip.Addr, error) {
		state, ok := states.State(entity, attribute)
		if !ok {
			return nil, fmt.Errorf("no state of %s from Home Assistant", what)
		}
		switch strings.ToLower(strings.TrimSpace(state)) {
		case "", "unknown", "unavailable", "none":
			return nil, fmt.Errorf("%s has no value: %q", what, state)
		}
		var addrs []netip.Addr
		for _, field := range strings.FieldsFunc(state, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t' }) {
			addr, err := netip.ParseAddr(field)
			if err != nil {
				return nil, fmt.Errorf("%s: %q is no address", what, field)
			}
			addrs = append(addrs, addr.Unmap())
		}
		return addrs, nil
	}
}
