package ipv6ddns

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/ddns"
)

// State holds the host names to update, by provider and endpoint. It is built once, so its maps
// don't change after.
type State struct {
	providers map[string]*Provider
}

type Provider struct {
	endpoints map[string]*Endpoint
}

// Endpoint is a credential: a DNS service, with the host names it updates.
type Endpoint struct {
	ddns.Service
	// The host names, by their first spelling in the configuration.
	hostnames map[string]*Hostname
	// The same, by the name of their records: see recordName.
	names map[string]*Hostname
	// One update of the service at a time, whatever the name: the providers read the records and
	// then change them, some over a session each, and all the names of a task change at once.
	updateMutex sync.Mutex
}

func NewState() *State {
	return &State{
		providers: make(map[string]*Provider),
	}
}

func NewProvider() *Provider {
	return &Provider{
		endpoints: make(map[string]*Endpoint),
	}
}

func NewEndpoint(service ddns.Service) *Endpoint {
	return &Endpoint{
		Service:   service,
		hostnames: make(map[string]*Hostname),
		names:     make(map[string]*Hostname),
	}
}

func (s *State) PrettyPrint(prefix string, hideSensible bool) string {
	var result strings.Builder

	fmt.Fprintf(&result, "%sDNS:\n", prefix)

	for _, providerKey := range slices.Sorted(maps.Keys(s.providers)) {
		fmt.Fprintf(&result, "%s    Provider: %s\n", prefix, providerKey)
		provider := s.providers[providerKey]

		for _, endpointKey := range slices.Sorted(maps.Keys(provider.endpoints)) {
			fmt.Fprintf(&result, "%s        Endpoint: %s\n", prefix, endpointKey)
			endpoint := provider.endpoints[endpointKey]

			for _, hostnameKey := range slices.Sorted(maps.Keys(endpoint.hostnames)) {
				fmt.Fprintf(&result, "%s            %s:", prefix, endpoint.Domain(hostnameKey))
				writeHostnameStatus(&result, prefix+"                ", endpoint.hostnames[hostnameKey].status(), hideSensible)
			}
		}
	}

	return result.String()
}

func writeHostnameStatus(result *strings.Builder, prefix string, status hostnameStatus, hideSensible bool) {
	if status.updateRunning {
		fmt.Fprint(result, " (update running)")
	}
	if status.nextUpdateTime.After(time.Now()) {
		fmt.Fprintf(result, " (next update: %v)", time.Until(status.nextUpdateTime).Round(time.Second))
	}
	if !status.updatedTime.IsZero() {
		fmt.Fprintf(result, " (last update: %s)", status.updatedTime.Format(time.RFC3339))
	}
	if status.updateError != nil {
		err := status.updateError.Error()
		if hideSensible {
			err = "<sensible data hidden>"
		}
		fmt.Fprintf(result, " (last update error: %s)", err)
	}

	// One line per address: the MAC and what saw it, for a discovered one; the source, for one
	// without a MAC.
	for _, addr := range status.addrs.Get() {
		ip := addr.WithZone("").String()
		if addr.Is6() {
			ip = "[" + ip + "]"
		}
		sources := strings.Join(addr.Sources(), ",")
		if len(addr.Hw) == 0 {
			fmt.Fprintf(result, "\n%s%s from source %s", prefix, ip, sources)
		} else {
			fmt.Fprintf(result, "\n%s%s from %s seen over %s", prefix, ip, addr.Hw, sources)
		}
	}

	fmt.Fprint(result, "\n")
}
