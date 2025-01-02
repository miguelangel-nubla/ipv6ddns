package ipv6ddns

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type State struct {
	providersMutex sync.RWMutex
	providers      map[string]*Provider
}

func (s *State) PrettyPrint(prefix string, hideSensible bool) string {
	var result strings.Builder

	fmt.Fprintf(&result, "%sDNS:\n", prefix)

	s.providersMutex.RLock()
	defer s.providersMutex.RUnlock()
	providerKeys := make([]string, 0, len(s.providers))
	for provider := range s.providers {
		providerKeys = append(providerKeys, provider)
	}
	sort.Strings(providerKeys)

	for _, providerKey := range providerKeys {
		fmt.Fprintf(&result, "%s    Provider: %s\n", prefix, providerKey)

		provider := s.providers[providerKey]
		provider.endpointsMutex.RLock()

		endpointKeys := make([]string, 0, len(provider.endpoints))
		for endpoint := range provider.endpoints {
			endpointKeys = append(endpointKeys, endpoint)
		}
		sort.Strings(endpointKeys)

		for _, endpointKey := range endpointKeys {
			fmt.Fprintf(&result, "%s        Endpoint: %s\n", prefix, endpointKey)

			endpoint := provider.endpoints[endpointKey]
			endpoint.hostnamesMutex.RLock()

			hostnamesKeys := make([]string, 0, len(endpoint.hostnames))
			for hostname := range endpoint.hostnames {
				hostnamesKeys = append(hostnamesKeys, hostname)
			}
			sort.Strings(hostnamesKeys)

			for _, hostnameKey := range hostnamesKeys {
				fmt.Fprintf(&result, "%s            %s:", prefix, endpoint.Domain(hostnameKey))
				hostname := endpoint.hostnames[hostnameKey]
				hostname.mutex.RLock()

				if hostname.updateRunning {
					fmt.Fprint(&result, " (update running)")
				}
				if !hostname.nextUpdateTime.IsZero() && hostname.nextUpdateTime.After(time.Now()) {
					fmt.Fprintf(&result, " (next update: %v)", time.Until(hostname.nextUpdateTime).Round(time.Second))
				}
				if !hostname.updatedTime.IsZero() {
					fmt.Fprintf(&result, " (last update: %s)", hostname.updatedTime.Format(time.RFC3339))
				}
				if hostname.updateError != nil {
					err := hostname.updateError
					if hideSensible {
						err = fmt.Errorf("<sensible data hidden>")
					}
					fmt.Fprintf(&result, " (last update error: %s)", err)
				}

				var lastIp string
				var lastHw string
				// Iterate over the already sorted arr
				for _, addr := range hostname.AddrCollection.Get() {
					ip := addr.WithZone("").String()
					if addr.Is6() {
						ip = "[" + ip + "]"
					}
					if lastIp != ip {
						fmt.Fprintf(&result, "\n%s                %s", prefix, ip)
						lastIp = ip
						lastHw = ""
					}

					if addr.Is6() {
						hw := addr.Hw.String()
						if lastHw != hw {
							fmt.Fprintf(&result, " from %s seen over", hw)
							lastHw = hw
						}

						fmt.Fprintf(&result, " %s", addr.Addr.Zone())
					}
				}

				fmt.Fprint(&result, "\n")

				hostname.mutex.RUnlock()
			}

			endpoint.hostnamesMutex.RUnlock()
		}

		provider.endpointsMutex.RUnlock()
	}

	return result.String()
}

func NewState() *State {
	return &State{
		providers: make(map[string]*Provider),
	}
}
