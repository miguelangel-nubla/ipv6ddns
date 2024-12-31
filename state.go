package ipv6ddns

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"

	"github.com/miguelangel-nubla/ipv6ddns/ddns"
)

type Hostname struct {
	ipv6disc.AddrCollection

	mutex sync.RWMutex

	updatedTime time.Time

	nextUpdateTime  time.Time
	nextUpdateTimer *time.Timer

	updateRunning bool
	updateError   error

	updateAction        func() error
	updateRetryInterval time.Duration
}

type Endpoint struct {
	hostnamesMutex sync.RWMutex
	hostnames      map[string]*Hostname
	service        ddns.Service
}

func (e *Endpoint) Update(hostname string) (*ipv6disc.AddrCollection, error) {
	e.hostnamesMutex.RLock()
	h := e.hostnames[hostname]
	// just copy it for now
	addrCollection := h.AddrCollection.Copy()
	e.hostnamesMutex.RUnlock()

	return addrCollection, e.service.Update(hostname, addrCollection)
}

type Provider struct {
	endpointsMutex sync.RWMutex
	endpoints      map[string]*Endpoint
}

type State struct {
	providersMutex sync.RWMutex
	providers      map[string]*Provider
}

func (hostname *Hostname) update() {
	hostname.mutex.Lock()
	hostname.updateRunning = true
	hostname.mutex.Unlock()

	// no mutex lock while working
	err := hostname.updateAction()

	hostname.mutex.Lock()
	hostname.updateError = err
	if hostname.updateError == nil {
		hostname.updatedTime = time.Now()
	} else {
		hostname.reScheduleUpdate()
	}
	hostname.updateRunning = false
	hostname.mutex.Unlock()
}

func (hostname *Hostname) reScheduleUpdate() {
	hostname.mutex.Lock()
	defer hostname.mutex.Unlock()

	// stop the current update timer if it exists
	if hostname.nextUpdateTimer != nil {
		hostname.nextUpdateTimer.Stop()
		hostname.nextUpdateTime = time.Time{}
	}

	hostname.nextUpdateTimer = time.AfterFunc(hostname.updateRetryInterval, hostname.update)
	hostname.nextUpdateTime = time.Now().Add(hostname.updateRetryInterval)
}

func (state *State) PrettyPrint(prefix string) string {
	var result strings.Builder

	fmt.Fprintf(&result, "%sDNS:\n", prefix)

	state.providersMutex.RLock()
	defer state.providersMutex.RUnlock()
	providerKeys := make([]string, 0, len(state.providers))
	for provider := range state.providers {
		providerKeys = append(providerKeys, provider)
	}
	sort.Strings(providerKeys)

	for _, providerKey := range providerKeys {
		fmt.Fprintf(&result, "%s    Provider: %s\n", prefix, providerKey)

		provider := state.providers[providerKey]
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
				fmt.Fprintf(&result, "%s            %s:", prefix, endpoint.service.Domain(hostnameKey))
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
					fmt.Fprintf(&result, " (last update error: %s)", hostname.updateError)
				}

				var lastIp string
				var lastHw string
				// Iterate over the already sorted arr
				for _, addr := range hostname.AddrCollection.Get() {
					ip := netip.AddrFrom16(addr.Addr.As16()).String()
					if lastIp != ip {
						fmt.Fprintf(&result, "\n%s                [%s]", prefix, ip)
						lastIp = ip
						lastHw = ""
					}

					hw := addr.Hw.String()
					if lastHw != hw {
						fmt.Fprintf(&result, " from %s seen over", hw)
						lastHw = hw
					}

					fmt.Fprintf(&result, " %s", addr.Addr.Zone())
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

func (hostname *Hostname) ScheduleUpdate(debounceTime time.Duration, action func() error) {
	hostname.mutex.Lock()
	// stop the current update timer if it exists
	if hostname.nextUpdateTimer != nil {
		hostname.nextUpdateTimer.Stop()
		hostname.nextUpdateTime = time.Time{}
	}
	hostname.updateAction = action
	hostname.updateRetryInterval = debounceTime
	hostname.mutex.Unlock()
	hostname.reScheduleUpdate()
}

func NewState() *State {
	return &State{
		providers: make(map[string]*Provider),
	}
}
