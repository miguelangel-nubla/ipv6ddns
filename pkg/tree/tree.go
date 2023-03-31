package tree

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miguelangel-nubla/ipv6disc/pkg/worker"

	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/ddns"
)

type Domain struct {
	HostsMutex sync.RWMutex
	Hosts      []*worker.IPAddressInfo

	mutex sync.RWMutex

	updatedTime time.Time

	updateRunning bool

	updateNext      time.Time
	updateNextTimer *time.Timer

	updateError error
}

type Endpoint struct {
	ID           string
	DomainsMutex sync.RWMutex
	Domains      map[string]*Domain
	Service      ddns.Service
}

type Provider struct {
	endpointsMutex sync.RWMutex
	endpoints      map[string]*Endpoint
}

type Tree struct {
	providersMutex sync.RWMutex
	providers      map[string]*Provider
}

func (tree *Tree) PrettyPrint(tabSize int) string {
	indent := func(level int) string {
		return strings.Repeat(" ", level*tabSize)
	}
	var result strings.Builder

	result.WriteString("Tree:\n")

	tree.providersMutex.RLock()
	defer tree.providersMutex.RUnlock()
	providerKeys := make([]string, 0, len(tree.providers))
	for provider := range tree.providers {
		providerKeys = append(providerKeys, provider)
	}
	sort.Strings(providerKeys)

	for _, providerKey := range providerKeys {
		fmt.Fprintf(&result, indent(1)+"Provider: %s\n", providerKey)

		provider := tree.providers[providerKey]
		provider.endpointsMutex.RLock()
		defer provider.endpointsMutex.RUnlock()

		endpointKeys := make([]string, 0, len(provider.endpoints))
		for endpoint := range provider.endpoints {
			endpointKeys = append(endpointKeys, endpoint)
		}
		sort.Strings(endpointKeys)

		for _, endpointKey := range endpointKeys {
			fmt.Fprintf(&result, indent(2)+"Endpoint: %s\n", endpointKey)

			endpoint := provider.endpoints[endpointKey]
			endpoint.DomainsMutex.RLock()
			defer endpoint.DomainsMutex.RUnlock()

			domainKeys := make([]string, 0, len(endpoint.Domains))
			for domain := range endpoint.Domains {
				domainKeys = append(domainKeys, domain)
			}
			sort.Strings(domainKeys)

			for _, domainKey := range domainKeys {
				fmt.Fprintf(&result, indent(3)+"Domain: %s", domainKey)
				domain := endpoint.Domains[domainKey]
				domain.HostsMutex.RLock()
				defer domain.HostsMutex.RUnlock()

				if domain.updateRunning {
					result.WriteString(" (update running)")
				}
				if domain.updateError != nil {
					fmt.Fprintf(&result, " (error: %s)", domain.updateError)
				}
				if !domain.updatedTime.IsZero() {
					result.WriteString(" (last update: " + domain.updatedTime.Format(time.RFC3339) + ")")
				}
				if !domain.updateNext.IsZero() && domain.updateNext.After(time.Now()) {
					fmt.Fprintf(&result, " (next update: %.0fs)", time.Until(domain.updateNext).Seconds())
				}
				result.WriteString("\n")

				// Sort hosts by hw and then by address
				sort.Slice(domain.Hosts, func(i, j int) bool {
					ipAddressInfo1 := domain.Hosts[i]
					ipAddressInfo2 := domain.Hosts[j]

					ipComparison := strings.Compare(ipAddressInfo1.Address.String(), ipAddressInfo2.Address.String())
					if ipComparison == 0 {
						// If address is equal, compare addresses
						return ipAddressInfo1.Hw.String() < ipAddressInfo2.Hw.String()
					}
					return ipComparison < 0
				})

				// Iterate over the sorted arr
				var lastIp string
				var lastHw string
				for _, ipAddressInfo := range domain.Hosts {
					ip := netip.AddrFrom16(ipAddressInfo.Address.As16()).String()
					if lastIp != ip {
						fmt.Fprintf(&result, indent(4)+"[%s]\n", ip)
						lastIp = ip
					}

					hw := ipAddressInfo.Hw.String()
					if lastHw != hw {
						fmt.Fprintf(&result, indent(5)+"from %s\n", hw)
						lastHw = hw
					}
					fmt.Fprintf(&result, indent(6)+"seen over %s \n", ipAddressInfo.Address.Zone())
				}
			}
		}
	}

	return result.String()
}

func (tree *Tree) Update(config *config.Config, table *worker.Table, stormDelay time.Duration, onUpdate func(endpoint *Endpoint, domain string) error) {
	for _, task := range config.Tasks {
		for endpoint, domains := range task.Endpoints {
			for _, domainName := range domains {
				credential := config.Credentials[endpoint]

				tree.providersMutex.Lock()
				if _, ok := tree.providers[credential.Provider]; !ok {
					tree.providers[credential.Provider] = &Provider{endpoints: make(map[string]*Endpoint)}
				}
				provider := tree.providers[credential.Provider]
				tree.providersMutex.Unlock()

				provider.endpointsMutex.Lock()
				if _, ok := provider.endpoints[endpoint]; !ok {
					service, err := ddns.NewDDNSService(credential.Provider, credential.RawSettings)
					if err != nil {
						panic(fmt.Sprintf("Error creating DDNSService for endpoint %s: %v\n", endpoint, err))
					}

					provider.endpoints[endpoint] = &Endpoint{
						ID:      endpoint,
						Domains: make(map[string]*Domain),
						Service: service,
					}
				}
				endpoint := provider.endpoints[endpoint]
				provider.endpointsMutex.Unlock()

				endpoint.DomainsMutex.Lock()
				if _, ok := endpoint.Domains[domainName]; !ok {
					endpoint.Domains[domainName] = &Domain{Hosts: []*worker.IPAddressInfo{}}
				}
				domain := endpoint.Domains[domainName]
				endpoint.DomainsMutex.Unlock()

				prefixes := []netip.Prefix{}
				for _, subnet := range task.Subnets {
					prefix, err := netip.ParsePrefix(subnet)
					if err != nil {
						continue
					}
					prefixes = append(prefixes, prefix)
				}

				domain.HostsMutex.Lock()
				currentHosts := table.Filter(task.MACAddresses, prefixes)
				existingHosts := domain.Hosts
				if !sameHosts(currentHosts, existingHosts) {
					domain.mutex.Lock()
					if domain.updateNextTimer != nil {
						domain.updateNextTimer.Stop()
					}
					callback := func() {
						domain.mutex.Lock()
						defer domain.mutex.Unlock()
						domain.updateRunning = true

						domain.updateError = onUpdate(endpoint, domainName)
						if domain.updateError == nil {
							domain.updatedTime = time.Now()
						}

						domain.updateRunning = false
					}
					domain.updateNextTimer = time.AfterFunc(stormDelay, callback)
					domain.updateNext = time.Now().Add(stormDelay)
					domain.mutex.Unlock()

					domain.Hosts = currentHosts
				}
				domain.HostsMutex.Unlock()
			}
		}
	}
}

func sameHosts(slice1 []*worker.IPAddressInfo, slice2 []*worker.IPAddressInfo) bool {
	if len(slice1) != len(slice2) {
		return false
	}

	countMap := make(map[*worker.IPAddressInfo]int)

	for _, ptr := range slice1 {
		countMap[ptr]++
	}

	for _, ptr := range slice2 {
		countMap[ptr]--
		if countMap[ptr] < 0 {
			return false
		}
	}

	return true
}

func NewTree() *Tree {
	return &Tree{
		providers: make(map[string]*Provider),
	}
}
