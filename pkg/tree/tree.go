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

	updateNext      time.Time
	updateNextTimer *time.Timer

	updateRunning bool
	updateError   error

	updateAction        func() error
	updateRetryInterval time.Duration
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
				if !domain.updateNext.IsZero() && domain.updateNext.After(time.Now()) {
					fmt.Fprintf(&result, " (next update: %.0fs)", time.Until(domain.updateNext).Seconds())
				}
				if !domain.updatedTime.IsZero() {
					result.WriteString(" (last update: " + domain.updatedTime.Format(time.RFC3339) + ")")
				}
				if domain.updateError != nil {
					fmt.Fprintf(&result, " (last update error: %s)", domain.updateError)
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
		for endpointId, domains := range task.Endpoints {
			for _, domainName := range domains {
				credential := config.Credentials[endpointId]

				tree.providersMutex.Lock()
				if _, ok := tree.providers[credential.Provider]; !ok {
					tree.providers[credential.Provider] = &Provider{endpoints: make(map[string]*Endpoint)}
				}
				provider := tree.providers[credential.Provider]
				tree.providersMutex.Unlock()

				provider.endpointsMutex.Lock()
				if _, ok := provider.endpoints[endpointId]; !ok {
					service, err := ddns.NewDDNSService(credential.Provider, credential.RawSettings)
					if err != nil {
						panic(fmt.Sprintf("Error creating DDNSService for endpoint %s: %v\n", endpointId, err))
					}

					provider.endpoints[endpointId] = &Endpoint{
						ID:      endpointId,
						Domains: make(map[string]*Domain),
						Service: service,
					}
				}

				endpoint := provider.endpoints[endpointId]
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

					// stop the current update timer if it exists
					if domain.updateNextTimer != nil {
						domain.updateNextTimer.Stop()
						domain.updateNext = time.Time{}
					}

					domain.updateRetryInterval = stormDelay

					// capture references to the current values
					currentDomainName := domainName
					currentEndpoint := endpoint
					domain.updateAction = func() error {
						return onUpdate(currentEndpoint, currentDomainName)
					}

					domain.updateNextTimer = time.AfterFunc(stormDelay, domain.update)
					domain.updateNext = time.Now().Add(stormDelay)

					domain.Hosts = currentHosts

					domain.mutex.Unlock()
				}
				domain.HostsMutex.Unlock()
			}
		}
	}
}

func (domain *Domain) update() {
	domain.mutex.Lock()
	defer domain.mutex.Unlock()

	domain.updateRunning = true

	domain.updateError = domain.updateAction()
	if domain.updateError == nil {
		domain.updatedTime = time.Now()
	} else {
		domain.updateNextTimer = time.AfterFunc(domain.updateRetryInterval, domain.update)
		domain.updateNext = time.Now().Add(domain.updateRetryInterval)
	}

	domain.updateRunning = false
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
