package ipv6ddns

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/ddns"
	"github.com/miguelangel-nubla/ipv6disc"
	"go.uber.org/zap"
)

type InvalidInterfaceError struct {
	iface *net.Interface
}

func (e *InvalidInterfaceError) Error() string {
	return fmt.Sprintf("invalid interface: %s", e.iface.Name)
}

type Worker struct {
	*State
	DiscWorker *ipv6disc.Worker
	logger     *zap.SugaredLogger
	config     config.Config
}

func NewWorker(logger *zap.SugaredLogger, rediscover time.Duration, lifetime time.Duration, config config.Config) *Worker {
	return &Worker{
		State:      NewState(),
		DiscWorker: ipv6disc.NewWorker(logger, rediscover, lifetime),
		logger:     logger,
		config:     config,
	}
}

func (w *Worker) Start() error {
	go func() {
		for {
			// @TODO: instead of proactively searching, be notified from ipv6disc.State.Enlist
			w.lookForChanges()
			time.Sleep(1 * time.Second)
		}
	}()

	return w.DiscWorker.Start()
}

func (w *Worker) lookForChanges() {
	for _, task := range w.config.Tasks {
		for endpointKey, hostnames := range task.Endpoints {
			for _, hostnameKey := range hostnames {
				// Provider creation
				credential := w.config.Credentials[endpointKey]
				w.State.providersMutex.Lock()
				if _, ok := w.State.providers[credential.Provider]; !ok {
					w.State.providers[credential.Provider] = &Provider{endpoints: make(map[string]*Endpoint)}
				}
				provider := w.State.providers[credential.Provider]
				w.State.providersMutex.Unlock()

				// Endpoint creation
				provider.endpointsMutex.Lock()
				if _, ok := provider.endpoints[endpointKey]; !ok {
					service, err := ddns.NewService(credential.Provider, credential.RawSettings)
					if err != nil {
						panic(fmt.Sprintf("Error creating DNS Service for endpoint %s: %v\n", endpointKey, err))
					}

					provider.endpoints[endpointKey] = &Endpoint{
						hostnames: make(map[string]*Hostname),
						service:   service,
					}
				}
				endpoint := provider.endpoints[endpointKey]
				provider.endpointsMutex.Unlock()

				// Hostname creation
				endpoint.hostnamesMutex.Lock()
				if _, ok := endpoint.hostnames[hostnameKey]; !ok {
					endpoint.hostnames[hostnameKey] = &Hostname{}
				}
				hostname := endpoint.hostnames[hostnameKey]
				endpoint.hostnamesMutex.Unlock()

				// Task handling
				prefixes := []netip.Prefix{}
				for _, subnet := range task.Subnets {
					prefix, err := netip.ParsePrefix(subnet)
					if err != nil {
						continue
					}
					prefixes = append(prefixes, prefix)
				}
				currentHosts := w.DiscWorker.Filter(task.MACAddresses, prefixes)
				if !hostname.AddrCollection.Equal(currentHosts) {
					// capture references to the current values
					currenthostnameKey := hostnameKey
					currentEndpoint := endpoint
					action := func() error {
						w.logger.Debugf("endpoint %s starting update of: %s", endpointKey, currenthostnameKey)

						addrCollection, err := currentEndpoint.Update(currenthostnameKey)
						if err != nil {
							w.logger.Errorf("endpoint %s error updating %s: %s", endpointKey, currenthostnameKey, err)
						} else {
							w.logger.Infof("endpoint %s successfully updated %s: %v", endpointKey, currenthostnameKey, addrCollection.Strings())
						}

						return err
					}
					hostname.ScheduleUpdate(credential.DebounceTime, action)

					hostname.mutex.Lock()
					hostname.AddrCollection = *currentHosts.Copy()
					hostname.mutex.Unlock()
				}
			}
		}
	}
}

func (w *Worker) PrettyPrint(prefix string) string {
	var result strings.Builder
	fmt.Fprint(&result, w.State.PrettyPrint(prefix))
	fmt.Fprint(&result, w.DiscWorker.State.PrettyPrint(prefix))
	fmt.Fprint(&result, w.config.PrettyPrint(prefix))
	return result.String()
}
