package ipv6ddns

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/ddns"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/filter"
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
	discWorker *ipv6disc.Worker
	logger     *zap.SugaredLogger
	config     config.Config
}

func (w *Worker) Start() error {
	for _, task := range w.config.Tasks {
		if task.IPv4 != nil && !task.IPv4.Running() {
			err := task.IPv4.Start(w.config.BaseDir, w.logger)
			if err != nil {
				return fmt.Errorf("error starting IPv4 handler for task %s: %w", task.Name, err)
			}
		}
	}

	go func() {
		for {
			// @TODO: instead of proactively searching, be notified from ipv6disc.AddrCollection.Seen
			w.lookForChanges()
			time.Sleep(1 * time.Second)
		}
	}()

	return w.discWorker.Start()
}

func (w *Worker) RegisterPlugin(p ipv6disc.Plugin) {
	w.discWorker.RegisterPlugin(p)
}

func (w *Worker) lookForChanges() {
	for _, task := range w.config.Tasks {
		for endpointKey, hostnames := range task.Endpoints {
			// Provider creation
			credential := w.config.Credentials[endpointKey]
			w.State.providersMutex.Lock()
			if _, ok := w.State.providers[credential.Provider]; !ok {
				w.State.providers[credential.Provider] = NewProvider()
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

				provider.endpoints[endpointKey] = NewEndpoint(service)
			}
			endpoint := provider.endpoints[endpointKey]
			provider.endpointsMutex.Unlock()

			for _, hostnameKey := range hostnames {
				// Hostname creation
				endpoint.hostnamesMutex.Lock()
				if _, ok := endpoint.hostnames[hostnameKey]; !ok {
					// capture references to the current values
					currenthostnameKey := hostnameKey
					currentEndpoint := endpoint
					updateAction := func(addrCollection *ipv6disc.AddrCollection) error {
						w.logger.Debugf("endpoint %s starting update of: %s", endpointKey, currenthostnameKey)

						err := currentEndpoint.Update(currenthostnameKey, addrCollection)
						if err != nil {
							w.logger.Errorf("endpoint %s error updating %s: %s", endpointKey, currenthostnameKey, err)
						} else {
							w.logger.Infof("endpoint %s successfully updated %s: %v", endpointKey, currenthostnameKey, addrCollection.Strings())
						}

						return err
					}
					endpoint.hostnames[hostnameKey] = NewHostname(updateAction, credential.DebounceTime, credential.RetryTime)
				}
				hostname := endpoint.hostnames[hostnameKey]
				endpoint.hostnamesMutex.Unlock()

				currentHosts := ipv6disc.NewAddrCollection()
				for _, collection := range w.discWorker.GetAll() {
					for _, addr := range collection.Get() {
						match := false
						for _, f := range task.Filters {
							if !filter.CheckMAC(addr.Hw, f.MAC.Address) {
								continue
							}
							if !filter.CheckMACMask(addr.Hw, f.MAC.Mask) {
								continue
							}
							if !filter.CheckMACType(addr.Hw, f.MAC.Type) {
								continue
							}
							if !filter.CheckIPType(addr, f.IP.Type) {
								continue
							}
							if !filter.CheckPrefix(addr.Addr, f.IP.Prefix) {
								continue
							}
							if !filter.CheckSuffix(addr.Addr, f.IP.Suffix) {
								continue
							}
							if !filter.CheckMask(addr.Addr, f.IP.Mask) {
								continue
							}
							if !filter.CheckSource(addr, f.Source) {
								continue
							}
							match = true
							break
						}

						if match {
							currentHosts.Add(addr)
						}
					}
				}
				if task.IPv4 != nil {
					currentHosts.Join(task.IPv4.AddrCollection)
				}
				hostname.SetAddrCollection(currentHosts)
			}
		}
	}
}

func (w *Worker) PrettyPrint(prefix string, hideSensible bool) string {
	var result strings.Builder
	fmt.Fprint(&result, w.State.PrettyPrint(prefix, hideSensible))
	fmt.Fprint(&result, w.discWorker.State.PrettyPrint(prefix, hideSensible))
	fmt.Fprint(&result, w.discWorker.PrettyPrintStats(prefix))
	fmt.Fprint(&result, w.config.PrettyPrint(prefix, hideSensible))
	return result.String()
}

func NewWorker(logger *zap.SugaredLogger, rediscover time.Duration, lifetime time.Duration, config config.Config) *Worker {
	return &Worker{
		State:      NewState(),
		discWorker: ipv6disc.NewWorker(logger, rediscover, lifetime, config.Discovery.Listen, config.Discovery.Active),
		logger:     logger,
		config:     config,
	}
}
