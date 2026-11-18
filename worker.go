package ipv6ddns

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/ddns"
	"github.com/miguelangel-nubla/ipv6ddns/source"
	"github.com/miguelangel-nubla/ipv6disc"
	"go.uber.org/zap"
)

// rematchInterval is how often the worker matches the addresses against the tasks with nothing
// telling it to: for the addresses of sources that outlive their lifetime, which nothing tells.
// The discovery's changes, and every run of a source, make it match at once.
const rematchInterval = 10 * time.Second

type Worker struct {
	*State
	discWorker *ipv6disc.Worker
	logger     *zap.SugaredLogger
	config     config.Config
	targets    []*target
	// The sources of addresses without a MAC, by name.
	sources map[string]*source.Source
	// A value tells the worker to match again; changes coming faster are matched once.
	rematch chan struct{}
	// The device of Home Assistant's ESPHome integration, without the homeassistant block nil.
	homeAssistant *homeAssistant
	// The goroutines Start starts, for Shutdown.
	running sync.WaitGroup
}

// target is a host name at an endpoint, with the tasks that give it addresses. A name in more than
// one task gets the addresses of all of them.
type target struct {
	hostname *Hostname
	tasks    []config.Task
}

// NewWorker makes the worker of the configuration; Start runs it. A lifetime left zero is an
// hour; a rediscovery interval, a third of the shortest lifetime of the families on.
func NewWorker(logger *zap.SugaredLogger, cfg config.Config) (*Worker, error) {
	lifetime := cfg.Lifetime.Duration
	if lifetime == 0 {
		lifetime = config.DefaultLifetime
	}
	w := &Worker{
		State: NewState(),
		discWorker: ipv6disc.NewWorker(logger, ipv6disc.Config{
			Lifetime:   lifetime,
			Rediscover: cfg.Discovery.Rediscover.Duration,
			IPv6:       discoveryFamily(cfg.Discovery.IPv6),
			IPv4:       discoveryFamily(cfg.Discovery.IPv4),

			Interfaces:        cfg.Discovery.Interfaces,
			ExcludeInterfaces: cfg.Discovery.ExcludeInterfaces,
		}),
		logger:  logger,
		config:  cfg,
		sources: make(map[string]*source.Source),
		rematch: make(chan struct{}, 1),
	}

	// Home Assistant's states for its sources; nil, not a nil *homeAssistant, without it.
	var states source.HomeAssistantStates
	if cfg.HomeAssistant != nil {
		h, err := newHomeAssistant(*cfg.HomeAssistant)
		if err != nil {
			return nil, err
		}
		h.device.Logger = logger
		w.homeAssistant, states = h, h
	}

	for name, sourceConfig := range cfg.Sources {
		s, err := source.New(name, sourceConfig, cfg.BaseDir, states)
		if err != nil {
			return nil, err
		}
		w.sources[name] = s
		if sourceConfig.Type == config.SourceHomeAssistant {
			w.homeAssistant.subscribe(sourceConfig.Entity, sourceConfig.Attribute, s.Trigger)
		}
	}

	targets := make(map[*Hostname]*target)
	for _, taskName := range slices.Sorted(maps.Keys(cfg.Tasks)) {
		task := cfg.Tasks[taskName]
		for _, endpointKey := range slices.Sorted(maps.Keys(task.Endpoints)) {
			endpoint, err := w.endpoint(endpointKey)
			if err != nil {
				return nil, err
			}
			for _, hostnameKey := range task.Endpoints[endpointKey] {
				hostname := w.hostname(endpointKey, endpoint, hostnameKey)
				t, ok := targets[hostname]
				if !ok {
					t = &target{hostname: hostname}
					targets[hostname] = t
					w.targets = append(w.targets, t)
				}
				t.tasks = append(t.tasks, task)
			}
		}
	}

	if w.homeAssistant != nil {
		var names []haName
		for _, providerKey := range slices.Sorted(maps.Keys(w.State.providers)) {
			provider := w.State.providers[providerKey]
			for _, endpointKey := range slices.Sorted(maps.Keys(provider.endpoints)) {
				endpoint := provider.endpoints[endpointKey]
				for _, hostnameKey := range slices.Sorted(maps.Keys(endpoint.hostnames)) {
					names = append(names, haName{endpointKey, hostnameKey, endpoint.Domain(hostnameKey)})
				}
			}
		}
		w.homeAssistant.addEntities(names, w.updateNow)
	}

	// The credentials no task names are checked too: a mistake shows at the start.
	for _, name := range slices.Sorted(maps.Keys(cfg.Credentials)) {
		credential := cfg.Credentials[name]
		if provider, ok := w.State.providers[credential.Provider]; ok && provider.endpoints[name] != nil {
			continue
		}
		if _, err := ddns.NewService(credential.Provider, credential.RawSettings); err != nil {
			return nil, fmt.Errorf("error creating DNS service for endpoint %s: %w", name, err)
		}
	}

	return w, nil
}

// endpoint returns the endpoint of a credential, making its service the first time.
func (w *Worker) endpoint(endpointKey string) (*Endpoint, error) {
	credential, ok := w.config.Credentials[endpointKey]
	if !ok {
		return nil, fmt.Errorf("no credential %s", endpointKey)
	}

	provider, ok := w.State.providers[credential.Provider]
	if !ok {
		provider = NewProvider()
		w.State.providers[credential.Provider] = provider
	}

	endpoint, ok := provider.endpoints[endpointKey]
	if !ok {
		service, err := ddns.NewService(credential.Provider, credential.RawSettings)
		if err != nil {
			return nil, fmt.Errorf("error creating DNS service for endpoint %s: %w", endpointKey, err)
		}
		endpoint = NewEndpoint(service)
		provider.endpoints[endpointKey] = endpoint
	}
	return endpoint, nil
}

func (w *Worker) hostname(endpointKey string, endpoint *Endpoint, hostnameKey string) *Hostname {
	if hostname, ok := endpoint.hostnames[hostnameKey]; ok {
		return hostname
	}

	credential := w.config.Credentials[endpointKey]
	updateAction := func(addrCollection *ipv6disc.AddrCollection) error {
		w.logger.Debugf("endpoint %s starting update of: %s", endpointKey, hostnameKey)

		err := endpoint.Update(hostnameKey, addrCollection)
		if warner, ok := endpoint.Service.(ddns.Warner); ok {
			for _, warning := range warner.Warnings() {
				w.logger.Warnf("endpoint %s: %s", endpointKey, warning)
			}
		}
		if err != nil {
			w.logger.Errorf("endpoint %s error updating %s: %s", endpointKey, hostnameKey, err)
		} else {
			w.logger.Infof("endpoint %s successfully updated %s: %v", endpointKey, hostnameKey, addrCollection.Strings())
		}

		return err
	}
	hostname := NewHostname(updateAction, credential.DebounceTime.Duration, credential.RetryTime.Duration)
	endpoint.hostnames[hostnameKey] = hostname
	return hostname
}

// Start runs the discovery, the IPv4 commands and the updates, until ctx is done. Shutdown waits
// for them to stop.
func (w *Worker) Start(ctx context.Context) error {
	for _, warning := range w.config.Warnings {
		w.logger.Warn(warning)
	}

	if err := w.discWorker.Start(ctx); err != nil {
		return err
	}
	if h := w.homeAssistant; h != nil {
		if err := h.serve(ctx, w.logger.Errorf); err != nil {
			return err
		}
		w.running.Add(1)
		go func() {
			defer w.running.Done()
			h.follow(ctx, func() Status { return w.Status(false) })
		}()
	}
	changes, unsubscribe := w.discWorker.State.Subscribe()
	for _, name := range slices.Sorted(maps.Keys(w.sources)) {
		w.sources[name].Start(ctx, w.logger, w.askRematch)
	}

	w.running.Add(1)
	go func() {
		defer w.running.Done()
		defer unsubscribe()
		ticker := time.NewTicker(rematchInterval)
		defer ticker.Stop()
		for {
			w.lookForChanges()
			select {
			case <-ctx.Done():
				return
			case <-changes:
			case <-w.rematch:
			case <-ticker.C:
			}
		}
	}()

	if d := w.config.Discovery; d.IPv6.Enabled && d.IPv6.Solicit || d.IPv4.Enabled && d.IPv4.Solicit {
		w.running.Add(1)
		go func() {
			defer w.running.Done()
			w.solicitLoop(ctx)
		}()
	}

	return nil
}

// Shutdown stops scheduling updates, and waits for the ones running and for the discovery to stop,
// once the context of Start is done. It gives up when ctx is done.
func (w *Worker) Shutdown(ctx context.Context) error {
	for _, t := range w.targets {
		t.hostname.Stop()
	}

	stopped := make(chan struct{})
	go func() {
		w.running.Wait()
		w.discWorker.Wait()
		for _, s := range w.sources {
			s.Wait()
		}
		for _, t := range w.targets {
			t.hostname.Wait()
		}
		close(stopped)
	}()

	select {
	case <-stopped:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("stopping: %w", ctx.Err())
	}
}

func (w *Worker) RegisterPlugin(p ipv6disc.Plugin) {
	w.discWorker.RegisterPlugin(p)
}

// updateNow updates every name now, as Home Assistant's button asks.
func (w *Worker) updateNow() {
	for _, t := range w.targets {
		t.hostname.ScheduleUpdate(0)
	}
}

// askRematch tells the worker to match again, at once.
func (w *Worker) askRematch() {
	select {
	case w.rematch <- struct{}{}:
	default:
	}
}

// discoveryFamily is the ipv6disc family of the configuration's.
func discoveryFamily(f config.Family) ipv6disc.Family {
	return ipv6disc.Family{Enabled: f.Enabled, Listen: f.Listen, Active: f.Active, Lifetime: f.Lifetime.Duration}
}

// lookForChanges gives each host name the addresses its tasks match now.
func (w *Worker) lookForChanges() {
	var discovered []*ipv6disc.Addr
	for _, collection := range w.discWorker.GetAll() {
		discovered = append(discovered, collection.Get()...)
	}

	for _, t := range w.targets {
		t.hostname.SetAddrCollection(w.matching(t.tasks, discovered))
	}
}

// matching returns the addresses that the filters of any of the tasks match, and those of the
// tasks' sources.
func (w *Worker) matching(tasks []config.Task, discovered []*ipv6disc.Addr) *ipv6disc.AddrCollection {
	result := ipv6disc.NewAddrCollection()
	for _, task := range tasks {
		for _, addr := range discovered {
			if task.Match(addr) {
				result.Add(addr)
			}
		}
		for _, name := range task.Sources {
			if s, ok := w.sources[name]; ok {
				result.Join(s.Addresses())
			}
		}
	}
	return result
}

func (w *Worker) PrettyPrint(prefix string, hideSensible bool) string {
	var result strings.Builder
	fmt.Fprint(&result, w.State.PrettyPrint(prefix, hideSensible))
	fmt.Fprint(&result, w.discWorker.State.PrettyPrint(prefix, hideSensible))
	fmt.Fprint(&result, w.discWorker.PrettyPrintStats(prefix))
	fmt.Fprint(&result, w.config.PrettyPrint(prefix, hideSensible))
	return result.String()
}
