package ipv6ddns

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/ddns"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/resolver"
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
	// The sources of addresses without a MAC, by name. Their addresses are theirs, not the
	// discovery state's: that one takes none without a MAC, and they need no watching, since the
	// matching leaves out the ones past their lifetime.
	sources map[string]*source.Source
	// A value tells the worker to match again; changes coming faster are matched once.
	rematch chan struct{}
	// The device of Home Assistant's ESPHome integration, without the homeassistant block nil.
	homeAssistant *homeAssistant
	// The goroutines Start starts, for Shutdown.
	running sync.WaitGroup
	// The resolvers, by name's order.
	resolvers []*resolver.Server
	// Start was called: a second one would run every source and the matching twice.
	started atomic.Bool
	// Of the context of Start: the resolvers stop once it is done, in the time Shutdown has.
	stopped <-chan struct{}
}

// target is a host name at an endpoint, with the tasks that give it addresses. A name in more than
// one task gets the addresses of all of them, however each spells it: "nas", "nas." and
// "nas.example.com" are one name of the zone example.com.
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
		h, err := newHomeAssistant(*cfg.HomeAssistant, cfg.BaseDir)
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
			// A task that spells a name twice gives it its addresses once.
			named := make(map[*Hostname]bool)
			for _, hostnameKey := range task.Endpoints[endpointKey] {
				hostname := w.hostname(endpointKey, endpoint, hostnameKey)
				if named[hostname] {
					continue
				}
				named[hostname] = true
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

	// The resolvers, each with the addresses of its zones' endpoints: a zone no task names has its
	// records still.
	for _, name := range slices.Sorted(maps.Keys(cfg.Resolvers)) {
		spec := cfg.Resolvers[name].Spec
		spec.Zones = slices.Clone(spec.Zones)
		for i, z := range spec.Zones {
			endpoint, err := w.endpoint(z.Credential)
			if err != nil {
				return nil, err
			}
			service, ok := endpoint.Service.(*ddns.Resolver)
			if !ok {
				return nil, fmt.Errorf("credential %s: not a resolver's zone", z.Credential)
			}
			spec.Zones[i].Addresses = service.Addresses()
		}
		server, err := resolver.New(spec, logger.Errorf)
		if err != nil {
			return nil, err
		}
		w.resolvers = append(w.resolvers, server)
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

// hostname returns the host name of an endpoint, making it the first time. Another spelling of a
// name the endpoint has is that name, under its first spelling: two would each update the same
// records with its own addresses, and remove the other's.
func (w *Worker) hostname(endpointKey string, endpoint *Endpoint, hostnameKey string) *Hostname {
	name := recordName(endpoint, hostnameKey)
	if hostname, ok := endpoint.names[name]; ok {
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
	hostname := NewHostname(updateAction, credential.Debounce.Duration, credential.Retry.Duration)
	hostname.endpointMutex = &endpoint.updateMutex
	endpoint.hostnames[hostnameKey] = hostname
	endpoint.names[name] = hostname
	return hostname
}

// recordName is the name of the records that a host name of the endpoint is: its domain, in lower
// case, as DNS tells no case apart. A provider that learns its zone later, as Route 53, has the
// name as written until then: there "nas" and "nas.example.com" stay two.
func recordName(endpoint *Endpoint, hostnameKey string) string {
	return strings.ToLower(strings.Trim(endpoint.Domain(hostnameKey), "."))
}

// Start runs the discovery, the IPv4 commands and the updates, until ctx is done. Shutdown waits
// for them to stop. A worker starts once.
//
// The discovery runs when the configuration has plugins or a family that listens. Its plugins are
// those registered with RegisterPlugin, one for each of the configuration's, as cmd does: with
// none in the configuration and no family listening, the registered ones don't run; with some in
// the configuration, none registered and no family listening, it is an error.
func (w *Worker) Start(ctx context.Context) error {
	if w.started.Swap(true) {
		return errors.New("worker already started")
	}
	for _, warning := range w.config.Warnings {
		w.logger.Warn(warning)
	}

	// The resolvers first: two on one address, however spelled, or one that can't listen, stops
	// the start, as the web server's address.
	if err := resolver.CheckListen(w.resolvers); err != nil {
		return err
	}
	for i, r := range w.resolvers {
		if err := r.Start(); err != nil {
			for _, started := range w.resolvers[:i] {
				started.Shutdown(context.Background())
			}
			return err
		}
		w.logger.Infof("resolver %s listening on %s", r.Status().Name, strings.Join(r.Addresses(), ", "))
	}
	w.stopped = ctx.Done()
	// A start that fails past them leaves none listening.
	closeResolvers := func() {
		for _, r := range w.resolvers {
			r.Shutdown(context.Background())
		}
	}

	// Without plugins nor a family listening, there is nothing to discover: the names get the
	// addresses of their sources only, as the public address of the network, or Home Assistant's.
	d := w.config.Discovery
	if len(d.Plugins) > 0 || d.IPv6.Enabled && d.IPv6.Listen || d.IPv4.Enabled && d.IPv4.Listen {
		if err := w.discWorker.Start(ctx); err != nil {
			closeResolvers()
			return err
		}
	} else {
		w.logger.Info("no discovery: no plugins, and no family listens; the names get the addresses of their sources")
	}
	if h := w.homeAssistant; h != nil {
		if err := h.serve(ctx, &w.running, w.config.Discovery.Interfaces, w.config.Discovery.ExcludeInterfaces, w.logger.Errorf); err != nil {
			closeResolvers()
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
// and for Home Assistant's connections to end and the device's announcement to be taken back,
// once the context of Start is done: before that, it waits. The addresses discovered stop expiring
// then, and stay for the status. It gives up when ctx is done, and what it waited for goes on.
//
// The resolvers stop here, once the context of Start is done: they answer no new query, and have
// until ctx is done, the time the program gives its stop, to answer those being made; then the
// queries still asked upstream are given up, and their addresses closed.
func (w *Worker) Shutdown(ctx context.Context) error {
	for _, t := range w.targets {
		t.hostname.Stop()
	}

	stopped := make(chan struct{})
	go func() {
		var resolvers sync.WaitGroup
		// The resolvers, as the rest, once Start's context is done: they answer the queries being
		// made in the time ctx gives, the program's.
		if w.stopped != nil && len(w.resolvers) > 0 {
			<-w.stopped
			for _, r := range w.resolvers {
				resolvers.Add(1)
				go func() {
					defer resolvers.Done()
					r.Shutdown(ctx)
				}()
			}
		}
		w.running.Wait()
		w.discWorker.Wait()
		// The addresses stay watched, each with its goroutine and timers, until this.
		w.discWorker.State.Close()
		for _, s := range w.sources {
			s.Wait()
		}
		for _, t := range w.targets {
			t.hostname.Wait()
		}
		resolvers.Wait()
		close(stopped)
	}()

	select {
	case <-stopped:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("stopping: %w", ctx.Err())
	}
}

// RegisterPlugin adds a discovery plugin, before Start: one for each of the configuration's
// discovery.plugins, which is what makes Start run them.
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
	fmt.Fprint(&result, w.prettyPrintResolvers(prefix))
	fmt.Fprint(&result, w.discWorker.State.PrettyPrint(prefix, hideSensible))
	fmt.Fprint(&result, w.discWorker.PrettyPrintStats(prefix))
	fmt.Fprint(&result, w.config.PrettyPrint(prefix, hideSensible))
	return result.String()
}

// prettyPrintResolvers tells, of each resolver, where it listens, whom it answers, and what it
// answered: nothing without resolvers.
func (w *Worker) prettyPrintResolvers(prefix string) string {
	if len(w.resolvers) == 0 {
		return ""
	}
	var result strings.Builder
	fmt.Fprintf(&result, "%sResolvers:\n", prefix)
	for _, r := range w.resolvers {
		s := r.Status()
		state := "serving"
		if !s.Serving {
			state = "not serving"
			if s.Error != "" {
				state += ": " + s.Error
			}
		}
		fmt.Fprintf(&result, "%s    %s: %s\n", prefix, s.Name, state)
		fmt.Fprintf(&result, "%s        Listening: %s\n", prefix, strings.Join(s.Listening, ", "))
		fmt.Fprintf(&result, "%s        Allow: %s\n", prefix, strings.Join(s.Allow, ", "))
		fmt.Fprintf(&result, "%s        Zones: %s\n", prefix, strings.Join(s.Zones, ", "))
		var upstreams []string
		for _, u := range s.Upstreams {
			upstreams = append(upstreams, fmt.Sprintf("%s (%d failed)", u, s.UpstreamFailures[u]))
		}
		fmt.Fprintf(&result, "%s        Upstream: %s\n", prefix, strings.Join(upstreams, ", "))
		var queries []string
		for _, kind := range resolver.Kinds {
			queries = append(queries, fmt.Sprintf("%s %d", kind, s.Queries[kind]))
		}
		fmt.Fprintf(&result, "%s        Queries: %s\n", prefix, strings.Join(queries, ", "))
		cached := "none"
		if s.CacheSize > 0 {
			cached = fmt.Sprintf("%d of %d", s.CacheEntries, s.CacheSize)
		}
		fmt.Fprintf(&result, "%s        Cache: %s\n", prefix, cached)
	}
	return result.String()
}
