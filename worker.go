package ipv6ddns

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/ddns"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/blocklist"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/certfile"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/resolver"
	"github.com/miguelangel-nubla/ipv6ddns/source"
	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/miguelangel-nubla/ipv6disc/pkg/pretty"
	"go.uber.org/zap"
)

// rematchInterval is how often the worker matches the addresses against the tasks with nothing
// telling it to: for the addresses of sources that outlive their lifetime, which nothing tells.
// The discovery's changes, and every run of a source, make it match at once.
const rematchInterval = 10 * time.Second

type Worker struct {
	*State
	discWorker *ipv6disc.Worker
	// The grants of the resolvers' keys that run: of challenges, whose timers remove what their
	// clients left; of names, which give their names to the hosts.
	grantsToStart []interface {
		start(context.Context, *sync.WaitGroup)
	}
	logger  *zap.SugaredLogger
	config  config.Config
	targets []*target
	// The sources of addresses without a MAC, by name. Their addresses are theirs, not the
	// discovery state's: that one takes none without a MAC, and they need no watching, since the
	// matching leaves out the ones past their lifetime.
	sources map[string]*source.Source
	// A value tells the worker to match again; changes coming faster are matched once.
	rematch chan struct{}
	// The device of Home Assistant's ESPHome integration, without the homeassistant block nil.
	homeAssistant *homeAssistant
	// The discovery plugins RegisterPlugin added, in its order, for their states.
	plugins []ipv6disc.Plugin
	// The goroutines Start starts, for Shutdown.
	running sync.WaitGroup
	// The resolvers, by name's order.
	resolvers []*resolver.Server
	// The blocklists the resolvers' blocks name, by name's order: each once, for all of them.
	blocklists []*blocklist.List
	// The certificates of the configuration, by name's order.
	certs []*certificate
	// The sockets the web servers opened, by their listener's name, as WebListening tells them.
	webSockets map[string][]string
	webMutex   sync.Mutex
	// Start was called: a second one would run every source and the matching twice.
	started atomic.Bool
	// Of the context of Start: the resolvers stop once it is done, in the time Shutdown has.
	stopped <-chan struct{}

	// The tasks' host names that are templates, each with its task and endpoint.
	templates []*templateTarget
	// The names the templates make now, and made, until they have nothing left to remove.
	dynamic      map[dynamicKey]*Hostname
	dynamicMutex sync.Mutex
	// The names of the templates that a name written as it is has, told once each.
	taken map[dynamicKey]bool
}

// templateTarget is a host name of a task that is a template, at an endpoint: a name for each host
// the task's filters match, by what the host is called.
type templateTarget struct {
	task        config.Task
	endpointKey string
	endpoint    *Endpoint
	template    config.Template
}

// dynamicKey is a name of a template, at its endpoint, by the name of its records.
type dynamicKey struct {
	endpoint *Endpoint
	name     string
}

// target is a host name at an endpoint, with the tasks that give it addresses. A name in more than
// one task gets the addresses of all of them, however each spells it: "nas", "nas." and
// "nas.example.com" are one name of the zone example.com.
type target struct {
	hostname *Hostname
	tasks    []config.Task
}

// NewWorker makes the worker of the configuration; Start runs it. The discovery is the
// configuration's, whole: its families, its names and its protocols, which a configuration read
// by config.NewConfig has by default, and one made by hand has from config.DefaultDiscovery. A
// lifetime left zero is an hour; a rediscovery interval, a third of the shortest lifetime of the
// families on.
func NewWorker(logger *zap.SugaredLogger, cfg config.Config) (*Worker, error) {
	// The state folder, which a configuration may give to be written in.
	if cfg.StateDir != "" {
		if err := os.MkdirAll(cfg.StateFolder, 0o700); err != nil {
			return nil, fmt.Errorf("state_dir: %w", err)
		}
	}
	discovery := cfg.Discovery.Config()
	if discovery.Lifetime == 0 {
		discovery.Lifetime = config.DefaultLifetime
	}
	w := &Worker{
		State:      NewState(),
		discWorker: ipv6disc.NewWorker(logger, discovery),
		logger:     logger,
		config:     cfg,
		sources:    make(map[string]*source.Source),
		rematch:    make(chan struct{}, 1),
		dynamic:    make(map[dynamicKey]*Hostname),
		taken:      make(map[dynamicKey]bool),
	}

	// Home Assistant's states for its sources; nil, not a nil *homeAssistant, without it.
	var states source.HomeAssistantStates
	if cfg.HomeAssistant != nil {
		h, err := newHomeAssistant(*cfg.HomeAssistant, cfg.StateFolder)
		if err != nil {
			return nil, err
		}
		h.device.Logger = logger
		w.homeAssistant, states = h, h
	}

	for name, sourceConfig := range cfg.Sources {
		s, err := source.New(name, sourceConfig, cfg.BaseDir, cfg.StateFolder, states)
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
				if config.IsTemplate(hostnameKey) {
					template, err := config.ParseTemplate(hostnameKey)
					if err != nil {
						return nil, fmt.Errorf("task %s: endpoint %s: the name %q: %w", taskName, endpointKey, hostnameKey, err)
					}
					w.templates = append(w.templates, &templateTarget{task: task, endpointKey: endpointKey, endpoint: endpoint, template: template})
					continue
				}
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
				// The names written as they are: a template's come later, and have no entity.
				keys, _ := endpoint.list()
				for _, hostnameKey := range keys {
					names = append(names, haName{endpointKey, hostnameKey, endpoint.Domain(hostnameKey)})
				}
			}
		}
		w.homeAssistant.addEntities(names, w.updateNow)
	}

	// The certificates, each loaded once, for every server that shows it.
	certs, err := w.certificates()
	if err != nil {
		return nil, err
	}
	w.certs = certs

	lists := w.setUpBlocklists()

	// The resolvers, each with the addresses of its zones' endpoints: a zone no task names has its
	// records still.
	for _, name := range slices.Sorted(maps.Keys(cfg.Resolvers)) {
		spec := cfg.Resolvers[name].Spec
		if spec.Block != nil {
			block := *spec.Block
			block.Sets = nil
			for _, l := range block.Lists {
				block.Sets = append(block.Sets, lists[l])
			}
			spec.Block = &block
		}
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
		spec.Encrypted = slices.Clone(spec.Encrypted)
		for i, e := range spec.Encrypted {
			if e.CertificateName != "" {
				spec.Encrypted[i].Certificate = w.certificate(e.CertificateName)
			}
		}
		if spec.CertificateName != "" {
			spec.Certificate = w.certificate(spec.CertificateName)
		}
		keys, err := w.updateKeys(name, cfg.Resolvers[name].Updates)
		if err != nil {
			return nil, err
		}
		spec.UpdateKeys, spec.Infof, spec.Warnf = keys, logger.Infof, logger.Warnf
		server, err := resolver.New(spec, logger.Errorf)
		if err != nil {
			return nil, err
		}
		w.resolvers = append(w.resolvers, server)
	}
	// The sockets that listeners of several share: each opened once, by the first's resolver.
	if err := resolver.Share(w.resolvers); err != nil {
		return nil, err
	}

	w.config.Warnings = append(slices.Clone(cfg.Warnings), w.zoneLaterWarnings()...)

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
	endpoint.mutex.RLock()
	hostname, ok := endpoint.names[name]
	endpoint.mutex.RUnlock()
	if ok {
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
	hostname = NewHostname(updateAction, credential.Debounce.Duration, credential.Retry.Duration)
	hostname.endpointMutex = &endpoint.updateMutex
	endpoint.mutex.Lock()
	endpoint.hostnames[hostnameKey] = hostname
	endpoint.names[name] = hostname
	endpoint.mutex.Unlock()
	return hostname
}

// recordName is the name of the records that a host name of the endpoint is: its domain, in lower
// case, as DNS tells no case apart. A provider that learns its zone later, as Route 53, has the
// name as written until then: there "nas" and "nas.example.com" stay two.
func recordName(endpoint *Endpoint, hostnameKey string) string {
	return strings.ToLower(strings.Trim(endpoint.Domain(hostnameKey), "."))
}

// zoneLaterWarnings tells, of each Route 53 endpoint, the names that may be one: Route 53 learns
// its zone at the first update, and until then "nas" and "nas.example.com" are two names, each of
// which writes the records with its own addresses alone, in place of the other's.
func (w *Worker) zoneLaterWarnings() []string {
	var warnings []string
	for _, providerKey := range slices.Sorted(maps.Keys(w.State.providers)) {
		provider := w.State.providers[providerKey]
		for _, endpointKey := range slices.Sorted(maps.Keys(provider.endpoints)) {
			endpoint := provider.endpoints[endpointKey]
			if _, ok := endpoint.Service.(*ddns.Route53); !ok {
				continue
			}
			names := slices.Sorted(maps.Keys(endpoint.names))
			for _, short := range names {
				for _, long := range names {
					if strings.HasPrefix(long, short+".") {
						warnings = append(warnings, fmt.Sprintf("endpoint %s: %s and %s may be the same name, written two ways. ipv6ddns learns the zone from Route 53 at the first update, and until then they are two names, each writing the records with only its own addresses. Write the name one way in every task", endpointKey, short, long))
					}
				}
			}
		}
	}
	return warnings
}

// Start runs the discovery, the IPv4 commands and the updates, until ctx is done. Shutdown waits
// for them to stop. A worker starts once.
//
// The discovery runs when the configuration has plugins or a family that listens. Its plugins are
// those registered with RegisterPlugin, one for each of the configuration's, as cmd does: with
// none in the configuration and no family listening, the registered ones don't run; with some in
// the configuration, none registered and no family listening, it is an error.
// SetWeb gives a web server's handler to the resolver that opens the HTTPS entries of the
// listener it shares with it, by the resolver's and the listener's names: before Start.
func (w *Worker) SetWeb(resolverName, listener string, h http.Handler) {
	for _, r := range w.resolvers {
		if r.Name() == resolverName {
			r.SetWeb(listener, h)
		}
	}
}

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
			// Of a start that fails, the error is the start's: those just started have no query to
			// cut.
			for _, started := range w.resolvers[:i] {
				_ = started.Shutdown(context.Background())
			}
			return err
		}
		w.logger.Infof("resolver %s listening on %s", r.Status().Name, strings.Join(r.Addresses(), ", "))
	}
	for _, c := range w.certs {
		if c.acme != nil {
			w.running.Go(func() { c.run(ctx) })
		}
	}
	// Once the resolvers serve: the system's resolver, which looks up the lists' hosts, may be one.
	for _, l := range w.blocklists {
		w.running.Go(func() { l.Run(ctx) })
	}
	w.stopped = ctx.Done()
	// A start that fails past them leaves none listening.
	closeResolvers := func() {
		for _, r := range w.resolvers {
			_ = r.Shutdown(context.Background())
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
		w.logger.Info("discovery is off: there are no plugins, and no family listens. The names get only their sources' addresses")
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
	for _, g := range w.grantsToStart {
		g.start(ctx, &w.running)
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

	if d := w.config.Discovery; d.IPv6.Enabled && d.Solicit.IPv6 || d.IPv4.Enabled && d.Solicit.IPv4 {
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
					if err := r.Shutdown(ctx); err != nil {
						w.logger.Warnf("resolver %s: %s: queries still in progress were cut off", r.Status().Name, err)
					}
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
		// The names of the templates, once the matching, which makes them, has stopped.
		w.dynamicMutex.Lock()
		for _, h := range w.dynamic {
			h.Stop()
			h.Wait()
		}
		w.dynamicMutex.Unlock()
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
	w.plugins = append(w.plugins, p)
	w.discWorker.RegisterPlugin(p)
}

// updateNow updates every name now, as Home Assistant's button asks.
func (w *Worker) updateNow() {
	for _, t := range w.targets {
		t.hostname.ScheduleUpdate(0)
	}
	w.dynamicMutex.Lock()
	defer w.dynamicMutex.Unlock()
	for _, h := range w.dynamic {
		h.ScheduleUpdate(0)
	}
}

// askRematch tells the worker to match again, at once.
func (w *Worker) askRematch() {
	select {
	case w.rematch <- struct{}{}:
	default:
	}
}

// lookForChanges gives each host name the addresses its tasks match now.
func (w *Worker) lookForChanges() {
	var discovered []*ipv6disc.Addr
	for _, collection := range w.discWorker.GetAll() {
		discovered = append(discovered, collection.Get()...)
	}

	// The push sources' prefixes, once: every address of the round is judged by the same.
	prefixes := w.prefixes()
	for _, t := range w.targets {
		t.hostname.SetAddrCollection(w.matching(t.tasks, discovered, prefixes))
	}
	w.expandTemplates(discovered, prefixes)
}

// prefixes are the IPv6 prefixes of their LAN that the push sources' routers sent, by source.
func (w *Worker) prefixes() config.Prefixes {
	prefixes := config.Prefixes{}
	for name, s := range w.sources {
		if p, ok := s.Prefix(); ok {
			prefixes[name] = p
		}
	}
	return prefixes
}

// expandTemplates gives the names of the tasks' templates the addresses of their hosts, as the
// hosts are called now: a name for each host a template's task matches, or one for all those of
// a name. A name no host has any more is left without addresses, which removes its records, and
// is then forgotten. A name that is written as it is, at the endpoint, is that one's: the
// template's is left out, and said once.
func (w *Worker) expandTemplates(discovered []*ipv6disc.Addr, prefixes config.Prefixes) {
	if len(w.templates) == 0 {
		return
	}
	type named struct {
		target      *templateTarget
		hostnameKey string
		addrs       *ipv6disc.AddrCollection
	}
	wanted := make(map[dynamicKey]*named)
	add := func(t *templateTarget, hostnameKey string, addrs []*ipv6disc.Addr) {
		key := dynamicKey{t.endpoint, recordName(t.endpoint, hostnameKey)}
		n, ok := wanted[key]
		if !ok {
			n = &named{target: t, hostnameKey: hostnameKey, addrs: ipv6disc.NewAddrCollection()}
			wanted[key] = n
		}
		for _, addr := range addrs {
			n.addrs.Add(addr)
		}
	}
	for _, t := range w.templates {
		// The hosts the task matches, by MAC, in the MACs' order.
		hosts := make(map[string][]*ipv6disc.Addr)
		for _, addr := range discovered {
			if len(addr.Hw) > 0 && t.task.Match(addr, prefixes) {
				hosts[addr.Hw.String()] = append(hosts[addr.Hw.String()], addr)
			}
		}
		macs := slices.Sorted(maps.Keys(hosts))
		if !t.template.Hostname {
			for _, mac := range macs {
				add(t, t.template.Expand("", 0, hosts[mac][0].Hw), hosts[mac])
			}
			continue
		}
		// Those of each name, in that order: a host's place among them is {n}.
		called := make(map[string][]string)
		for _, mac := range macs {
			for _, name := range w.discWorker.NamesOf(hosts[mac][0].Hw) {
				called[name.Name] = append(called[name.Name], mac)
			}
		}
		for name, of := range called {
			for i, mac := range of {
				add(t, t.template.Expand(name, i+1, hosts[mac][0].Hw), hosts[mac])
			}
		}
	}

	w.dynamicMutex.Lock()
	defer w.dynamicMutex.Unlock()
	for key, n := range wanted {
		hostname, ok := w.dynamic[key]
		if !ok {
			key.endpoint.mutex.RLock()
			_, written := key.endpoint.names[key.name]
			key.endpoint.mutex.RUnlock()
			if written {
				if !w.taken[key] {
					w.taken[key] = true
					w.logger.Warnf("endpoint %s: %s is written in the configuration, so it keeps its own addresses: hosts with that name, from the template %q of task %s, are left out of it", n.target.endpointKey, key.name, n.target.template.Text, n.target.task.Name)
				}
				continue
			}
			hostname = w.hostname(n.target.endpointKey, key.endpoint, n.hostnameKey)
			w.dynamic[key] = hostname
		}
		hostname.SetAddrCollection(n.addrs)
	}
	for key, hostname := range w.dynamic {
		if _, ok := wanted[key]; ok {
			continue
		}
		hostname.SetAddrCollection(ipv6disc.NewAddrCollection())
		if hostname.idle() {
			hostname.Stop()
			key.endpoint.mutex.Lock()
			delete(key.endpoint.names, key.name)
			for spelling, h := range key.endpoint.hostnames {
				if h == hostname {
					delete(key.endpoint.hostnames, spelling)
				}
			}
			key.endpoint.mutex.Unlock()
			delete(w.dynamic, key)
		}
	}
}

// matching returns the addresses that the filters of any of the tasks match, and those of the
// tasks' sources.
func (w *Worker) matching(tasks []config.Task, discovered []*ipv6disc.Addr, prefixes config.Prefixes) *ipv6disc.AddrCollection {
	result := ipv6disc.NewAddrCollection()
	for _, task := range tasks {
		for _, addr := range discovered {
			if task.Match(addr, prefixes) {
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

// PrettyPrint is the status page as text: Page, without the roles.
func (w *Worker) PrettyPrint(prefix string, hideSensible bool) string {
	return w.Page(prefix, hideSensible).String()
}

// Page is the status page: the names, the resolvers, the discovery and the configuration, each
// after a blank line, and each piece with its role, for a terminal or a web page to color. The
// words say every state all the same: as text it lacks nothing.
func (w *Worker) Page(prefix string, hideSensible bool) pretty.Page {
	var page pretty.Page
	for _, section := range []pretty.Page{
		w.State.page(prefix, hideSensible, w.writtenRecords()),
		w.resolversPage(prefix),
		w.blocklistsPage(prefix, hideSensible),
		w.listenersPage(prefix),
		w.certificatesPage(prefix),
		w.sourcesPage(prefix, hideSensible),
		append(w.discWorker.State.Page(prefix), w.discWorker.StatsPage(prefix)...),
		processPage(prefix, processStatus()),
		w.config.Page(prefix, hideSensible),
	} {
		if len(section) == 0 {
			continue
		}
		if len(page) > 0 {
			page.Add()
		}
		page = append(page, section...)
	}
	return page
}

// sourcesPage is the page of the sources and Home Assistant's device, of
// the states the status has.
func (w *Worker) sourcesPage(prefix string, hideSensible bool) pretty.Page {
	sources := []source.Status{}
	for _, name := range slices.Sorted(maps.Keys(w.sources)) {
		sources = append(sources, w.sources[name].Status(hideSensible))
	}
	return sourcesPage(prefix, sources, w.homeAssistantStatus())
}

// writtenRecords are the records written in the resolvers' zones, by the credential of each zone.
func (w *Worker) writtenRecords() map[string][]string {
	written := map[string][]string{}
	for _, r := range w.resolvers {
		s := r.Status()
		for zone, lines := range s.ZoneRecords {
			if credential := s.ZoneCredentials[zone]; credential != "" && written[credential] == nil {
				written[credential] = lines
			}
		}
	}
	return written
}

// resolversPage tells, of each resolver, where it listens, whom it answers, and what it
// answered: nothing without resolvers.
func (w *Worker) resolversPage(prefix string) pretty.Page {
	statuses := make([]resolver.Status, 0, len(w.resolvers))
	for _, r := range w.resolvers {
		statuses = append(statuses, r.Status())
	}
	return resolversPage(prefix, statuses)
}

// upstreamSpans are servers asked upstream, each with the addresses found of a host name and its
// failures: one that failed stands out; one that never did steps back.
func upstreamSpans(upstreams []string, failures map[string]uint64, found map[string][]string) pretty.Line {
	var spans pretty.Line
	for i, u := range upstreams {
		sep := ""
		if i > 0 {
			sep = ", "
		}
		failed := pretty.Detail
		if failures[u] > 0 {
			failed = pretty.Warn
		}
		name := u
		if addresses := found[u]; len(addresses) > 0 {
			name += " [" + strings.Join(addresses, ", ") + "]"
		}
		spans = append(spans, pretty.Span{Text: sep + name + " "}, pretty.As(failed, fmt.Sprintf("(%d failed)", failures[u])))
	}
	return spans
}

// resolversPage is the page of the resolvers of those statuses.
func resolversPage(prefix string, statuses []resolver.Status) pretty.Page {
	if len(statuses) == 0 {
		return nil
	}
	var page pretty.Page
	plain := func(format string, args ...any) {
		page.Add(pretty.Span{Text: prefix + fmt.Sprintf(format, args...)})
	}
	detail := func(format string, args ...any) {
		page.Add(pretty.As(pretty.Detail, prefix+fmt.Sprintf(format, args...)))
	}
	serving := 0
	for _, s := range statuses {
		if s.Serving {
			serving++
		}
	}
	all := pretty.OK
	if serving < len(statuses) {
		all = pretty.Error
	}
	page.Add(pretty.Span{Text: prefix}, pretty.As(pretty.Heading, "Resolvers:"), pretty.Span{Text: fmt.Sprintf(" %d, ", len(statuses))}, pretty.As(all, fmt.Sprintf("%d serving", serving)))
	for _, s := range statuses {
		state := pretty.As(pretty.OK, "serving")
		if !s.Serving {
			state = pretty.As(pretty.Error, "not serving")
			if s.Error != "" {
				state.Text += ": " + s.Error
			}
		}
		page.Add(pretty.As(pretty.Name, prefix+"    "+s.Name), pretty.Span{Text: ": "}, state)
		// An empty list says what it means: no sockets yet, anyone, or no other server.
		list := func(items []string, empty string) string {
			if len(items) == 0 {
				return empty
			}
			return strings.Join(items, ", ")
		}
		plain("        Listening: %s", list(s.Listening, "none"))
		// Whose the allow is: the resolver's, on all its sockets, its listeners', each on its own, or
		// of none, the networks of the machine's addresses it listens on.
		whose := "the resolver's"
		switch {
		case !s.AllowOwn && len(s.ListenerAllow) > 0:
			whose = "its listeners'"
		case !s.AllowOwn:
			whose = "the networks it listens on"
		}
		if len(s.Allow) == 0 {
			plain("        Allow: none")
		} else {
			plain("        Allow: %s (%s)", strings.Join(s.Allow, ", "), whose)
		}
		for _, l := range s.ListenerAllow {
			of := l.Listen
			if l.Listener != "" {
				of += " (" + l.Listener + ")"
			}
			plain("            %s: %s", of, strings.Join(l.Allow, ", "))
		}
		// A socket of listeners of several: which this one is, by the name its clients ask.
		for _, sh := range s.Shared {
			by := "the clients that ask " + sh.Name
			if sh.Name == "" {
				by = "the clients of its certificate's names"
			}
			switch {
			case sh.Default:
				by += ", or another name, or none"
			case sh.Name != "" && sh.Others:
				by += ", or another name of its certificate that none before it is for"
			case sh.Name != "":
				// Its certificate's other names, of one before it too, are that one's.
				by += ", by that name alone"
			}
			plain("        Shared: %s, listener %s, with %s: %s", sh.Address, sh.Listener, strings.Join(sh.With, ", "), by)
		}
		var zones []string
		for _, z := range s.Zones {
			count := countNames(s.ZoneNames[z])
			if n := len(s.ZoneRecords[z]); n > 0 {
				written := "records"
				if n == 1 {
					written = "record"
				}
				count += fmt.Sprintf(", %d written %s", n, written)
			}
			count += fmt.Sprintf(", TTL %ds", s.ZoneTTL[z])
			zones = append(zones, fmt.Sprintf("%s (%s)", z, count))
		}
		// The names themselves are under their endpoints, above; each one's task in /status.json.
		plain("        Zones: %s", list(zones, "none"))
		if len(s.Records) > 0 {
			plain("        Records:")
		}
		for _, r := range s.Records {
			plain("            %s", r)
		}
		upstreams := pretty.Line{{Text: prefix + "        Upstream: "}}
		if len(s.Upstreams) == 0 {
			upstreams = append(upstreams, pretty.Span{Text: "none, its own names only"})
		}
		page.Add(append(upstreams, upstreamSpans(s.Upstreams, s.UpstreamFailures, s.UpstreamAddresses)...)...)
		// Each domain forwarded, with its own servers, of their own failures.
		for _, f := range s.Forwards {
			forward := pretty.Line{{Text: prefix + "        Forward: " + f.Domain + " to "}}
			page.Add(append(forward, upstreamSpans(f.Upstreams, f.UpstreamFailures, f.UpstreamAddresses)...)...)
		}
		if len(s.Bootstrap) > 0 {
			plain("        Bootstrap: %s", strings.Join(s.Bootstrap, ", "))
		}
		private := "the unknown answered here as no such name (RFC 6303)"
		if s.ForwardUnknownPrivateReverse {
			private = "forwarded"
		}
		plain("        Private reverse: %s", private)
		var queries []string
		for _, kind := range resolver.Kinds {
			queries = append(queries, fmt.Sprintf("%s %d", kind, s.Queries[kind]))
		}
		detail("        Queries: %s", strings.Join(queries, ", "))
		if b := s.Block; b != nil {
			allow := ""
			if len(b.Allow) > 0 {
				allow = ", allow " + strings.Join(b.Allow, ", ")
			}
			plain("        Block: %s%s, answer %s, TTL %ds", strings.Join(b.Lists, ", "), allow, b.Answer, b.TTL)
		}
		cached := "none"
		if s.CacheSize > 0 {
			cached = fmt.Sprintf("%d of %d", s.CacheEntries, s.CacheSize)
		}
		detail("        Cache: %s", cached)
		if s.Certificate != "" {
			plain("        Certificate: %s", s.Certificate)
		}
		if len(s.Keys) > 0 {
			plain("        Keys:")
		}
		for _, k := range s.Keys {
			counts := fmt.Sprintf("applied %d, refused %d, failed %d", k.Updates[resolver.UpdateApplied], k.Updates[resolver.UpdateRefused], k.Updates[resolver.UpdateFailed])
			page.Add(pretty.As(pretty.Name, prefix+"            "+k.Name), pretty.Span{Text: fmt.Sprintf(" (%s): %s", strings.Join(k.Permissions, ", "), counts)})
			// What each permission may change: its zone's names, or all of them, of its types.
			for _, g := range k.Grants {
				names := "not asked of its provider yet"
				switch {
				case g.Zone != "" && len(g.Names) == 0:
					names = "all of " + g.Zone
				case g.Zone != "":
					names = strings.Join(g.Names, ", ") + " of " + g.Zone
				}
				plain("                %s: %s (%s)", g.Permission, names, strings.Join(g.Types, ", "))
			}
			if k.Last != nil {
				style := pretty.Detail
				if k.LastResult != resolver.UpdateApplied {
					style = pretty.Warn
				}
				page.Add(pretty.Span{Text: prefix + "                Last: "}, pretty.As(style, fmt.Sprintf("%s, %s: %s", k.Last.Local().Format(time.DateTime), k.LastResult, k.LastMessage)))
			}
		}
	}
	return page
}

// certificateWarning is how long before its end a certificate is said to expire soon: renewals
// come a month before, so one this close is no longer renewed.
const certificateWarning = 14 * 24 * time.Hour

// certificateLine tells of a certificate, after its label: its names, and until when, in amber
// when it ends within two weeks, in red once it ended; and, in amber, files that don't read
// again, while it is still shown.
func certificateLine(indent, label string, c *certfile.Status, now time.Time) pretty.Line {
	if c.NotAfter.IsZero() {
		line := pretty.Line{{Text: indent + label + ": "}, pretty.As(pretty.Warn, "none yet")}
		return append(line, renewalSpans(c)...)
	}
	until := c.NotAfter.UTC().Format(time.DateOnly)
	line := pretty.Line{{Text: indent + label + ": " + strings.Join(c.Names, ", ") + ", "}}
	switch left := c.NotAfter.Sub(now); {
	case left <= 0:
		line = append(line, pretty.As(pretty.Error, "expired on "+until))
	case left < certificateWarning:
		line = append(line, pretty.As(pretty.Warn, fmt.Sprintf("until %s, in %s", until, countDays(int(left.Hours()/24)))))
	default:
		line = append(line, pretty.Span{Text: "until " + until})
	}
	if c.Error != "" {
		line = append(line, pretty.Span{Text: " "}, pretty.As(pretty.Warn, "(its files don't read again: "+c.Error+")"))
	}
	return append(line, renewalSpans(c)...)
}

// renewalSpans tell, in amber, why the last attempt to get the certificate failed, and when the
// next is: nothing, of one that didn't fail.
func renewalSpans(c *certfile.Status) pretty.Line {
	if c.Renewal == "" {
		return nil
	}
	text := "(getting it failed: " + c.Renewal
	if !c.NextAttempt.IsZero() {
		text += "; again at " + c.NextAttempt.UTC().Format("2006-01-02 15:04") + " UTC"
	}
	return pretty.Line{{Text: " "}, pretty.As(pretty.Warn, text+")")}
}

// countDays is n days, or 1 day.
func countDays(n int) string {
	if n == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", n)
}

// PushSource is the source of that name that a router pushes to: none of another type.
func (w *Worker) PushSource(name string) (*source.Source, bool) {
	s, ok := w.sources[name]
	if !ok || !s.IsPush() {
		return nil, false
	}
	return s, true
}

// Logger is the worker's logger.
func (w *Worker) Logger() *zap.SugaredLogger { return w.logger }

// certificatesPage tells, of each certificate, what shows it, the names it is for, and until
// when: nothing without certificates.
func (w *Worker) certificatesPage(prefix string) pretty.Page {
	return certificatesPage(prefix, w.certificateStatuses(), time.Now())
}

// certificatesPage is the page of the certificates of those statuses.
func certificatesPage(prefix string, statuses []CertificateStatus, now time.Time) pretty.Page {
	if len(statuses) == 0 {
		return nil
	}
	var page pretty.Page
	page.Add(pretty.Span{Text: prefix}, pretty.As(pretty.Heading, "Certificates:"))
	for _, c := range statuses {
		var users []string
		for _, u := range c.UsedBy {
			for prefix, kind := range map[string]string{"resolvers.": "resolver ", "webservers.": "web server ", "listeners.": "listener "} {
				if name, ok := strings.CutPrefix(u, prefix); ok {
					u = kind + name
				}
			}
			users = append(users, u)
		}
		page.Add(certificateLine(prefix+"    ", c.Name+" ("+strings.Join(users, ", ")+")", c.Status, now)...)
		// Of acme: the names asked, as written, and the credential that writes their challenge.
		if len(c.ACMENames) > 0 {
			page.Add(pretty.Span{Text: fmt.Sprintf("%s        ACME: %s, by credential %s", prefix, strings.Join(c.ACMENames, ", "), c.Credential)})
		}
	}
	return page
}
