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

// lookInterval is how often the worker matches the discovered addresses against the tasks.
const lookInterval = time.Second

type Worker struct {
	*State
	discWorker *ipv6disc.Worker
	logger     *zap.SugaredLogger
	config     config.Config
	targets    []*target
	// The sources of addresses without a MAC, by name.
	sources map[string]*source.Source
	// The goroutines Start starts, for Shutdown.
	running sync.WaitGroup
}

// target is a host name at an endpoint, with the tasks that give it addresses. A name in more than
// one task gets the addresses of all of them.
type target struct {
	hostname *Hostname
	tasks    []config.Task
}

func NewWorker(logger *zap.SugaredLogger, rediscover time.Duration, lifetime time.Duration, cfg config.Config) (*Worker, error) {
	w := &Worker{
		State:      NewState(),
		discWorker: ipv6disc.NewWorker(logger, rediscover, lifetime, cfg.Discovery.Listen, cfg.Discovery.Active),
		logger:     logger,
		config:     cfg,
		sources:    make(map[string]*source.Source),
	}
	if cfg.Discovery.IPv4 {
		w.discWorker.State.EnableIPv4()
	}

	for name, sourceConfig := range cfg.Sources {
		s, err := source.New(name, sourceConfig, cfg.BaseDir)
		if err != nil {
			return nil, err
		}
		w.sources[name] = s
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

	for _, name := range slices.Sorted(maps.Keys(w.sources)) {
		w.sources[name].Start(ctx, w.logger)
	}

	if err := w.discWorker.Start(ctx); err != nil {
		return err
	}

	w.running.Add(1)
	go func() {
		defer w.running.Done()
		ticker := time.NewTicker(lookInterval)
		defer ticker.Stop()
		for {
			// @TODO: instead of proactively searching, be notified from ipv6disc.AddrCollection.Seen
			w.lookForChanges()
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()

	if w.config.Discovery.SolicitEUI64 {
		w.running.Add(1)
		go func() {
			defer w.running.Done()
			w.solicitEUI64Loop(ctx)
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
