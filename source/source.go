// Package source runs the sources of addresses that have no MAC: echo services for the public
// address of the network, commands, fixed lists.
package source

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6disc"
	"go.uber.org/zap"
)

// A fetcher returns the addresses a source has now.
type fetcher func(ctx context.Context) ([]netip.Addr, error)

// Source runs a source at its interval, and keeps the addresses it gives for their lifetime after
// the last run that gave them.
type Source struct {
	name   string
	config config.Source
	fetch  fetcher
	addrs  *ipv6disc.AddrCollection

	mutex       sync.Mutex
	lastRun     time.Time
	lastSuccess time.Time
	lastError   error
	runs        int
	failures    int
	// Whether the last run waited, and whether the addresses expired since the wait started.
	waiting, waitExpired bool

	running sync.WaitGroup
	// A value runs the source now, rather than at its next interval.
	trigger chan struct{}

	// push: the file of the addresses the router sent, and what Start was told to call after a
	// change.
	pushFile string
	ran      func()
}

// HomeAssistantStates are the states of Home Assistant's entities that homeassistant sources read:
// State returns the latest of an entity, or of its attribute when not empty; or an error, an
// ErrWaiting one while Home Assistant isn't connected, or hasn't sent it yet.
type HomeAssistantStates interface {
	State(entity, attribute string) (string, error)
}

// ErrWaiting is in the error of a run that waits for what it reads, as Home Assistant while it
// restarts: no failure, logged when the wait starts and ends only; the source's addresses stay
// for their lifetime, as through a failure.
var ErrWaiting = errors.New("waiting")

// New makes the source of the configuration. baseDir is where commands run; states, which can be
// nil without homeassistant sources, are Home Assistant's.
func New(name string, cfg config.Source, baseDir string, states HomeAssistantStates) (*Source, error) {
	s := &Source{name: name, config: cfg, addrs: ipv6disc.NewAddrCollection(), trigger: make(chan struct{}, 1)}
	switch cfg.Type {
	case config.SourceHTTP:
		s.fetch = httpFetcher(cfg.Family, cfg.URLs, defaultEchoURLs)
	case config.SourceDNS:
		s.fetch = dnsFetcher(cfg.Family, defaultResolvers)
	case config.SourceCommand:
		s.fetch = commandFetcher(cfg, baseDir)
	case config.SourceStatic:
		s.fetch = staticFetcher(cfg.Addresses)
	case config.SourceHomeAssistant:
		if states == nil {
			return nil, fmt.Errorf("source %s: a homeassistant source needs Home Assistant", name)
		}
		s.fetch = homeAssistantFetcher(states, cfg.Entity, cfg.Attribute)
	case config.SourcePush:
		// Nothing runs: the router sends. What it sent before a restart is kept.
		s.pushFile = pushFile(name, cfg, baseDir)
		if err := s.load(); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("source %s: unknown type %q", name, cfg.Type)
	}
	return s, nil
}

func (s *Source) Name() string { return s.name }

// Start runs the source now and at every interval, until ctx is done; Wait waits for it. ran,
// which can be nil, is called after each run.
func (s *Source) Start(ctx context.Context, logger *zap.SugaredLogger, ran func()) {
	if s.IsPush() {
		// Nothing runs: a push matches again.
		s.mutex.Lock()
		s.ran = ran
		s.mutex.Unlock()
		return
	}
	s.running.Add(1)
	go func() {
		defer s.running.Done()
		ticker := time.NewTicker(s.config.Interval.Duration)
		defer ticker.Stop()
		for {
			s.run(ctx, logger)
			if ran != nil && ctx.Err() == nil {
				ran()
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			case <-s.trigger:
			}
		}
	}()
}

// Trigger runs the source now, as when the value it reads changed.
func (s *Source) Trigger() {
	select {
	case s.trigger <- struct{}{}:
	default:
	}
}

func (s *Source) Wait() {
	s.running.Wait()
}

// runTimeout bounds a run: within the interval, so runs don't overlap, and a minute at most.
func (s *Source) runTimeout() time.Duration {
	return min(max(s.config.Interval.Duration-time.Second, s.config.Interval.Duration/2), time.Minute)
}

// attempt bounds one try, of the left that remain, with its share of the time the run has left: one
// that hangs doesn't take the time of the next ones, and what one that fails fast leaves is theirs.
func attempt(ctx context.Context, left int) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Deadline()
	if !ok || left <= 1 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, time.Until(deadline)/time.Duration(left))
}

func (s *Source) run(ctx context.Context, logger *zap.SugaredLogger) {
	ctx, cancel := context.WithTimeout(ctx, s.runTimeout())
	defer cancel()

	addrs, err := s.fetch(ctx)
	if errors.Is(ctx.Err(), context.Canceled) {
		return // stopping
	}
	waiting := errors.Is(err, ErrWaiting)
	had := len(s.addrs.Get()) > 0
	// What a run gives stays, even when it failed for a part, as for one family of two.
	current := make(map[netip.Addr]bool, len(addrs))
	for _, ip := range addrs {
		// Without a MAC, which is how the status tells them from the discovered ones: they stay in
		// this collection, never in the discovery's state, which takes no address without one.
		s.addrs.Seen(ipv6disc.NewAddr(nil, ip, s.name, s.config.Lifetime.Duration, nil), s.name)
		current[ip.WithZone("")] = true
	}
	for _, addr := range s.addrs.Get() {
		// A run that worked says what the source has now: an address it no longer gives, as the
		// public address before the ISP changed it, goes at once. A failed run keeps them for
		// their lifetime, through an outage of the service asked.
		if !addr.Valid() || err == nil && !current[addr.WithZone("")] {
			s.addrs.Remove(addr)
		}
	}

	s.mutex.Lock()
	s.lastRun = time.Now()
	s.runs++
	s.lastError = err
	switch {
	case err == nil:
		s.lastSuccess = s.lastRun
	case !waiting:
		s.failures++
	}
	wasWaiting := s.waiting
	s.waiting = waiting
	expired := waiting && had && len(s.addrs.Get()) == 0 && !s.waitExpired
	if !waiting {
		s.waitExpired = false
	} else if expired {
		s.waitExpired = true
	}
	s.mutex.Unlock()

	switch {
	case expired:
		logger.Warnf("source %s: still %s after its lifetime, %s: its addresses have expired", s.name, err, s.config.Lifetime.Duration)
	case waiting && !wasWaiting:
		logger.Infof("source %s: %s; its addresses stay for their lifetime, %s", s.name, err, s.config.Lifetime.Duration)
	case waiting:
		logger.Debugf("source %s: %s", s.name, err)
	case err != nil:
		logger.Errorf("source %s: %s", s.name, err)
	case wasWaiting:
		logger.Infof("source %s: done waiting: %v", s.name, addrs)
	default:
		logger.Debugf("source %s: %v", s.name, addrs)
	}
}

// Addresses returns the addresses the source gave within their lifetime.
func (s *Source) Addresses() *ipv6disc.AddrCollection {
	return s.addrs.FilterValid()
}

// Status is the state of a source, to show.
type Status struct {
	Name        string     `json:"name"`
	Type        string     `json:"type"`
	Addresses   []string   `json:"addresses"`
	LastRun     *time.Time `json:"last_run,omitempty"`
	LastSuccess *time.Time `json:"last_success,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	Runs        int        `json:"runs"`
	Failures    int        `json:"failures"`
}

// Status returns the state of the source. hideSensible hides the error, which can tell a command's
// arguments.
func (s *Source) Status(hideSensible bool) Status {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	status := Status{
		Name:      s.name,
		Type:      s.config.Type,
		Addresses: s.Addresses().Strings(),
		Runs:      s.runs,
		Failures:  s.failures,
	}
	if !s.lastRun.IsZero() {
		lastRun := s.lastRun
		status.LastRun = &lastRun
	}
	if !s.lastSuccess.IsZero() {
		lastSuccess := s.lastSuccess
		status.LastSuccess = &lastSuccess
	}
	if s.lastError != nil {
		status.LastError = s.lastError.Error()
		if hideSensible {
			status.LastError = "<sensible data hidden>"
		}
	}
	return status
}

func staticFetcher(addresses []string) fetcher {
	var addrs []netip.Addr
	for _, a := range addresses {
		addrs = append(addrs, netip.MustParseAddr(a)) // checked by the configuration
	}
	return func(context.Context) ([]netip.Addr, error) {
		return addrs, nil
	}
}

// ofFamily tells whether ip is of family, 4 or 6.
func ofFamily(ip netip.Addr, family int) bool {
	if family == 4 {
		return ip.Unmap().Is4()
	}
	return ip.Is6() && !ip.Is4In6()
}
