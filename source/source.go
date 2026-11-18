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

	running sync.WaitGroup
}

// New makes the source of the configuration. baseDir is where commands run.
func New(name string, cfg config.Source, baseDir string) (*Source, error) {
	s := &Source{name: name, config: cfg, addrs: ipv6disc.NewAddrCollection()}
	switch cfg.Type {
	case config.SourceHTTP:
		s.fetch = httpFetcher(cfg.Family, cfg.URLs, defaultEchoURLs)
	case config.SourceDNS:
		s.fetch = dnsFetcher(cfg.Family, defaultResolvers)
	case config.SourceCommand:
		s.fetch = commandFetcher(cfg, baseDir)
	case config.SourceStatic:
		s.fetch = staticFetcher(cfg.Addresses)
	default:
		return nil, fmt.Errorf("source %s: unknown type %q", name, cfg.Type)
	}
	return s, nil
}

func (s *Source) Name() string { return s.name }

// Start runs the source now and at every interval, until ctx is done; Wait waits for it. ran,
// which can be nil, is called after each run.
func (s *Source) Start(ctx context.Context, logger *zap.SugaredLogger, ran func()) {
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
			}
		}
	}()
}

func (s *Source) Wait() {
	s.running.Wait()
}

// runTimeout bounds a run: within the interval, so runs don't overlap, and a minute at most.
func (s *Source) runTimeout() time.Duration {
	return min(max(s.config.Interval.Duration-time.Second, s.config.Interval.Duration/2), time.Minute)
}

func (s *Source) run(ctx context.Context, logger *zap.SugaredLogger) {
	ctx, cancel := context.WithTimeout(ctx, s.runTimeout())
	defer cancel()

	addrs, err := s.fetch(ctx)
	if errors.Is(ctx.Err(), context.Canceled) {
		return // stopping
	}
	// What a run gives stays, even when it failed for a part, as for one family of two.
	for _, ip := range addrs {
		s.addrs.Seen(ipv6disc.NewAddr(nil, ip, s.name, s.config.Lifetime.Duration, nil), s.name)
	}
	for _, addr := range s.addrs.Get() {
		if !addr.Valid() {
			s.addrs.Remove(addr)
		}
	}

	s.mutex.Lock()
	s.lastRun = time.Now()
	s.runs++
	s.lastError = err
	if err != nil {
		s.failures++
	} else {
		s.lastSuccess = s.lastRun
	}
	s.mutex.Unlock()

	if err != nil {
		logger.Errorf("source %s: %s", s.name, err)
	} else {
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
