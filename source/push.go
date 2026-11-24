package source

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6disc"
)

// pushState is what a push source keeps in its file: the addresses the router sent last, and when.
type pushState struct {
	Addresses []string  `json:"addresses"`
	At        time.Time `json:"at"`
	// The prefix of the LAN, and when it was sent, which may be before At.
	Prefix   string     `json:"prefix,omitempty"`
	PrefixAt *time.Time `json:"prefix_at,omitempty"`
}

// pushFile is the file of a push source: its state_file, relative to the configuration's folder,
// or push-<source>.json there.
func pushFile(name string, cfg config.Source, baseDir string) string {
	file := cfg.StateFile
	if file == "" {
		file = "push-" + name + ".json"
	}
	if filepath.IsAbs(file) {
		return file
	}
	return filepath.Join(baseDir, file)
}

// IsPush tells whether the source is one a router pushes to.
func (s *Source) IsPush() bool { return s.config.Type == config.SourcePush }

// Accepts tells whether password is the source's: compared in constant time, as anyone who
// reaches the web server can try.
func (s *Source) Accepts(password string) bool {
	return subtle.ConstantTimeCompare([]byte(password), []byte(s.config.Password)) == 1
}

// Push takes the addresses a router sent, and the IPv6 prefix of its LAN, if valid. Each family
// the addresses have replaces the source's of that family, and the other family's stay: a router
// that sends IPv4 and IPv6 apart doesn't take one away with the other. The prefix replaces the
// one before; without one, that one stays. They are kept for the source's lifetime, written to
// its file, and the tasks match again. It tells whether they changed. Pushes are one at a time.
func (s *Source) Push(addrs []netip.Addr, prefix netip.Prefix) (bool, error) {
	if len(addrs) == 0 && !prefix.IsValid() {
		return false, errors.New("no address, nor prefix")
	}
	s.pushMutex.Lock()
	defer s.pushMutex.Unlock()
	now := time.Now()
	prefixChanged := false
	if prefix.IsValid() {
		prefix = prefix.Masked()
		s.mutex.Lock()
		before, had := s.prefixLocked(now)
		prefixChanged = !had || before != prefix
		s.prefix, s.prefixAt = prefix, now
		s.mutex.Unlock()
	}
	families := map[int]bool{}
	sent := map[netip.Addr]bool{}
	for _, ip := range addrs {
		ip = ip.Unmap().WithZone("")
		sent[ip] = true
		families[familyOf(ip)] = true
	}
	before := slices.Sorted(slices.Values(s.Addresses().Strings()))
	for _, addr := range s.addrs.Get() {
		ip := addr.Unmap().WithZone("")
		if families[familyOf(ip)] && !sent[ip] {
			s.addrs.Remove(addr)
		}
	}
	for ip := range sent {
		s.addrs.Seen(ipv6disc.NewAddr(nil, ip, s.name, s.config.Lifetime.Duration, nil), s.name)
	}
	after := slices.Sorted(slices.Values(s.Addresses().Strings()))

	s.mutex.Lock()
	s.lastRun, s.lastSuccess, s.lastError = now, now, nil
	s.runs++
	ran := s.ran
	s.mutex.Unlock()

	err := s.save(after, now)
	if ran != nil {
		ran()
	}
	return prefixChanged || !slices.Equal(before, after), err
}

// Prefix is the IPv6 prefix of its LAN that the router sent last, if it sent one within the
// source's lifetime.
func (s *Source) Prefix() (netip.Prefix, bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.prefixLocked(time.Now())
}

// prefixLocked is Prefix, at now, with the mutex held.
func (s *Source) prefixLocked(now time.Time) (netip.Prefix, bool) {
	if !s.prefix.IsValid() || now.Sub(s.prefixAt) >= s.config.Lifetime.Duration {
		return netip.Prefix{}, false
	}
	return s.prefix, true
}

// familyOf is 4 or 6.
func familyOf(ip netip.Addr) int {
	if ip.Is4() {
		return 4
	}
	return 6
}

// save writes the addresses, and the prefix, to the source's file, through a file beside it,
// renamed.
func (s *Source) save(addrs []string, at time.Time) error {
	state := pushState{Addresses: addrs, At: at.UTC()}
	s.mutex.Lock()
	if p, ok := s.prefixLocked(at); ok {
		prefixAt := s.prefixAt.UTC()
		state.Prefix, state.PrefixAt = p.String(), &prefixAt
	}
	s.mutex.Unlock()
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.pushFile), 0o700); err != nil {
		return fmt.Errorf("source %s: keeping the addresses: %w", s.name, err)
	}
	tmp := s.pushFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("source %s: keeping the addresses: %w", s.name, err)
	}
	if err := os.Rename(tmp, s.pushFile); err != nil {
		return fmt.Errorf("source %s: keeping the addresses: %w", s.name, err)
	}
	return nil
}

// load takes the addresses of the source's file, as the router sent them before a restart, for
// what is left of their lifetime. A file there is none of is no error: the router hasn't sent yet.
func (s *Source) load() error {
	data, err := os.ReadFile(s.pushFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("source %s: %w", s.name, err)
	}
	var state pushState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("source %s: %s doesn't read: %w", s.name, s.pushFile, err)
	}
	if state.Prefix != "" {
		prefix, err := netip.ParsePrefix(state.Prefix)
		if err != nil {
			return fmt.Errorf("source %s: %s has the prefix %q: %w", s.name, s.pushFile, state.Prefix, err)
		}
		prefixAt := state.At
		if state.PrefixAt != nil {
			prefixAt = *state.PrefixAt
		}
		// Prefix tells whether it is still within the lifetime.
		s.mutex.Lock()
		s.prefix, s.prefixAt = prefix, prefixAt
		s.mutex.Unlock()
	}
	left := s.config.Lifetime.Duration - time.Since(state.At)
	if left <= 0 {
		return nil
	}
	for _, a := range state.Addresses {
		ip, err := netip.ParseAddr(a)
		if err != nil {
			return fmt.Errorf("source %s: %s has %q, not an address", s.name, s.pushFile, a)
		}
		s.addrs.Seen(ipv6disc.NewAddr(nil, ip, s.name, left, nil), s.name)
	}
	s.mutex.Lock()
	s.lastRun, s.lastSuccess = state.At, state.At
	s.mutex.Unlock()
	return nil
}
