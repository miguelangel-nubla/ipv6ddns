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

// pushState is what a push source keeps in its file: the addresses the router sent, and when it
// sent last.
type pushState struct {
	Addresses []string  `json:"addresses"`
	At        time.Time `json:"at"`
	// When each address was sent last, which may be before At: a router sends each family apart.
	// A file of before it was kept has none, and At is every address's.
	AddressesAt map[string]time.Time `json:"addresses_at,omitempty"`
	// The prefix of the LAN, and when it was sent, which may be before At.
	Prefix   string     `json:"prefix,omitempty"`
	PrefixAt *time.Time `json:"prefix_at,omitempty"`
}

// pushFile is the file of a push source: its state_file, relative to the state folder, or
// push-<source>.json there.
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
// reaches the web server can try. A source without one, which takes the updates of a key alone,
// accepts none.
func (s *Source) Accepts(password string) bool {
	if s.config.Password == "" {
		return false
	}
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
	families := map[int]bool{}
	for _, ip := range addrs {
		families[familyOf(ip.Unmap())] = true
	}
	return s.push(addrs, prefix, families)
}

// Replace makes the source's addresses those given, of both families, none for none, as a key's
// dynamic update has them: kept, written and matched as Push's. It tells whether they changed.
func (s *Source) Replace(addrs []netip.Addr) (bool, error) {
	return s.push(addrs, netip.Prefix{}, map[int]bool{4: true, 6: true})
}

// push takes the addresses, which replace the source's of the families given, and the prefix.
func (s *Source) push(addrs []netip.Addr, prefix netip.Prefix, families map[int]bool) (bool, error) {
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
	sent := map[netip.Addr]bool{}
	for _, ip := range addrs {
		sent[ip.Unmap().WithZone("")] = true
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
	// When each was sent, for the file: of those the source still has alone.
	sentAt := make(map[string]time.Time, len(after))
	for _, a := range after {
		at, ok := s.sentAt[a]
		if ip, err := netip.ParseAddr(a); !ok || err == nil && sent[ip] {
			at = now
		}
		sentAt[a] = at
	}
	s.sentAt = sentAt

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

// save writes the addresses, each with when it was sent, and the prefix, to the source's file,
// through a file beside it, renamed. The push's mutex is held.
func (s *Source) save(addrs []string, at time.Time) error {
	state := pushState{Addresses: addrs, At: at.UTC(), AddressesAt: make(map[string]time.Time, len(addrs))}
	for _, a := range addrs {
		state.AddressesAt[a] = s.sentAt[a].UTC()
	}
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

// load takes the addresses of the source's file, as the router sent them before a restart, each
// for what is left of its lifetime from when it was sent: a restart renews none. A file there is
// none of is no error: the router hasn't sent yet.
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
	s.sentAt = map[string]time.Time{}
	for _, a := range state.Addresses {
		ip, err := netip.ParseAddr(a)
		if err != nil {
			return fmt.Errorf("source %s: %s has %q, not an address", s.name, s.pushFile, a)
		}
		at, ok := state.AddressesAt[a]
		if !ok {
			at = state.At
		}
		left := s.config.Lifetime.Duration - time.Since(at)
		if left <= 0 {
			continue
		}
		ip = ip.Unmap().WithZone("")
		s.addrs.Seen(ipv6disc.NewAddr(nil, ip, s.name, left, nil), s.name)
		s.sentAt[ip.String()] = at
	}
	if time.Since(state.At) >= s.config.Lifetime.Duration {
		return nil
	}
	s.mutex.Lock()
	s.lastRun, s.lastSuccess = state.At, state.At
	s.mutex.Unlock()
	return nil
}
