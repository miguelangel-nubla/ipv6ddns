package ipv6ddns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/ddns"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/resolver"
	"github.com/miguelangel-nubla/ipv6ddns/source"
	"github.com/miguelangel-nubla/ipv6disc"
)

// updateKeys are the keys of a resolver's dynamic updates, each with a grant of each of its
// permissions: none without updates.
func (w *Worker) updateKeys(resolverName string, u *config.Updates) ([]resolver.UpdateKey, error) {
	if u == nil {
		return nil, nil
	}
	var keys []resolver.UpdateKey
	for _, name := range slices.Sorted(maps.Keys(u.Keys)) {
		k := u.Keys[name]
		key := k.Spec
		key.Grants = nil
		for i, p := range k.Permissions {
			path := fmt.Sprintf("resolvers.%s.updates.keys.%s.permissions[%d].%s", resolverName, name, i, p.Kind())
			g, err := w.grant(path, name, p)
			if err != nil {
				return nil, err
			}
			key.Grants = append(key.Grants, g)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// grant is the grant of a permission: where what the key sends goes.
func (w *Worker) grant(path, key string, p config.Permission) (resolver.Grant, error) {
	switch {
	case p.Challenges != nil:
		endpoint, err := w.endpoint(p.Challenges.Credential)
		if err != nil {
			return nil, err
		}
		writer, ok := endpoint.Service.(ddns.TXTWriter)
		if !ok {
			return nil, fmt.Errorf("%s.credential: the provider of %s, %s, can't write the TXT records of the DNS challenge: give a credential of cloudflare, route53, rfc2136 or duckdns", path, p.Challenges.Credential, w.config.Credentials[p.Challenges.Credential].Provider)
		}
		g := newChallengeGrant(writer, p.Challenges.Names, filepath.Join(w.config.BaseDir, "challenges-"+key+"-"+p.Challenges.Credential+".json"),
			func(f string, args ...any) { w.logger.Warnf(path+": "+f, args...) })
		if err := g.load(); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		w.grantsToStart = append(w.grantsToStart, g)
		return g, nil
	}
	if p.Addresses != nil {
		a := p.Addresses
		s, ok := w.sources[a.Source]
		if !ok || !s.IsPush() {
			return nil, fmt.Errorf("%s.source: no push source %s", path, a.Source)
		}
		name := a.Name
		if name == "" {
			name = a.Source
		}
		return &addressesGrant{source: s, zone: resolver.Name("", a.Zone), name: resolver.Name(name, a.Zone),
			warnf: func(f string, args ...any) { w.logger.Warnf(path+": "+f, args...) }}, nil
	}
	n := p.Names
	zone := resolver.Name("", n.Zone)
	g := &namesGrant{
		state: w.discWorker.State, zone: zone, source: "updates." + key,
		file:    filepath.Join(w.config.BaseDir, "names-"+strings.TrimSuffix(zone, ".")+".json"),
		warnf:   func(f string, args ...any) { w.logger.Warnf(path+": "+f, args...) },
		records: make(map[string][]dns.RR),
	}
	if err := g.load(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	w.grantsToStart = append(w.grantsToStart, g)
	return g, nil
}

// namesRefresh is how often the names of a permission of names are given again to the hosts at
// their addresses: those that discovery found since get them, and a name removed, no longer given,
// expires with discovery's names.
var namesRefresh = time.Minute

// namesGrant is a permission of names: the A, AAAA and DHCID records of the names of a zone, as a
// DHCP server sends them. Each name goes to the host discovery has at one of its addresses, as a
// name the host said itself. The records are kept in a file, for a restart.
type namesGrant struct {
	state *ipv6disc.State
	zone  string
	// What the names are said by, in the report: updates.kea.
	source string
	file   string
	warnf  func(string, ...any)

	mutex   sync.Mutex
	records map[string][]dns.RR
}

func (g *namesGrant) Kind() string { return config.PermissionNames }

func (g *namesGrant) Scope() (string, []string, error) { return g.zone, nil, nil }

func (g *namesGrant) Types() []uint16 { return []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeDHCID} }

func (g *namesGrant) Records(name string) []dns.RR {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	return slices.Clone(g.records[name])
}

// Apply keeps the records, in the file first: one it can't write changes nothing. Then the
// names go to their hosts.
func (g *namesGrant) Apply(changes map[string][]dns.RR) error {
	g.mutex.Lock()
	next := maps.Clone(g.records)
	for name, rrs := range changes {
		if len(rrs) == 0 {
			delete(next, name)
		} else {
			next[name] = rrs
		}
	}
	if err := g.save(next); err != nil {
		g.mutex.Unlock()
		return err
	}
	g.records = next
	g.mutex.Unlock()
	g.give()
	return nil
}

// start gives the names to their hosts now, and at every refresh, until ctx is done.
func (g *namesGrant) start(ctx context.Context, running *sync.WaitGroup) {
	running.Add(1)
	go func() {
		defer running.Done()
		ticker := time.NewTicker(namesRefresh)
		defer ticker.Stop()
		for {
			g.give()
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

// give gives each name to the host discovery has at one of its addresses: every host that has one,
// as two of a name are told apart by discovery, as any.
func (g *namesGrant) give() {
	g.mutex.Lock()
	names := make(map[string][]netip.Addr)
	for name, rrs := range g.records {
		for _, rr := range rrs {
			var ip net.IP
			switch rr := rr.(type) {
			case *dns.A:
				ip = rr.A
			case *dns.AAAA:
				ip = rr.AAAA
			}
			if a, ok := netip.AddrFromSlice(ip); ok {
				names[name] = append(names[name], a.Unmap())
			}
		}
	}
	g.mutex.Unlock()
	if len(names) == 0 {
		return
	}
	// Of each address, the host discovery has it of.
	macs := make(map[netip.Addr]net.HardwareAddr)
	for _, c := range g.state.GetAll() {
		for _, a := range c.Get() {
			if len(a.Hw) > 0 {
				macs[a.Addr.WithZone("").Unmap()] = a.Hw
			}
		}
	}
	for name, addrs := range names {
		// The zone's own name is no host's.
		if name == g.zone {
			continue
		}
		label := strings.TrimSuffix(strings.TrimSuffix(name, "."+g.zone), ".")
		given := map[string]bool{}
		for _, a := range addrs {
			if hw, ok := macs[a]; ok && !given[hw.String()] {
				given[hw.String()] = true
				g.state.RegisterName(hw, label, g.source, 3*namesRefresh)
			}
		}
	}
}

// namesState is a names file: each name's records, in zone file syntax.
type namesState struct {
	Names map[string][]string `json:"names"`
}

func (g *namesGrant) save(records map[string][]dns.RR) error {
	st := namesState{Names: make(map[string][]string)}
	for name, rrs := range records {
		for _, rr := range rrs {
			st.Names[name] = append(st.Names[name], rr.String())
		}
	}
	if err := writeJSON(g.file, st); err != nil {
		return fmt.Errorf("keeping the names: %w", err)
	}
	return nil
}

// load reads the names file, if there is one: of names of the zone, of the grant's types.
func (g *namesGrant) load() error {
	var st namesState
	if ok, err := readJSON(g.file, &st); err != nil || !ok {
		return err
	}
	for name, lines := range st.Names {
		for _, line := range lines {
			rr, err := dns.NewRR(line)
			if err != nil || rr == nil || strings.ToLower(rr.Header().Name) != name || !g.Holds(name) || !slices.Contains(g.Types(), rr.Header().Rrtype) {
				return fmt.Errorf("reading the names, %s: %q is no record of %s", g.file, line, strings.TrimSuffix(name, "."))
			}
			g.records[name] = append(g.records[name], rr)
		}
	}
	return nil
}

// Holds tells whether name is one a host can have: one label below the zone, and no wildcard.
func (g *namesGrant) Holds(name string) bool {
	label, ok := strings.CutSuffix(name, "."+g.zone)
	return ok && label != "" && !strings.ContainsAny(label, ".*")
}

// addressesGrant is a permission of addresses: the A and AAAA records of one name, which are the
// addresses of a push source. Its records are the source's, so a restart keeps them, in its file.
type addressesGrant struct {
	source     *source.Source
	zone, name string
	warnf      func(string, ...any)
}

func (g *addressesGrant) Kind() string { return config.PermissionAddresses }

func (g *addressesGrant) Scope() (string, []string, error) {
	return g.zone, []string{g.name}, nil
}

func (g *addressesGrant) Types() []uint16 { return []uint16{dns.TypeA, dns.TypeAAAA} }

// Records are the source's addresses, as records of the name.
func (g *addressesGrant) Records(name string) []dns.RR {
	if name != g.name {
		return nil
	}
	var out []dns.RR
	for _, a := range g.source.Addresses().Get() {
		ip := a.Unmap().WithZone("")
		h := dns.RR_Header{Name: g.name, Class: dns.ClassINET, Ttl: 60}
		if ip.Is4() {
			h.Rrtype = dns.TypeA
			out = append(out, &dns.A{Hdr: h, A: ip.AsSlice()})
		} else {
			h.Rrtype = dns.TypeAAAA
			out = append(out, &dns.AAAA{Hdr: h, AAAA: ip.AsSlice()})
		}
	}
	return out
}

// Apply makes the source's addresses the name's records, all of them.
func (g *addressesGrant) Apply(changes map[string][]dns.RR) error {
	rrs, ok := changes[g.name]
	if !ok {
		return nil
	}
	var addrs []netip.Addr
	for _, rr := range rrs {
		var ip net.IP
		switch rr := rr.(type) {
		case *dns.A:
			ip = rr.A
		case *dns.AAAA:
			ip = rr.AAAA
		}
		if a, ok := netip.AddrFromSlice(ip); ok {
			addrs = append(addrs, a.Unmap())
		}
	}
	// The addresses are the source's once Replace returns, and the tasks have them: a file that
	// isn't written is told, not the update's error, which would say nothing changed.
	if _, err := g.source.Replace(addrs); err != nil {
		g.warnf("%s", err)
	}
	return nil
}

// challengeExpiry is how long a value of a challenge's record stays after its name last changed,
// when its client doesn't remove it: an ACME authority checks it within minutes.
var challengeExpiry = time.Hour

// challengeGrant is a permission of challenges: the TXT records of _acme-challenge of each of
// its names, written through a credential's provider. What it wrote is kept in its file, so that
// a client's removal after a restart, or the expiry, still removes it.
type challengeGrant struct {
	writer ddns.TXTWriter
	names  []string
	file   string
	warnf  func(string, ...any)

	mutex sync.Mutex
	// The zone and the challenges' names, absolute and in lower case, once the provider told them.
	zone       string
	challenges []string
	// The records of each name, as written last, and when; the timer that removes them, and the
	// generation of the name's records it is of: a timer of records since changed does nothing.
	records    map[string][]dns.RR
	changed    map[string]time.Time
	expiry     map[string]*time.Timer
	generation map[string]uint64
	// Once the worker stopped: no timer writes.
	closed bool
}

func newChallengeGrant(writer ddns.TXTWriter, names []string, file string, warnf func(string, ...any)) *challengeGrant {
	return &challengeGrant{writer: writer, names: names, file: file, warnf: warnf, records: make(map[string][]dns.RR),
		changed: make(map[string]time.Time), expiry: make(map[string]*time.Timer), generation: make(map[string]uint64)}
}

func (g *challengeGrant) Kind() string { return config.PermissionChallenges }

func (g *challengeGrant) Types() []uint16 { return []uint16{dns.TypeTXT} }

// Scope asks the provider the names in full, the first time: Route 53 learns its zone of AWS, and
// a time it can't is tried again at the next update.
func (g *challengeGrant) Scope() (string, []string, error) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	if g.challenges != nil {
		return g.zone, g.challenges, nil
	}
	zone, err := g.writer.FullName("")
	if err != nil {
		return "", nil, err
	}
	var challenges []string
	for _, n := range g.names {
		full, err := g.writer.FullName(strings.TrimPrefix(strings.Trim(n, "."), "*."))
		if err != nil {
			return "", nil, err
		}
		name := strings.ToLower(dns.Fqdn("_acme-challenge." + full))
		if !slices.Contains(challenges, name) {
			challenges = append(challenges, name)
		}
	}
	g.zone, g.challenges = strings.ToLower(dns.Fqdn(zone)), challenges
	return g.zone, g.challenges, nil
}

func (g *challengeGrant) Records(name string) []dns.RR {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	return slices.Clone(g.records[name])
}

// txtValues are the values of TXT records.
func txtValues(rrs []dns.RR) []string {
	var values []string
	for _, rr := range rrs {
		if txt, ok := rr.(*dns.TXT); ok {
			values = append(values, strings.Join(txt.Txt, ""))
		}
	}
	return values
}

// Apply writes the values of each name changed, all of them: a provider's SetTXT makes the
// records of a name those it is given. One that fails puts back those written before it, so
// that nothing is changed, as far as the provider lets.
func (g *challengeGrant) Apply(changes map[string][]dns.RR) error {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	var written []string
	for _, name := range slices.Sorted(maps.Keys(changes)) {
		if err := g.writer.SetTXT(strings.TrimSuffix(name, "."), txtValues(changes[name])); err != nil {
			for _, w := range written {
				if err := g.writer.SetTXT(strings.TrimSuffix(w, "."), txtValues(g.records[w])); err != nil {
					g.warnf("putting back the TXT records of %s: %s", strings.TrimSuffix(w, "."), err)
				}
			}
			return fmt.Errorf("writing the TXT records of %s: %w", strings.TrimSuffix(name, "."), err)
		}
		written = append(written, name)
	}
	now := time.Now()
	for _, name := range written {
		g.set(name, changes[name], now)
	}
	g.save()
	return nil
}

// set makes name's records those given, changed at, and its timer, of a new generation: mutex
// held.
func (g *challengeGrant) set(name string, rrs []dns.RR, at time.Time) {
	g.generation[name]++
	if t := g.expiry[name]; t != nil {
		t.Stop()
		delete(g.expiry, name)
	}
	if len(rrs) == 0 {
		delete(g.records, name)
		delete(g.changed, name)
		return
	}
	g.records[name], g.changed[name] = rrs, at
	if g.closed {
		return
	}
	generation := g.generation[name]
	g.expiry[name] = time.AfterFunc(max(time.Until(at.Add(challengeExpiry)), 0), func() { g.expire(name, generation) })
}

// expire removes the records of a name its client left, an hour after they last changed: unless
// they changed since, of a newer generation, or the worker stopped.
func (g *challengeGrant) expire(name string, generation uint64) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	if g.closed || g.generation[name] != generation || len(g.records[name]) == 0 {
		return
	}
	if err := g.writer.SetTXT(strings.TrimSuffix(name, "."), nil); err != nil {
		g.warnf("removing the TXT records of %s, which its client left: %s", strings.TrimSuffix(name, "."), err)
		return
	}
	g.set(name, nil, time.Now())
	g.save()
}

// start arms the timers of the records of its file, and stops every timer once ctx is done.
func (g *challengeGrant) start(ctx context.Context, running *sync.WaitGroup) {
	g.mutex.Lock()
	for name, rrs := range g.records {
		g.set(name, rrs, g.changed[name])
	}
	g.mutex.Unlock()
	running.Add(1)
	go func() {
		defer running.Done()
		<-ctx.Done()
		g.mutex.Lock()
		defer g.mutex.Unlock()
		g.closed = true
		for _, t := range g.expiry {
			t.Stop()
		}
	}()
}

// challengesState is a challenges file: each name's values, and when they last changed.
type challengesState struct {
	Names map[string]challengeState `json:"names"`
}

type challengeState struct {
	Values  []string  `json:"values"`
	Changed time.Time `json:"changed"`
}

// save writes the records to the file, telling of an error: what the provider has is the
// update's, whatever the file.
func (g *challengeGrant) save() {
	st := challengesState{Names: make(map[string]challengeState)}
	for name, rrs := range g.records {
		st.Names[name] = challengeState{Values: txtValues(rrs), Changed: g.changed[name].UTC()}
	}
	if err := writeJSON(g.file, st); err != nil {
		g.warnf("keeping the challenges: %s", err)
	}
}

// load reads the file, if there is one.
func (g *challengeGrant) load() error {
	var st challengesState
	if ok, err := readJSON(g.file, &st); err != nil || !ok {
		return err
	}
	for name, c := range st.Names {
		name = strings.ToLower(dns.Fqdn(name))
		if !strings.HasPrefix(name, "_acme-challenge.") {
			return fmt.Errorf("reading the challenges, %s: %s is no challenge's name", g.file, name)
		}
		var rrs []dns.RR
		for _, v := range c.Values {
			rrs = append(rrs, &dns.TXT{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{v}})
		}
		g.records[name], g.changed[name] = rrs, c.Changed
	}
	return nil
}

// writeJSON writes v to file, through a file beside it, renamed.
func writeJSON(file string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, file)
}

// readJSON reads file into v, and tells whether there was one.
func readJSON(file string, v any) (bool, error) {
	data, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", file, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return false, fmt.Errorf("reading %s: %w", file, err)
	}
	return true, nil
}
