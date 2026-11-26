// Package resolver is a DNS server for a network's clients: it answers the names of its zones,
// with the addresses that tasks give them and the records written for them, and records of its
// own, and asks its upstream servers the rest, whose answers it relays, and keeps for their TTL.
//
// Per query, in order: a client outside allow is REFUSED; a name of the resolver's records is
// answered from them; a name of the zone with the longest suffix, if a task publishes it or a
// record has it, is answered from those, with no data of a type it doesn't have; the reverse of
// an address that one of those names has, a PTR query, with the names; anything else is answered
// from the cache, or forwarded, to the upstream servers in order, over plain DNS, TLS or HTTPS,
// and SERVFAIL when none answers. A CNAME is followed among the local names, up to MaxChain
// steps, and to the upstream servers past them.
package resolver

import (
	"fmt"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/certfile"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/listen"
)

// MaxChain is how many CNAMEs an answer follows.
const MaxChain = 8

// Config is a resolver, as the configuration gives it: Check tells what is wrong with it.
type Config struct {
	Name string
	// Where its errors are, in the configuration: resolvers.lan.
	Path   string
	Listen []listen.Entry
	// The text of each listen entry, as written, for errors: or none.
	ListenLines []string
	// The allow of each listen entry's sockets, of a listener's: none, Allow. Allow, when given,
	// replaces it.
	ListenAllow [][]netip.Prefix
	// The listener of each listen entry, by its name: none, the resolver's own listen.
	ListenListeners []string
	// Where it answers over the encrypted transports, each entry with its transport and its text:
	// DNS over TLS, over HTTPS and over QUIC.
	Encrypted []EncryptedListen
	// The certificate the encrypted transports show, read again when its files change: of
	// certificates, by its name. Required with Encrypted; while it has none, as before ACME got
	// it, they refuse their connections.
	Certificate     *certfile.Certificate
	CertificateName string
	// The networks of the clients it answers. None: the networks of the machine's addresses it
	// listens on, read when it starts.
	Allow []netip.Prefix
	// In order: host:port, of plain DNS, or tls://host[:port] or https://host[:port]/path, as
	// written; the host an address, or a host name, which Bootstrap finds.
	Upstreams []string
	// host:port, addresses: the servers asked the addresses of the upstreams given by host name.
	Bootstrap []string
	// Absolute, of no zone.
	Records []dns.RR
	// The text of each record, as written, for errors: or none.
	Lines []string
	Zones []Zone
	// How many answers forwarded it keeps: 0, none.
	CacheSize int
	// Whether the reverse of the private networks' addresses that it has no name of is asked of the
	// upstream servers, out of RFC 6303: by default, it is no such name, its own.
	ForwardUnknownPrivateReverse bool
	// The keys that may change records by dynamic updates, over plain DNS and DNS over TLS.
	UpdateKeys []UpdateKey
	// The networks the keys may send from, of those that give none. None: Allow.
	UpdateAllow []netip.Prefix
	// Where the updates are logged, and the messages refused: nowhere, for nil.
	Infof, Warnf func(string, ...any)
}

// Zone is a credential's zone, which a resolver answers.
type Zone struct {
	Credential string
	// Absolute, in lower case.
	Name string
	// Where its records are, in the configuration: credentials.home.settings.records.
	Path    string
	Records []dns.RR
	// The text of each record, as written, for errors: or none.
	Lines []string
	// The names the tasks publish, absolute and in lower case, each with a task that does.
	Tasks map[string]string
	// Of the tasks' addresses.
	TTL time.Duration
	// The addresses the tasks give the names, as the provider has them: nil while checking.
	Addresses *Addresses
}

// Addresses are the addresses of a zone's names, as the tasks give them. Safe for concurrent use.
type Addresses struct {
	mutex sync.RWMutex
	names map[string][]Address
}

// Address is an address of a name, with when it expires. Expires is asked as the resolver
// answers, since a sighting moves it later without the name being set again; nil, or a zero
// time, is never.
type Address struct {
	Addr    netip.Addr
	Expires func() time.Time
}

func NewAddresses() *Addresses {
	return &Addresses{names: make(map[string][]Address)}
}

// Set makes addrs the addresses of name, absolute, never expiring: none removes them.
func (a *Addresses) Set(name string, addrs []netip.Addr) {
	all := make([]Address, len(addrs))
	for i, addr := range addrs {
		all[i] = Address{Addr: addr}
	}
	a.SetExpiring(name, all)
}

// SetExpiring makes addrs the addresses of name, absolute: none removes them. An address given
// twice, as with a zone and without, expires with the later.
func (a *Addresses) SetExpiring(name string, addrs []Address) {
	name = strings.ToLower(dns.Fqdn(name))
	var kept []Address
	for _, addr := range addrs {
		addr.Addr = addr.Addr.WithZone("").Unmap()
		if !addr.Addr.IsValid() {
			continue
		}
		i := slices.IndexFunc(kept, func(k Address) bool { return k.Addr == addr.Addr })
		if i < 0 {
			kept = append(kept, addr)
			continue
		}
		if first, second := kept[i].Expires, addr.Expires; first == nil || second == nil {
			kept[i].Expires = nil
		} else {
			kept[i].Expires = func() time.Time {
				x, y := first(), second()
				if x.IsZero() || y.IsZero() {
					return time.Time{}
				}
				return later(x, y)
			}
		}
	}
	slices.SortFunc(kept, func(x, y Address) int { return x.Addr.Compare(y.Addr) })
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if len(kept) == 0 {
		delete(a.names, name)
		return
	}
	a.names[name] = kept
}

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// Get returns the addresses of name, absolute.
func (a *Addresses) Get(name string) []netip.Addr {
	var addrs []netip.Addr
	for _, addr := range a.expiring(name) {
		addrs = append(addrs, addr.Addr)
	}
	return addrs
}

func (a *Addresses) expiring(name string) []Address {
	if a == nil {
		return nil
	}
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	return a.names[strings.ToLower(dns.Fqdn(name))]
}

// capTTL is ttl, or less: no longer than the soonest of expires is from now, so that a client
// keeps no address past when the resolver gives it up; 1s at least, as an address goes. Seconds.
func capTTL(ttl time.Duration, expires []func() time.Time, now time.Time) uint32 {
	for _, e := range expires {
		if e == nil {
			continue
		}
		if t := e(); !t.IsZero() {
			ttl = min(ttl, t.Sub(now))
		}
	}
	return uint32(max(ttl/time.Second, 1))
}

// Names returns the names that have addresses now, absolute.
func (a *Addresses) Names() []string {
	if a == nil {
		return nil
	}
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	return slices.Sorted(maps.Keys(a.names))
}

// names are the names of a zone, or the resolver's own, under apex.
type names struct {
	apex    string
	zone    *Zone
	records map[string][]dns.RR
	tasks   map[string]string
	// Every name with data, and every name above one, to apex: a wildcard answers a name only
	// below the closest of them.
	exists map[string]bool
}

func newNames(apex string, zone *Zone) *names {
	return &names{apex: apex, zone: zone, records: make(map[string][]dns.RR), tasks: make(map[string]string), exists: make(map[string]bool)}
}

func (n *names) add(name string) {
	for name != "" && dns.IsSubDomain(n.apex, name) && !n.exists[name] {
		n.exists[name] = true
		name = parent(name)
	}
}

// parent is the name above name, "" above the root.
func parent(name string) string {
	if name == "." {
		return ""
	}
	_, rest, _ := strings.Cut(name, ".")
	if rest == "" {
		return "."
	}
	return rest
}

func (n *names) has(name string) bool {
	_, task := n.tasks[name]
	return task || len(n.records[name]) > 0
}

// owner is the name whose data answers name: itself, or the wildcard of the closest name above
// it that exists; "" for none.
func (n *names) owner(name string) string {
	if n.has(name) {
		return name
	}
	if n.exists[name] {
		return ""
	}
	for p := parent(name); p != "" && dns.IsSubDomain(n.apex, p); p = parent(p) {
		wildcard := "*." + p
		if p == "." {
			wildcard = "*."
		}
		if n.has(wildcard) {
			return wildcard
		}
		if n.exists[p] {
			return ""
		}
	}
	return ""
}

// table is the names of a resolver. Built once: its maps don't change after.
type table struct {
	own   *names
	zones []*names
	// The names of each address that an A or AAAA record gives, for its reverse.
	reverseOf map[netip.Addr][]reverseName
}

// namesOf returns the names that name is of: the zone's with the longest suffix, or the
// resolver's own.
func (t *table) namesOf(name string) *names {
	var best *names
	for _, z := range t.zones {
		if dns.IsSubDomain(z.apex, name) && (best == nil || dns.CountLabel(z.apex) > dns.CountLabel(best.apex)) {
			best = z
		}
	}
	if best == nil {
		return t.own
	}
	return best
}

type kind int

const (
	// Not a name of the resolver: the upstream servers answer it.
	notLocal kind = iota
	found
	noData
)

type lookup struct {
	kind kind
	// The records, each with the name asked, a wildcard's too.
	records []dns.RR
	names   *names
}

// lookup answers asked, an absolute name, of qtype, from the resolver's names alone: the records
// have its spelling.
func (t *table) lookup(asked string, qtype uint16) lookup {
	name := strings.ToLower(asked)
	n := t.namesOf(name)
	// A name the zone was given addresses for that it didn't know of: a task's template made it,
	// for a host called so. It answers while it has addresses, before a wildcard above it, and
	// after the names written, the tasks' and the records', which stay theirs.
	given := n.zone != nil && !n.has(name) && !isWildcard(name) && len(n.zone.Addresses.Get(name)) > 0
	owner := name
	if !given {
		owner = n.owner(name)
	}
	if owner == "" {
		return lookup{kind: notLocal, names: n}
	}
	var records []dns.RR
	if _, ok := n.tasks[owner]; ok || given {
		// One TTL for the records, as an RRset has (RFC 2181 5.2): the zone's, or less, to when
		// the first of them expires.
		var expires []func() time.Time
		for _, a := range n.zone.Addresses.expiring(owner) {
			addr := a.Addr
			header := dns.RR_Header{Name: asked, Class: dns.ClassINET}
			switch {
			case addr.Is4() && (qtype == dns.TypeA || qtype == dns.TypeANY):
				header.Rrtype = dns.TypeA
				records = append(records, &dns.A{Hdr: header, A: addr.AsSlice()})
			case addr.Is6() && (qtype == dns.TypeAAAA || qtype == dns.TypeANY):
				header.Rrtype = dns.TypeAAAA
				records = append(records, &dns.AAAA{Hdr: header, AAAA: addr.AsSlice()})
			default:
				continue
			}
			expires = append(expires, a.Expires)
		}
		ttl := capTTL(n.zone.TTL, expires, time.Now())
		for _, rr := range records {
			rr.Header().Ttl = ttl
		}
	} else {
		all := n.records[owner]
		for _, rr := range all {
			if t := rr.Header().Rrtype; t == qtype || qtype == dns.TypeANY || t == dns.TypeCNAME {
				records = append(records, rr)
			}
		}
		// A CNAME is alone at its name, so it is all of records then.
		for i, rr := range records {
			records[i] = dns.Copy(rr)
			records[i].Header().Name = asked
		}
	}
	if len(records) == 0 {
		return lookup{kind: noData, names: n}
	}
	return lookup{kind: found, records: records, names: n}
}

// soa is the SOA the resolver makes for a zone, for the answers with no data.
func soa(zone string) *dns.SOA {
	negative := uint32(NegativeTTL.Seconds())
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: negative},
		Ns:      zone,
		Mbox:    "hostmaster." + strings.TrimPrefix(zone, "."),
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  negative,
	}
}

// build makes the table of cfg, or tells what in it is wrong.
func build(cfg Config) (*table, error) {
	t := &table{own: newNames(".", nil)}
	byName := make(map[string]Zone)
	for i := range cfg.Zones {
		z := &cfg.Zones[i]
		z.Name = strings.ToLower(dns.Fqdn(z.Name))
		if other, ok := byName[z.Name]; ok {
			return nil, fmt.Errorf("credentials %s and %s are both the zone %s of resolver %s: a zone can belong to only one credential", other.Credential, z.Credential, strings.TrimSuffix(z.Name, "."), cfg.Name)
		}
		byName[z.Name] = *z
		n := newNames(z.Name, z)
		for name, task := range z.Tasks {
			name = strings.ToLower(dns.Fqdn(name))
			n.tasks[name] = task
			n.add(name)
		}
		for i, rr := range z.Records {
			name, text := rr.Header().Name, quoted(z.Lines, i, rr)
			if !dns.IsSubDomain(z.Name, name) {
				return nil, fmt.Errorf("%s: %s: %s isn't in the zone %s: a zone's records must be for its names, relative to it or absolute within it", z.Path, text, name, strings.TrimSuffix(z.Name, "."))
			}
			if task, ok := n.tasks[name]; ok {
				return nil, fmt.Errorf("%s: %s: %s is published by task %s, which gives its addresses: records are for other names", z.Path, text, name, task)
			}
			n.records[name] = append(n.records[name], rr)
			n.add(name)
		}
		if err := checkCNAMEs(n, z.Path); err != nil {
			return nil, err
		}
		t.zones = append(t.zones, n)
	}
	path := cfg.Path + ".records"
	for i, rr := range cfg.Records {
		name, text := rr.Header().Name, quoted(cfg.Lines, i, rr)
		if z := t.namesOf(name).zone; z != nil {
			return nil, fmt.Errorf("%s: %s: %s is in the zone %s, of credential %s: give it in that credential's records", path, text, name, strings.TrimSuffix(z.Name, "."), z.Credential)
		}
		t.own.records[name] = append(t.own.records[name], rr)
		t.own.add(name)
	}
	if err := checkCNAMEs(t.own, path); err != nil {
		return nil, err
	}
	if err := t.checkLoops(cfg.Path); err != nil {
		return nil, err
	}
	t.indexReverse()
	return t, nil
}

// quoted is the record i, as written in lines, or as rr, in quotes.
func quoted(lines []string, i int, rr dns.RR) string {
	if i < len(lines) {
		return strconv.Quote(lines[i])
	}
	return strconv.Quote(rr.String())
}

// checkCNAMEs tells of a name with a CNAME and other data: a client asking it of a type would get
// one or the other.
func checkCNAMEs(n *names, path string) error {
	for _, name := range slices.Sorted(maps.Keys(n.records)) {
		records := n.records[name]
		cnames := 0
		for _, rr := range records {
			if rr.Header().Rrtype == dns.TypeCNAME {
				cnames++
			}
		}
		if cnames > 0 && len(records) > 1 {
			return fmt.Errorf("%s: %s has a CNAME and other records: a name with a CNAME can't have others, since its data is the target's", path, name)
		}
	}
	return nil
}

// checkLoops tells of CNAMEs that lead back to themselves, among the local names.
func (t *table) checkLoops(path string) error {
	for _, n := range append([]*names{t.own}, t.zones...) {
		for _, name := range slices.Sorted(maps.Keys(n.records)) {
			chain := []string{name}
			next := name
			for {
				l := t.lookup(next, dns.TypeA)
				if l.kind != found {
					break
				}
				cname, ok := l.records[0].(*dns.CNAME)
				if !ok {
					break
				}
				next = strings.ToLower(cname.Target)
				if slices.Contains(chain, next) {
					chain = append(chain, next)
					return fmt.Errorf("%s: the CNAMEs %s are a loop", path, strings.Join(chain, " -> "))
				}
				chain = append(chain, next)
			}
		}
	}
	return nil
}

// Check tells what is wrong with cfg: the rules of its records, and of its zones'.
func Check(cfg Config) error {
	cfg.Zones = slices.Clone(cfg.Zones)
	_, err := build(cfg)
	return err
}
