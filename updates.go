package ipv6ddns

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/ddns"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/resolver"
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
			g, err := w.grant(path, p)
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
func (w *Worker) grant(path string, p config.Permission) (resolver.Grant, error) {
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
		return newChallengeGrant(writer, p.Challenges.Names, func(f string, args ...any) { w.logger.Warnf(path+": "+f, args...) }), nil
	}
	return nil, fmt.Errorf("%s: permissions of %s aren't taken yet", path, p.Kind())
}

// challengeExpiry is how long a value of a challenge's record stays after its name last changed,
// when its client doesn't remove it: an ACME authority checks it within minutes.
var challengeExpiry = time.Hour

// challengeGrant is a permission of challenges: the TXT records of _acme-challenge of each of
// its names, written through a credential's provider.
type challengeGrant struct {
	writer ddns.TXTWriter
	names  []string
	warnf  func(string, ...any)

	mutex sync.Mutex
	// The zone and the challenges' names, absolute and in lower case, once the provider told them.
	zone       string
	challenges []string
	// The records of each name, as written last; and the timer that removes them.
	records map[string][]dns.RR
	expiry  map[string]*time.Timer
}

func newChallengeGrant(writer ddns.TXTWriter, names []string, warnf func(string, ...any)) *challengeGrant {
	return &challengeGrant{writer: writer, names: names, warnf: warnf, records: make(map[string][]dns.RR), expiry: make(map[string]*time.Timer)}
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

// Apply writes the values of each name changed, all of them: a provider's SetTXT makes the
// records of a name those it is given.
func (g *challengeGrant) Apply(changes map[string][]dns.RR) error {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	for _, name := range slices.Sorted(maps.Keys(changes)) {
		var values []string
		for _, rr := range changes[name] {
			if txt, ok := rr.(*dns.TXT); ok {
				values = append(values, strings.Join(txt.Txt, ""))
			}
		}
		if err := g.writer.SetTXT(strings.TrimSuffix(name, "."), values); err != nil {
			return fmt.Errorf("writing the TXT records of %s: %w", strings.TrimSuffix(name, "."), err)
		}
		g.records[name] = changes[name]
		if t := g.expiry[name]; t != nil {
			t.Stop()
			delete(g.expiry, name)
		}
		if len(values) > 0 {
			g.expiry[name] = time.AfterFunc(challengeExpiry, func() { g.expire(name) })
		}
	}
	return nil
}

// expire removes the records of a name its client left, an hour after they last changed.
func (g *challengeGrant) expire(name string) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	if len(g.records[name]) == 0 {
		return
	}
	if err := g.writer.SetTXT(strings.TrimSuffix(name, "."), nil); err != nil {
		g.warnf("removing the TXT records of %s, which its client left: %s", strings.TrimSuffix(name, "."), err)
		return
	}
	delete(g.records, name)
	delete(g.expiry, name)
}
