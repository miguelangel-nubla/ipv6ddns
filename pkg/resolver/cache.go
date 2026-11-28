package resolver

import (
	"container/list"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DefaultCacheSize is how many answers a resolver keeps, of those forwarded, when the
// configuration gives no cache_size.
const DefaultCacheSize = 10000

// The bounds of how long an answer is kept: at most a day, one that a name has data; and an hour,
// one that it hasn't, as RFC 2308 suggests.
const (
	maxCacheTTL         = 24 * time.Hour
	maxNegativeCacheTTL = time.Hour
)

// cacheKey is what tells two queries apart, for the cache: the name, in lower case, the type and
// class, and the RD, DO and CD bits, which go upstream and change what the answer holds: one
// asked without RD is what the server had at hand, as a CNAME without its target's addresses.
type cacheKey struct {
	name          string
	qtype, qclass uint16
	rd, do, cd    bool
}

func keyOf(m *dns.Msg) cacheKey {
	q := m.Question[0]
	k := cacheKey{name: strings.ToLower(q.Name), qtype: q.Qtype, qclass: q.Qclass, rd: m.RecursionDesired, cd: m.CheckingDisabled}
	if opt := m.IsEdns0(); opt != nil {
		k.do = opt.Do()
	}
	return k
}

type cacheEntry struct {
	key cacheKey
	// The answer, without its OPT: the client's EDNS is given when it is answered.
	msg     *dns.Msg
	stored  time.Time
	expires time.Time
}

// cache is the answers forwarded, kept for their TTL, the least recently used given up first
// beyond size. Safe for concurrent use.
type cache struct {
	size int
	now  func() time.Time

	mutex   sync.Mutex
	entries map[cacheKey]*list.Element
	// Of *cacheEntry, the most recently used first.
	order *list.List
}

func newCache(size int, now func() time.Time) *cache {
	return &cache{size: size, now: now, entries: make(map[cacheKey]*list.Element), order: list.New()}
}

// cacheTTL is how long resp can be kept, or 0 when it can't be: an answer with data for the
// shortest TTL of its records, a day at most; one of no data or no name, NOERROR empty or
// NXDOMAIN, for the SOA's minimum or its TTL, the lower, as RFC 2308 has it, an hour at most.
// Never a truncated answer, nor any of another code, nor a negative one without an SOA, which
// tells no TTL.
func cacheTTL(resp *dns.Msg) time.Duration {
	if resp.Truncated || resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		return 0
	}
	shortest := func(rrs ...[]dns.RR) (uint32, bool) {
		var least uint32
		found := false
		for _, section := range rrs {
			for _, rr := range section {
				if rr.Header().Rrtype == dns.TypeOPT {
					continue
				}
				if !found || rr.Header().Ttl < least {
					least, found = rr.Header().Ttl, true
				}
			}
		}
		return least, found
	}
	if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
		least, _ := shortest(resp.Answer, resp.Ns, resp.Extra)
		return min(time.Duration(least)*time.Second, maxCacheTTL)
	}
	for _, rr := range resp.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			least := min(soa.Hdr.Ttl, soa.Minttl)
			// A CNAME before the name without data: its TTL too.
			if l, ok := shortest(resp.Answer); ok {
				least = min(least, l)
			}
			return min(time.Duration(least)*time.Second, maxNegativeCacheTTL)
		}
	}
	return 0
}

// put keeps resp, the answer to query, when it can be kept: as the server gave it, unvalidated,
// and only ever the answer to the question it was asked for.
func (c *cache) put(query, resp *dns.Msg) {
	if c == nil || len(query.Question) != 1 {
		return
	}
	d := cacheTTL(resp)
	if d <= 0 {
		return
	}
	m := resp.Copy()
	extra := m.Extra[:0]
	for _, rr := range m.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			extra = append(extra, rr)
		}
	}
	m.Extra = extra
	// Not the authority's own any more.
	m.Authoritative = false
	if len(m.Answer) == 0 || m.Rcode == dns.RcodeNameError {
		// The SOA of an answer of no data has the time it is kept for, which counts down: a
		// client's cache reads it there.
		for _, rr := range m.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				soa.Hdr.Ttl = uint32(d / time.Second)
			}
		}
	}
	now := c.now()
	e := &cacheEntry{key: keyOf(query), msg: m, stored: now, expires: now.Add(d)}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if old, ok := c.entries[e.key]; ok {
		c.order.Remove(old)
	}
	c.entries[e.key] = c.order.PushFront(e)
	for c.order.Len() > c.size {
		oldest := c.order.Back()
		c.order.Remove(oldest)
		delete(c.entries, oldest.Value.(*cacheEntry).key)
	}
}

// get is the answer to req kept, or nil: with req's id and question, and each TTL less the whole
// seconds it was kept, which leaves 1 at least, as an answer goes when its shortest TTL would be
// 0. The client's EDNS is given it as for any answer.
func (c *cache) get(req *dns.Msg) *dns.Msg {
	if c == nil || len(req.Question) != 1 {
		return nil
	}
	key := keyOf(req)
	now := c.now()
	c.mutex.Lock()
	el, ok := c.entries[key]
	if !ok {
		c.mutex.Unlock()
		return nil
	}
	e := el.Value.(*cacheEntry)
	if !now.Before(e.expires) {
		c.order.Remove(el)
		delete(c.entries, key)
		c.mutex.Unlock()
		return nil
	}
	c.order.MoveToFront(el)
	c.mutex.Unlock()

	elapsed := uint32(now.Sub(e.stored) / time.Second)
	resp := e.msg.Copy()
	resp.Id = req.Id
	resp.Question = []dns.Question{req.Question[0]}
	resp.Opcode, resp.RecursionDesired, resp.CheckingDisabled = req.Opcode, req.RecursionDesired, req.CheckingDisabled
	for _, section := range [][]dns.RR{resp.Answer, resp.Ns, resp.Extra} {
		for _, rr := range section {
			h := rr.Header()
			if h.Ttl > elapsed {
				h.Ttl -= elapsed
			} else {
				h.Ttl = 1
			}
			// The name asked, as the client spells it.
			if strings.EqualFold(h.Name, req.Question[0].Name) {
				h.Name = req.Question[0].Name
			}
		}
	}
	if opt := req.IsEdns0(); opt != nil {
		resp.SetEdns0(ednsSize, opt.Do())
	}
	return resp
}

// len is how many answers are kept: those whose time is over are given up first.
func (c *cache) len() int {
	if c == nil {
		return 0
	}
	now := c.now()
	c.mutex.Lock()
	defer c.mutex.Unlock()
	for el := c.order.Front(); el != nil; {
		next := el.Next()
		if e := el.Value.(*cacheEntry); !now.Before(e.expires) {
			c.order.Remove(el)
			delete(c.entries, e.key)
		}
		el = next
	}
	return c.order.Len()
}
