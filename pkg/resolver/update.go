package resolver

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// UpdateKey is a TSIG key whose holder may change records by RFC 2136 dynamic updates, within
// its grants, and is answered with authority about them. See docs/resolver.md.
type UpdateKey struct {
	// Absolute, in lower case: nas.
	Name string
	// Base64, as tsig-keygen writes it.
	Secret string
	// The algorithm, as TSIG names it: dns.HmacSHA256, dns.HmacSHA384 or dns.HmacSHA512.
	Algorithm string
	// The networks it may send from. None: Config.UpdateAllow.
	Allow []netip.Prefix
	// What it may change, in order: an update is applied to the first that holds all of it.
	Grants []Grant
}

// Grant is what a key may change: the records of some names of a zone, of some types, and where
// they go when they change. Its methods are called one at a time, by the server.
type Grant interface {
	// Kind is the permission it is of, for the status and the log: challenges.
	Kind() string
	// Scope is the zone, and the names of it that it may change, absolute and in lower case: all
	// of the zone's, for nil. It may ask a provider, and fail.
	Scope() (zone string, names []string, err error)
	// Types are the types of record it may change.
	Types() []uint16
	// Records are the records of name it has now, of its types.
	Records(name string) []dns.RR
	// Apply makes the records of each name changed those given, of its types: none removes them.
	// An error is the update's, which the client is answered SERVFAIL for, and nothing is changed.
	Apply(changes map[string][]dns.RR) error
}

// UpdateAlgorithms are the algorithms a key may have, by the names the configuration gives them:
// those of SHA-2 that RFC 8945 recommends, and none weaker.
var UpdateAlgorithms = map[string]string{
	"hmac-sha256": dns.HmacSHA256,
	"hmac-sha384": dns.HmacSHA384,
	"hmac-sha512": dns.HmacSHA512,
}

// macSizes are the sizes of the signatures of the algorithms, in bytes.
var macSizes = map[string]int{dns.HmacSHA256: 32, dns.HmacSHA384: 48, dns.HmacSHA512: 64}

// holder is a Grant that holds some names of its zone alone, of those Scope gives: a DHCP
// server's names, one label below the zone, and no wildcard.
type holder interface {
	Holds(name string) bool
}

// limited is a Grant whose updates are each a provider's write, which a client in a loop would
// repeat as fast as the provider answers: they are limited, of each key, to updateLimit a minute.
type limited interface {
	Limited() bool
}

// updateLimit is how many updates of a limited grant a key may send a minute, and at once: a
// certificate of 30 names, each added and removed.
const updateLimit = 60

// warnEvery is how often a client's signatures refused are logged, of each key it names: a host
// that sends many is told of once a minute, and the log isn't flooded.
const warnEvery = time.Minute

// The bounds of an update's sections, past which it is refused unread: more than any client sends
// for one name, which is what updates are for.
const (
	maxPrerequisites = 64
	maxUpdates       = 256
)

// tsigFudge is the clock skew a signature is good for, and the one the responses say: RFC 8945's.
const tsigFudge = 300

// The results of updates, as the status and the metrics count them.
const (
	UpdateApplied = "applied"
	UpdateRefused = "refused"
	UpdateFailed  = "failed"
)

// keyState is a key at work, with what it did.
type keyState struct {
	UpdateKey
	secret []byte

	counts map[string]*atomic.Uint64
	mutex  sync.Mutex
	// The updates of limited grants it may send now, and when they were counted last.
	allowance float64
	refilled  time.Time
	last      time.Time
	// What the last update did, or why it was refused.
	lastResult, lastMessage string
	// The scope each grant gave last, by its place among them, for the status: of a limited
	// grant, which asks a provider, the status asks no other.
	read map[int]scope
}

// newKeys checks the keys and reads their secrets: by their names.
func newKeys(path string, keys []UpdateKey) (map[string]*keyState, error) {
	out := make(map[string]*keyState)
	for _, k := range keys {
		name := strings.ToLower(dns.Fqdn(k.Name))
		if !KeyName(name) {
			return nil, fmt.Errorf("%s.updates.keys: %q is not a name a TSIG key can have", path, k.Name)
		}
		if _, ok := out[name]; ok {
			return nil, fmt.Errorf("%s.updates.keys: %s is there twice", path, strings.TrimSuffix(name, "."))
		}
		if !slices.Contains(slices.Collect(maps.Values(UpdateAlgorithms)), k.Algorithm) {
			return nil, fmt.Errorf("%s.updates.keys.%s: the algorithm %s isn't one of hmac-sha256, hmac-sha384 and hmac-sha512", path, k.Name, k.Algorithm)
		}
		secret, err := base64.StdEncoding.DecodeString(k.Secret)
		if err != nil || len(secret) == 0 {
			return nil, fmt.Errorf("%s.updates.keys.%s.secret is not base64, as tsig-keygen writes it", path, k.Name)
		}
		if len(k.Grants) == 0 {
			return nil, fmt.Errorf("%s.updates.keys.%s has no permissions", path, k.Name)
		}
		k.Name = name
		ks := &keyState{UpdateKey: k, secret: secret, counts: make(map[string]*atomic.Uint64), allowance: updateLimit}
		for _, r := range []string{UpdateApplied, UpdateRefused, UpdateFailed} {
			ks.counts[r] = new(atomic.Uint64)
		}
		out[name] = ks
	}
	return out, nil
}

// KeyName tells whether name, absolute, is one a key can have: labels of letters, digits,
// hyphens and underscores, as tsig-keygen and the clients take.
func KeyName(name string) bool {
	if name == "." || len(name) > 254 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" || len(label) > 63 || strings.Trim(label, "abcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
			return false
		}
	}
	return true
}

// keyring is the TSIG provider of the keys: it signs and checks with a key's secret, by its
// algorithm alone.
type keyring map[string]*keyState

func (k keyring) mac(msg []byte, t *dns.TSIG) ([]byte, error) {
	key := k[strings.ToLower(t.Hdr.Name)]
	if key == nil {
		return nil, dns.ErrSecret
	}
	if dns.CanonicalName(t.Algorithm) != key.Algorithm {
		return nil, dns.ErrKeyAlg
	}
	var h func() hash.Hash
	switch key.Algorithm {
	case dns.HmacSHA256:
		h = sha256.New
	case dns.HmacSHA384:
		h = sha512.New384
	default:
		h = sha512.New
	}
	m := hmac.New(h, key.secret)
	m.Write(msg)
	return m.Sum(nil), nil
}

func (k keyring) Generate(msg []byte, t *dns.TSIG) ([]byte, error) { return k.mac(msg, t) }

func (k keyring) Verify(msg []byte, t *dns.TSIG) error {
	want, err := k.mac(msg, t)
	if err != nil {
		return err
	}
	got, err := hex.DecodeString(t.MAC)
	if err != nil || !hmac.Equal(want, got) {
		return dns.ErrSig
	}
	return nil
}

// acceptUpdates is the servers' accept function, with keys: dynamic updates too, of one zone and
// bounded sections, and every other message as miekg/dns takes it.
func acceptUpdates(dh dns.Header) dns.MsgAcceptAction {
	const response = 1 << 15
	if opcode := int(dh.Bits>>11) & 0xF; opcode == dns.OpcodeUpdate && dh.Bits&response == 0 {
		if dh.Qdcount != 1 || dh.Ancount > maxPrerequisites || dh.Nscount > maxUpdates || dh.Arcount > 2 {
			return dns.MsgReject
		}
		return dns.MsgAccept
	}
	return dns.DefaultMsgAcceptFunc(dh)
}

// scope is a grant's scope, read for a message.
type scope struct {
	grant Grant
	zone  string
	// nil: all of the zone's.
	names []string
	types []uint16
}

// covers tells whether the grant may change name's records of rrtype; of TypeANY, any of its.
func (sc scope) covers(name string, rrtype uint16) bool {
	if !InZone(name, sc.zone) || sc.names != nil && !slices.Contains(sc.names, name) {
		return false
	}
	if h, ok := sc.grant.(holder); ok && !h.Holds(name) {
		return false
	}
	return rrtype == dns.TypeANY || slices.Contains(sc.types, rrtype)
}

// within tells whether name is one the grant may change, or a name between one and the zone:
// whose SOA it answers with authority, to a query signed with its key, as the clients find the
// zone.
func (sc scope) within(name string) bool {
	if !InZone(name, sc.zone) {
		return false
	}
	return sc.names == nil || slices.ContainsFunc(sc.names, func(n string) bool { return InZone(n, name) })
}

// scopes are the scopes of the key's grants that can be read now, and the error of one that
// can't.
func (key *keyState) scopes() ([]scope, error) {
	var out []scope
	var errs []error
	for i, g := range key.Grants {
		sc, err := scopeOf(g)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", g.Kind(), err))
			continue
		}
		key.mutex.Lock()
		if key.read == nil {
			key.read = make(map[int]scope)
		}
		key.read[i] = sc
		key.mutex.Unlock()
		out = append(out, sc)
	}
	return out, errors.Join(errs...)
}

// scopeOf is the scope a grant gives now, its names in lower case: nil names for all of its zone.
func scopeOf(g Grant) (scope, error) {
	zone, names, err := g.Scope()
	if err != nil {
		return scope{}, err
	}
	sc := scope{grant: g, zone: lowerName(zone), types: g.Types()}
	if names != nil {
		sc.names = []string{}
		for _, n := range names {
			sc.names = append(sc.names, lowerName(n))
		}
	}
	return sc, nil
}

// take takes one update of the key's allowance, at now: false when none is left. The allowance
// fills again, updateLimit a minute, up to updateLimit.
func (key *keyState) take(now time.Time) bool {
	key.mutex.Lock()
	defer key.mutex.Unlock()
	if !key.refilled.IsZero() {
		key.allowance = min(updateLimit, key.allowance+now.Sub(key.refilled).Minutes()*updateLimit)
	}
	key.refilled = now
	if key.allowance < 1 {
		return false
	}
	key.allowance--
	return true
}

// lowerName is name absolute, in lower case.
func lowerName(name string) string { return strings.ToLower(dns.Fqdn(name)) }

// serveSigned answers a message signed with TSIG: with the keys', an update or a query, signed
// with its key; and of a key it doesn't know, or a signature that is wrong, NOTAUTH, unsigned,
// as RFC 8945 has it.
func (s *Server) serveSigned(w dns.ResponseWriter, req *dns.Msg, t *dns.TSIG, remote net.Addr) {
	key := s.keys[strings.ToLower(t.Hdr.Name)]
	var tsigError uint16
	switch err := w.TsigStatus(); {
	case key == nil, dns.CanonicalName(t.Algorithm) != key.Algorithm:
		tsigError = dns.RcodeBadKey
	case errors.Is(err, dns.ErrTime):
		tsigError = dns.RcodeBadTime
	case err != nil:
		tsigError = dns.RcodeBadSig
	}
	if tsigError != 0 {
		// Of a client no allow has, as a host of the internet that tries keys: refused, unsaid.
		if !s.anyAllowed(remote) {
			s.queries[Refused].Add(1)
			_ = w.WriteMsg(reply(req, dns.RcodeRefused))
			return
		}
		if s.shouldWarn(hostOf(remote) + " " + strings.ToLower(t.Hdr.Name)) {
			s.warnf("resolver %s: a message from %s signed with the key %s refused: %s", s.config.Name, hostOf(remote),
				strings.TrimSuffix(t.Hdr.Name, "."), map[uint16]string{dns.RcodeBadKey: "no such key, or of another algorithm",
					dns.RcodeBadTime: "its time is more than 5 minutes off: check the clocks", dns.RcodeBadSig: "the signature is wrong: check the secret"}[tsigError])
		}
		resp := new(dns.Msg)
		resp.SetRcode(req, dns.RcodeNotAuth)
		if tsigError == dns.RcodeBadTime {
			// Signed, with the server's time, as RFC 8945 has it: the key is right, and the client
			// tells the clocks apart from a secret refused.
			now := s.now().Unix()
			resp.SetTsig(t.Hdr.Name, t.Algorithm, tsigFudge, now)
			sig := resp.IsTsig()
			sig.Error, sig.OtherLen, sig.OtherData = dns.RcodeBadTime, 6, fmt.Sprintf("%012x", now)
			_ = w.WriteMsg(resp)
			return
		}
		// Unsigned: the key, or its signature, is not one to sign with.
		resp.Extra = append(resp.Extra, &dns.TSIG{Hdr: dns.RR_Header{Name: t.Hdr.Name, Rrtype: dns.TypeTSIG, Class: dns.ClassANY},
			Algorithm: t.Algorithm, TimeSigned: uint64(s.now().Unix()), Fudge: tsigFudge, OrigId: req.Id, Error: tsigError})
		if data, err := resp.Pack(); err == nil {
			_, _ = w.Write(data)
		}
		return
	}

	var resp *dns.Msg
	switch {
	case !s.keyAllowed(key, remote):
		resp = reply(req, dns.RcodeRefused)
		if req.Opcode == dns.OpcodeUpdate {
			s.updated(key, UpdateRefused, fmt.Sprintf("from %s, which its allow hasn't", hostOf(remote)))
		} else {
			s.queries[Refused].Add(1)
		}
	case req.Opcode == dns.OpcodeUpdate:
		resp = s.update(req, key)
	case req.Opcode == dns.OpcodeQuery:
		var kind string
		resp, kind = s.answerSigned(req, key, remote)
		if kind != "" {
			s.queries[kind].Add(1)
		}
	default:
		resp = reply(req, dns.RcodeNotImplemented)
	}
	if _, overUDP := w.RemoteAddr().(*net.UDPAddr); overUDP {
		size := dns.MinMsgSize
		if opt := req.IsEdns0(); opt != nil {
			size = max(int(opt.UDPSize()), dns.MinMsgSize)
		}
		fitSigned(resp, size-tsigRoom(t.Hdr.Name, key.Algorithm))
	}
	resp.SetTsig(t.Hdr.Name, t.Algorithm, tsigFudge, s.now().Unix())
	_ = w.WriteMsg(resp)
}

// fitSigned truncates resp to size, which leaves its signature room: as Truncate does, which
// never goes below 512 bytes, so can't leave that room in a response of 512.
func fitSigned(resp *dns.Msg, size int) {
	resp.Compress = true
	for resp.Len() > size {
		switch {
		case len(resp.Extra) > 0 && resp.IsEdns0() == nil, len(resp.Extra) > 1:
			// The additional records, but OPT, which says the size.
			for i := len(resp.Extra) - 1; i >= 0; i-- {
				if resp.Extra[i].Header().Rrtype != dns.TypeOPT {
					resp.Extra = slices.Delete(resp.Extra, i, i+1)
					break
				}
			}
		case len(resp.Ns) > 0:
			resp.Ns = resp.Ns[:len(resp.Ns)-1]
		case len(resp.Answer) > 0:
			resp.Answer = resp.Answer[:len(resp.Answer)-1]
		default:
			return
		}
		resp.Truncated = true
	}
}

// tsigRoom is the room the signature of a response takes, signed with the key of that name and
// algorithm.
func tsigRoom(name, algorithm string) int {
	m := new(dns.Msg)
	base := m.Len()
	m.SetTsig(name, algorithm, tsigFudge, 0)
	sig := m.IsTsig()
	sig.MACSize = uint16(macSizes[algorithm])
	sig.MAC = strings.Repeat("00", macSizes[algorithm])
	return m.Len() - base
}

// anyAllowed tells whether remote is in any allow: the resolver's, or a key's.
func (s *Server) anyAllowed(remote net.Addr) bool {
	if s.allowed(remote) {
		return true
	}
	for _, k := range s.keys {
		if s.keyAllowed(k, remote) {
			return true
		}
	}
	return false
}

// shouldWarn tells whether what, a client and a key, wasn't warned of within warnEvery, and notes
// it now.
func (s *Server) shouldWarn(what string) bool {
	s.warnedMutex.Lock()
	defer s.warnedMutex.Unlock()
	now := s.now()
	if last, ok := s.warned[what]; ok && now.Sub(last) < warnEvery {
		return false
	}
	// Bounded, whatever the clients send.
	if s.warned == nil || len(s.warned) > 4096 {
		s.warned = make(map[string]time.Time)
	}
	s.warned[what] = now
	return true
}

// keyAllowed tells whether a key may be used from remote: its allow's, the updates', or the
// resolver's.
func (s *Server) keyAllowed(key *keyState, remote net.Addr) bool {
	ip, ok := addrOf(remote)
	if !ok {
		return false
	}
	allow := key.Allow
	if allow == nil {
		allow = s.config.UpdateAllow
	}
	if allow == nil {
		allow = s.allowOf(remote)
	}
	return slices.ContainsFunc(allow, func(p netip.Prefix) bool { return p.Contains(ip) })
}

// addrOf is the address of a client.
func addrOf(addr net.Addr) (netip.Addr, bool) {
	var ip netip.Addr
	switch a := addr.(type) {
	case client:
		return addrOf(a.Addr)
	case *net.UDPAddr:
		ip, _ = netip.AddrFromSlice(a.IP)
	case *net.TCPAddr:
		ip, _ = netip.AddrFromSlice(a.IP)
	default:
		return ip, false
	}
	return ip.Unmap(), ip.IsValid()
}

// hostOf is a client's address, for the log.
func hostOf(addr net.Addr) string {
	if ip, ok := addrOf(addr); ok {
		return ip.String()
	}
	return addr.String()
}

// answerSigned answers a query signed with key: with authority, from the grant, of a name of a
// grant's scope; as any query, from the clients the resolver answers, of any other.
func (s *Server) answerSigned(req *dns.Msg, key *keyState, remote net.Addr) (*dns.Msg, string) {
	if len(req.Question) != 1 {
		return reply(req, dns.RcodeFormatError), ""
	}
	q := req.Question[0]
	name := lowerName(q.Name)
	if q.Qclass == dns.ClassINET {
		scopes, _ := key.scopes()
		for _, sc := range scopes {
			// The names it may change, of any type; the names between them and the zone, of
			// their SOA alone: the rest of those names is the world's, as any client is told.
			if sc.covers(name, dns.TypeANY) || q.Qtype == dns.TypeSOA && sc.within(name) {
				return s.authoritative(req, sc, name, q.Qtype), Local
			}
		}
	}
	plain := req.Copy()
	plain.Extra = slices.DeleteFunc(plain.Extra, func(rr dns.RR) bool { return rr.Header().Rrtype == dns.TypeTSIG })
	return s.answer(plain, remote)
}

// authoritative is the answer of the grant about name: its records of qtype, the zone's SOA at
// the zone, and no data, with the SOA, without them.
func (s *Server) authoritative(req *dns.Msg, sc scope, name string, qtype uint16) *dns.Msg {
	s.updateMutex.Lock()
	records := sc.grant.Records(name)
	s.updateMutex.Unlock()
	resp := reply(req, dns.RcodeSuccess)
	resp.Authoritative = true
	if name == sc.zone && (qtype == dns.TypeSOA || qtype == dns.TypeANY) {
		resp.Answer = append(resp.Answer, soa(sc.zone))
	}
	for _, rr := range records {
		if qtype == dns.TypeANY || rr.Header().Rrtype == qtype {
			resp.Answer = append(resp.Answer, dns.Copy(rr))
		}
	}
	if len(resp.Answer) == 0 {
		resp.Ns = append(resp.Ns, soa(sc.zone))
	}
	return resp
}

// update applies a dynamic update of key, by RFC 2136: its prerequisites checked and its changes
// made, all or none, by the first grant that holds all of it.
func (s *Server) update(req *dns.Msg, key *keyState) *dns.Msg {
	refuse := func(rcode int, why string) *dns.Msg {
		s.updated(key, UpdateRefused, why)
		return reply(req, rcode)
	}
	if len(req.Question) != 1 || req.Question[0].Qtype != dns.TypeSOA || req.Question[0].Qclass != dns.ClassINET {
		return refuse(dns.RcodeFormatError, "its zone section isn't one zone of class IN")
	}
	zone := lowerName(req.Question[0].Name)
	scopes, scopesErr := key.scopes()
	var candidates []scope
	for _, sc := range scopes {
		if InZone(zone, sc.zone) {
			candidates = append(candidates, sc)
		}
	}
	if len(candidates) == 0 {
		if scopesErr != nil {
			s.updated(key, UpdateFailed, scopesErr.Error())
			return reply(req, dns.RcodeServerFailure)
		}
		// REFUSED, not NOTAUTH, which clients take for a signature refused: RFC 8945's.
		return refuse(dns.RcodeRefused, fmt.Sprintf("the zone %s is of none of its permissions", strings.TrimSuffix(zone, ".")))
	}

	for _, rr := range append(slices.Clone(req.Answer), req.Ns...) {
		if !InZone(lowerName(rr.Header().Name), zone) {
			return refuse(dns.RcodeNotZone, fmt.Sprintf("%s is not of the zone %s", strings.TrimSuffix(rr.Header().Name, "."), strings.TrimSuffix(zone, ".")))
		}
	}
	for _, rr := range req.Ns {
		if why := checkUpdate(rr); why != "" {
			return refuse(dns.RcodeFormatError, why)
		}
	}

	var sc scope
	found := false
	var outside string
	for _, c := range candidates {
		outside = c.outside(req.Answer, req.Ns)
		if outside == "" {
			sc, found = c, true
			break
		}
	}
	if !found {
		return refuse(dns.RcodeRefused, outside+" is outside its permissions")
	}

	if l, ok := sc.grant.(limited); ok && l.Limited() && !key.take(s.now()) {
		// Counted, and logged once a minute: the client that sends them would flood the log too.
		why := fmt.Sprintf("more than %d updates of %s a minute: a client that tries again and again?", updateLimit, sc.grant.Kind())
		s.note(key, UpdateRefused, why)
		if s.shouldWarn("limit " + key.Name) {
			s.warnf("resolver %s: key %s: update refused: %s", s.config.Name, strings.TrimSuffix(key.Name, "."), why)
		}
		return reply(req, dns.RcodeRefused)
	}

	s.updateMutex.Lock()
	defer s.updateMutex.Unlock()
	if rcode, why := checkPrerequisites(sc, req.Answer); rcode != dns.RcodeSuccess {
		// A prerequisite that doesn't hold is an answer, as RFC 4703 asks them, not an error.
		s.updated(key, UpdateRefused, why)
		return reply(req, rcode)
	}

	before := make(map[string][]dns.RR)
	work := make(map[string][]dns.RR)
	records := func(name string) []dns.RR {
		if _, ok := work[name]; !ok {
			before[name] = sc.grant.Records(name)
			work[name] = slices.Clone(before[name])
		}
		return work[name]
	}
	for _, rr := range req.Ns {
		h := rr.Header()
		name := lowerName(h.Name)
		have := records(name)
		switch {
		case h.Class == dns.ClassINET:
			if !slices.ContainsFunc(have, func(r dns.RR) bool { return dns.IsDuplicate(r, rr) }) {
				add := dns.Copy(rr)
				add.Header().Name = name
				work[name] = append(have, add)
			}
		case h.Class == dns.ClassANY && h.Rrtype == dns.TypeANY:
			work[name] = nil
		case h.Class == dns.ClassANY:
			work[name] = slices.DeleteFunc(have, func(r dns.RR) bool { return r.Header().Rrtype == h.Rrtype })
		default: // NONE: one record.
			del := dns.Copy(rr)
			del.Header().Class = dns.ClassINET
			work[name] = slices.DeleteFunc(have, func(r dns.RR) bool { return dns.IsDuplicate(r, del) })
		}
	}
	changes := make(map[string][]dns.RR)
	for name, rrs := range work {
		if !sameRecords(rrs, before[name]) {
			changes[name] = rrs
		}
	}
	if len(changes) == 0 {
		s.updated(key, UpdateApplied, "nothing to change")
		return reply(req, dns.RcodeSuccess)
	}
	if err := sc.grant.Apply(changes); err != nil {
		s.updated(key, UpdateFailed, fmt.Sprintf("%s: %s", sc.grant.Kind(), err))
		return reply(req, dns.RcodeServerFailure)
	}
	var names []string
	for _, n := range slices.Sorted(maps.Keys(changes)) {
		names = append(names, strings.TrimSuffix(n, "."))
	}
	s.updated(key, UpdateApplied, fmt.Sprintf("%s: %s", sc.grant.Kind(), strings.Join(names, ", ")))
	return reply(req, dns.RcodeSuccess)
}

// outside is the first record of the prerequisites or the changes that the scope doesn't hold,
// as text; none, for all held.
func (sc scope) outside(prerequisites, changes []dns.RR) string {
	for _, rr := range append(slices.Clone(prerequisites), changes...) {
		h := rr.Header()
		if !sc.covers(lowerName(h.Name), h.Rrtype) {
			return fmt.Sprintf("%s %s", strings.TrimSuffix(h.Name, "."), dns.TypeToString[h.Rrtype])
		}
	}
	return ""
}

// checkUpdate tells what is wrong with a record of the update section, by RFC 2136, 3.4.1.2:
// none, for nothing.
func checkUpdate(rr dns.RR) string {
	h := rr.Header()
	empty := h.Rdlength == 0
	what := fmt.Sprintf("the change %s %s %s", strings.TrimSuffix(h.Name, "."), dns.ClassToString[h.Class], dns.TypeToString[h.Rrtype])
	meta := h.Rrtype == dns.TypeANY || h.Rrtype == dns.TypeAXFR || h.Rrtype == dns.TypeIXFR || h.Rrtype == dns.TypeMAILA || h.Rrtype == dns.TypeMAILB || h.Rrtype == dns.TypeOPT || h.Rrtype == dns.TypeTSIG
	switch h.Class {
	case dns.ClassINET:
		if meta || empty {
			return what + " adds no record"
		}
	case dns.ClassANY:
		if h.Ttl != 0 || !empty || meta && h.Rrtype != dns.TypeANY {
			return what + " is no deletion of a name or of a set of records"
		}
	case dns.ClassNONE:
		if h.Ttl != 0 || empty || meta {
			return what + " is no deletion of a record"
		}
	default:
		return what + " is of no class an update has"
	}
	return ""
}

// checkPrerequisites checks the prerequisites of an update against the grant's records, by RFC
// 2136, 3.2: success, or the rcode of the first that fails, and why.
func checkPrerequisites(sc scope, prerequisites []dns.RR) (int, string) {
	type set struct {
		name   string
		rrtype uint16
	}
	sets := make(map[set][]dns.RR)
	var order []set
	for _, rr := range prerequisites {
		h := rr.Header()
		name := lowerName(h.Name)
		empty := h.Rdlength == 0
		have := sc.grant.Records(name)
		hasType := slices.ContainsFunc(have, func(r dns.RR) bool { return r.Header().Rrtype == h.Rrtype })
		shown := strings.TrimSuffix(name, ".")
		if h.Ttl != 0 {
			return dns.RcodeFormatError, "a prerequisite has a TTL"
		}
		switch {
		case h.Class == dns.ClassANY && !empty, h.Class == dns.ClassNONE && !empty:
			return dns.RcodeFormatError, "a prerequisite of a name or a set has data"
		case h.Class == dns.ClassANY && h.Rrtype == dns.TypeANY:
			if len(have) == 0 {
				return dns.RcodeNameError, fmt.Sprintf("the prerequisite that %s is in use: it isn't", shown)
			}
		case h.Class == dns.ClassANY:
			if !hasType {
				return dns.RcodeNXRrset, fmt.Sprintf("the prerequisite that %s has %s records: it hasn't", shown, dns.TypeToString[h.Rrtype])
			}
		case h.Class == dns.ClassNONE && h.Rrtype == dns.TypeANY:
			if len(have) > 0 {
				return dns.RcodeYXDomain, fmt.Sprintf("the prerequisite that %s is not in use: it is", shown)
			}
		case h.Class == dns.ClassNONE:
			if hasType {
				return dns.RcodeYXRrset, fmt.Sprintf("the prerequisite that %s has no %s records: it has", shown, dns.TypeToString[h.Rrtype])
			}
		case h.Class == dns.ClassINET && h.Rrtype != dns.TypeANY && !empty:
			k := set{name, h.Rrtype}
			if _, ok := sets[k]; !ok {
				order = append(order, k)
			}
			r := dns.Copy(rr)
			r.Header().Name = name
			sets[k] = append(sets[k], r)
		default:
			return dns.RcodeFormatError, "a prerequisite is of no class a prerequisite has"
		}
	}
	for _, k := range order {
		var have []dns.RR
		for _, r := range sc.grant.Records(k.name) {
			if r.Header().Rrtype == k.rrtype {
				have = append(have, r)
			}
		}
		if !sameRecords(have, sets[k]) {
			return dns.RcodeNXRrset, fmt.Sprintf("the prerequisite that %s has exactly those %s records: it has others", strings.TrimSuffix(k.name, "."), dns.TypeToString[k.rrtype])
		}
	}
	return dns.RcodeSuccess, ""
}

// sameRecords tells whether two sets of records have the same records, whatever their TTLs and
// their order.
func sameRecords(a, b []dns.RR) bool {
	if len(a) != len(b) {
		return false
	}
	for _, r := range a {
		if !slices.ContainsFunc(b, func(o dns.RR) bool { return dns.IsDuplicate(r, o) }) {
			return false
		}
	}
	for _, r := range b {
		if !slices.ContainsFunc(a, func(o dns.RR) bool { return dns.IsDuplicate(r, o) }) {
			return false
		}
	}
	return true
}

// note notes what an update of key did: its count, and its last.
func (s *Server) note(key *keyState, result, message string) {
	key.counts[result].Add(1)
	key.mutex.Lock()
	key.last, key.lastResult, key.lastMessage = s.now(), result, message
	key.mutex.Unlock()
}

// updated notes what an update of key did, and logs it.
func (s *Server) updated(key *keyState, result, message string) {
	s.note(key, result, message)
	name := strings.TrimSuffix(key.Name, ".")
	if result == UpdateApplied {
		s.infof("resolver %s: key %s: updated %s", s.config.Name, name, message)
		return
	}
	s.warnf("resolver %s: key %s: update %s: %s", s.config.Name, name, result, message)
}

func (s *Server) infof(format string, args ...any) {
	if s.config.Infof != nil {
		s.config.Infof(format, args...)
	}
}

func (s *Server) warnf(format string, args ...any) {
	if s.config.Warnf != nil {
		s.config.Warnf(format, args...)
	}
}

// KeyStatus is a key's, for the report, /status.json and the metrics.
type KeyStatus struct {
	Name string `json:"name"`
	// The kinds of its permissions, in order.
	Permissions []string `json:"permissions"`
	// What each permission may change, in the same order.
	Grants []GrantStatus `json:"grants"`
	// The updates, by result.
	Updates map[string]uint64 `json:"updates"`
	// The last: when, its result and what it did, or why not.
	Last        *time.Time `json:"last,omitempty"`
	LastResult  string     `json:"last_result,omitempty"`
	LastMessage string     `json:"last_message,omitempty"`
}

// GrantStatus is what a key's permission may change, for the report and /status.json.
type GrantStatus struct {
	Permission string `json:"permission"`
	// Its zone, and the names of it: all of the zone's, for none. No zone while not known: of a
	// permission that asks a provider, until an update of the key asked it.
	Zone  string   `json:"zone,omitempty"`
	Names []string `json:"names,omitempty"`
	// The types of record it may change.
	Types []string `json:"types"`
}

// grantStatus is the status of the key's grant at i: its scope as it reads now, or as it read
// last, of a limited grant, which asks a provider.
func (key *keyState) grantStatus(i int) GrantStatus {
	g := key.Grants[i]
	st := GrantStatus{Permission: g.Kind(), Types: []string{}}
	for _, t := range g.Types() {
		st.Types = append(st.Types, dns.TypeToString[t])
	}
	key.mutex.Lock()
	sc, ok := key.read[i]
	key.mutex.Unlock()
	if l, isLimited := g.(limited); !isLimited || !l.Limited() {
		var err error
		if sc, err = scopeOf(g); err != nil {
			ok = false
		} else {
			ok = true
		}
	}
	if ok {
		st.Zone = strings.TrimSuffix(sc.zone, ".")
		for _, n := range sc.names {
			st.Names = append(st.Names, strings.TrimSuffix(n, "."))
		}
	}
	return st
}

// keysStatus is the status of every key, by name.
func (s *Server) keysStatus() []KeyStatus {
	var out []KeyStatus
	for _, name := range slices.Sorted(maps.Keys(s.keys)) {
		k := s.keys[name]
		st := KeyStatus{Name: strings.TrimSuffix(name, "."), Permissions: []string{}, Grants: []GrantStatus{}, Updates: make(map[string]uint64)}
		for i, g := range k.Grants {
			st.Permissions = append(st.Permissions, g.Kind())
			st.Grants = append(st.Grants, k.grantStatus(i))
		}
		for r, c := range k.counts {
			st.Updates[r] = c.Load()
		}
		k.mutex.Lock()
		if !k.last.IsZero() {
			last := k.last
			st.Last, st.LastResult, st.LastMessage = &last, k.lastResult, k.lastMessage
		}
		k.mutex.Unlock()
		out = append(out, st)
	}
	return out
}
