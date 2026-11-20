package resolver

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/listen"
)

// DefaultPort is the port of the listen entries that give none.
const DefaultPort = "53"

// UpstreamTimeout is how long an upstream server has to answer, over each transport, before the
// next is asked.
const UpstreamTimeout = 2 * time.Second

// ednsSize is the size of UDP message the resolver says it takes, as DNS Flag Day 2020 has it: one
// that crosses any link without fragments.
const ednsSize = 1232

// The kinds of answer, as the metrics count them.
const (
	Local     = "local"
	NoData    = "nodata"
	Forwarded = "forwarded"
	Cached    = "cached"
	Refused   = "refused"
	ServFail  = "servfail"
)

// Kinds are the kinds of answer, in order.
var Kinds = []string{Local, NoData, Forwarded, Cached, Refused, ServFail}

// Server is a resolver at work: New makes it, Start opens its addresses, Shutdown closes them.
type Server struct {
	config  Config
	table   *table
	timeout time.Duration
	errorf  func(string, ...any)

	queries  map[string]*atomic.Uint64
	failures map[string]*atomic.Uint64
	// The upstream servers, in order.
	upstreams []*upstreamServer
	// The upstream servers whose host is a host name, by their text as configured.
	named map[string]*namedUpstream
	// The answers forwarded, kept: nil for none.
	cache *cache
	now   func() time.Time
	// The roots the certificates of encrypted upstream servers are verified against: the
	// system's, nil, but in tests.
	roots *x509.CertPool
	// Done when the shutdown's time is over: the queries to the upstream servers still asked
	// then are given up.
	ctx    context.Context
	cancel context.CancelFunc

	mutex     sync.Mutex
	servers   []*dns.Server
	listening []string
	allow     []netip.Prefix
	serving   bool
	stopping  bool
	err       error
}

// New makes the server of cfg, whose zones have their Addresses. errorf logs a server that stops
// on its own.
func New(cfg Config, errorf func(string, ...any)) (*Server, error) {
	t, err := build(cfg)
	if err != nil {
		return nil, err
	}
	if errorf == nil {
		errorf = func(string, ...any) {}
	}
	s := &Server{config: cfg, table: t, timeout: UpstreamTimeout, errorf: errorf, now: time.Now,
		queries: make(map[string]*atomic.Uint64), failures: make(map[string]*atomic.Uint64)}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	for _, k := range Kinds {
		s.queries[k] = new(atomic.Uint64)
	}
	if cfg.CacheSize > 0 {
		s.cache = newCache(cfg.CacheSize, func() time.Time { return s.now() })
	}
	s.named = make(map[string]*namedUpstream)
	for _, u := range cfg.Upstreams {
		s.failures[u] = new(atomic.Uint64)
		srv, err := parseServer(u)
		if err != nil {
			return nil, fmt.Errorf("%s.upstream: %q: %w", cfg.Path, u, err)
		}
		if srv.isName() {
			if len(cfg.Bootstrap) == 0 {
				return nil, fmt.Errorf("%s.upstream: %q is a host name, and there is no bootstrap to find it", cfg.Path, u)
			}
			srv.named = &namedUpstream{host: dns.Fqdn(srv.host), port: srv.port}
			s.named[u] = srv.named
		}
		s.upstreams = append(s.upstreams, srv)
	}
	return s, nil
}

// The bounds of how long the addresses of an upstream server given by host name are kept: what
// the bootstrap servers' answer says, but a minute at least, an hour at most. And when they don't
// answer, how long until they are asked again, the addresses there were kept meanwhile.
const (
	minUpstreamTTL     = time.Minute
	maxUpstreamTTL     = time.Hour
	bootstrapRetryWait = 10 * time.Second
)

// namedUpstream is an upstream server given by host name, and the addresses the bootstrap servers
// found for it.
type namedUpstream struct {
	host, port string

	mutex sync.Mutex
	// host:port of each address, as last found.
	addresses []string
	// When they are asked of the bootstrap servers again.
	refresh time.Time
}

// targets are the addresses to send a query for upstream to: itself, of one that is an address;
// those the bootstrap servers found, of one given by host name, asked again when their time is
// over. None, when they never answered.
func (s *Server) targets(srv *upstreamServer) []string {
	n := srv.named
	if n == nil {
		return []string{net.JoinHostPort(srv.host, srv.port)}
	}
	n.mutex.Lock()
	defer n.mutex.Unlock()
	if time.Now().Before(n.refresh) {
		return n.addresses
	}
	addresses, ttl := s.lookUp(n.host)
	if len(addresses) == 0 {
		// The addresses there were stay, until the bootstrap servers answer again.
		n.refresh = time.Now().Add(bootstrapRetryWait)
		return n.addresses
	}
	n.addresses = nil
	for _, a := range addresses {
		n.addresses = append(n.addresses, net.JoinHostPort(a, n.port))
	}
	n.refresh = time.Now().Add(min(max(ttl, minUpstreamTTL), maxUpstreamTTL))
	return n.addresses
}

// lookUp asks the bootstrap servers, in order, the IPv4 and IPv6 addresses of host, and returns
// those of the first that answers each, and the shortest of their TTLs.
func (s *Server) lookUp(host string) ([]string, time.Duration) {
	var addresses []string
	ttl := maxUpstreamTTL
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		for _, bootstrap := range s.config.Bootstrap {
			m := new(dns.Msg)
			m.SetQuestion(host, qtype)
			m.SetEdns0(ednsSize, false)
			resp, err := s.ask(s.ctx, m, "udp", bootstrap)
			if err == nil && resp.Truncated {
				resp, err = s.ask(s.ctx, m, "tcp", bootstrap)
			}
			if err != nil || resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
				continue
			}
			for _, rr := range resp.Answer {
				var ip net.IP
				switch rr := rr.(type) {
				case *dns.A:
					ip = rr.A
				case *dns.AAAA:
					ip = rr.AAAA
				default:
					continue
				}
				addresses = append(addresses, ip.String())
				ttl = min(ttl, time.Duration(rr.Header().Ttl)*time.Second)
			}
			break
		}
	}
	return addresses, ttl
}

// Start listens on every address of the configuration, over UDP and TCP, and answers there until
// Shutdown. An address it can't listen on stops it, closing the others: no resolver serves half
// of its addresses.
func (s *Server) Start() error {
	addresses, err := listen.Addresses(s.config.Listen)
	if err != nil {
		return fmt.Errorf("%s.listen: %w", s.config.Path, err)
	}
	for _, srv := range s.upstreams {
		srv.open(s)
	}
	var (
		conns     []net.PacketConn
		listeners []net.Listener
	)
	closeAll := func() {
		for _, c := range conns {
			c.Close()
		}
		for _, l := range listeners {
			l.Close()
		}
	}
	var listening []string
	for _, a := range addresses {
		udp, tcp := networks(a)
		c, err := net.ListenPacket(udp, a)
		if err != nil {
			closeAll()
			return fmt.Errorf("%s.listen: %w", s.config.Path, err)
		}
		conns = append(conns, c)
		// The port the UDP socket has, for the TCP one: the same, when the entry's is 0.
		a = c.LocalAddr().String()
		l, err := net.Listen(tcp, a)
		if err != nil {
			closeAll()
			return fmt.Errorf("%s.listen: %w", s.config.Path, err)
		}
		listeners = append(listeners, l)
		listening = append(listening, a)
	}
	allow := s.config.Allow
	if len(allow) == 0 {
		allow, err = listenedNetworks(conns)
		if err != nil {
			closeAll()
			return fmt.Errorf("%s.allow: the networks listened on: %w", s.config.Path, err)
		}
	}

	var started sync.WaitGroup
	var servers []*dns.Server
	for i := range conns {
		servers = append(servers,
			&dns.Server{PacketConn: conns[i], Handler: s, NotifyStartedFunc: started.Done},
			&dns.Server{Listener: listeners[i], Handler: s, NotifyStartedFunc: started.Done,
				ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second})
	}
	s.mutex.Lock()
	s.servers, s.listening, s.allow, s.serving = servers, listening, allow, true
	s.mutex.Unlock()
	started.Add(len(servers))
	for _, srv := range servers {
		go func() {
			err := srv.ActivateAndServe()
			s.mutex.Lock()
			defer s.mutex.Unlock()
			if s.stopping {
				return
			}
			if err == nil {
				err = errors.New("stopped")
			}
			s.serving, s.err = false, err
			s.errorf("resolver %s: %s", s.config.Name, err)
		}()
	}
	started.Wait()
	return nil
}

// Shutdown stops answering, and closes the addresses: it waits for the answers being made, until
// ctx is done, the program's time to stop, when the queries still asked upstream are given up.
// The connections kept to the upstream servers are closed.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mutex.Lock()
	s.stopping, s.serving = true, false
	servers := s.servers
	s.mutex.Unlock()
	stop := context.AfterFunc(ctx, s.cancel)
	defer stop()
	var wg sync.WaitGroup
	errs := make([]error, len(servers))
	for i, srv := range servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = srv.ShutdownContext(ctx)
		}()
	}
	wg.Wait()
	s.cancel()
	for _, srv := range s.upstreams {
		srv.close()
	}
	return errors.Join(errs...)
}

// Addresses are the addresses the server listens on, host:port, once started.
func (s *Server) Addresses() []string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return slices.Clone(s.listening)
}

// networks are the networks to listen on address over, UDP and TCP: of its family for an IP
// address, as listen does, so that 0.0.0.0 is IPv4 alone; both for none.
func networks(address string) (udp, tcp string) {
	host, _, _ := net.SplitHostPort(address)
	ip, err := netip.ParseAddr(host)
	switch {
	case host == "" || err != nil:
		return "udp", "tcp"
	case ip.Unmap().Is4():
		return "udp4", "tcp4"
	default:
		return "udp6", "tcp6"
	}
}

// listenedNetworks are the networks of the machine's addresses that conns listen on: each one's,
// or every network of its family, for an address that is all of them.
func listenedNetworks(conns []net.PacketConn) ([]netip.Prefix, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var machine []netip.Prefix
	for _, a := range addrs {
		if ipNet, ok := a.(*net.IPNet); ok {
			ip, ok := netip.AddrFromSlice(ipNet.IP)
			ones, _ := ipNet.Mask.Size()
			if ok {
				machine = append(machine, netip.PrefixFrom(ip.Unmap(), ones).Masked())
			}
		}
	}
	var result []netip.Prefix
	add := func(p netip.Prefix) {
		if !slices.Contains(result, p) {
			result = append(result, p)
		}
	}
	for _, c := range conns {
		udp, ok := c.LocalAddr().(*net.UDPAddr)
		if !ok {
			continue
		}
		ip, _ := netip.AddrFromSlice(udp.IP)
		ip = ip.Unmap()
		network, _ := networks(c.LocalAddr().String())
		for _, p := range machine {
			switch {
			case !ip.IsUnspecified():
				if p.Contains(ip) {
					add(p)
				}
			case network == "udp", network == "udp4" && p.Addr().Is4(), network == "udp6" && p.Addr().Is6():
				add(p)
			}
		}
		// The address of an entry, the machine's with no network that holds it, as a /32 on
		// some systems: itself.
		if !ip.IsUnspecified() && !slices.ContainsFunc(result, func(p netip.Prefix) bool { return p.Contains(ip) }) {
			add(netip.PrefixFrom(ip, ip.BitLen()))
		}
	}
	if len(result) == 0 {
		return nil, errors.New("none found")
	}
	return result, nil
}

// allowed tells whether a client at addr is answered.
func (s *Server) allowed(addr net.Addr) bool {
	var ip netip.Addr
	switch a := addr.(type) {
	case *net.UDPAddr:
		ip, _ = netip.AddrFromSlice(a.IP)
	case *net.TCPAddr:
		ip, _ = netip.AddrFromSlice(a.IP)
	default:
		return false
	}
	ip = ip.Unmap()
	s.mutex.Lock()
	allow := s.allow
	s.mutex.Unlock()
	return slices.ContainsFunc(allow, func(p netip.Prefix) bool { return p.Contains(ip) })
}

// ServeDNS answers a query.
func (s *Server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	_, overUDP := w.RemoteAddr().(*net.UDPAddr)
	resp, kind := s.answer(req, w.RemoteAddr())
	if kind != "" {
		s.queries[kind].Add(1)
	}
	if resp == nil {
		return
	}
	size := dns.MaxMsgSize
	if overUDP {
		size = dns.MinMsgSize
		if opt := req.IsEdns0(); opt != nil {
			size = max(int(opt.UDPSize()), dns.MinMsgSize)
		}
	}
	resp.Truncate(size)
	w.WriteMsg(resp)
}

// answer makes the response to req, from a client at remote, and tells its kind.
func (s *Server) answer(req *dns.Msg, remote net.Addr) (*dns.Msg, string) {
	if req.Response {
		return nil, ""
	}
	if !s.allowed(remote) {
		return reply(req, dns.RcodeRefused), Refused
	}
	if req.Opcode != dns.OpcodeQuery {
		return reply(req, dns.RcodeNotImplemented), ""
	}
	if len(req.Question) != 1 {
		return reply(req, dns.RcodeFormatError), ""
	}
	q := req.Question[0]
	var first lookup
	if q.Qclass == dns.ClassINET {
		first = s.table.lookup(q.Name, q.Qtype)
		// The reverse of an address a name of the resolver's has, but of a PTR record written.
		if first.kind != found && q.Qtype == dns.TypePTR {
			if ptrs := s.table.reverse(q.Name); len(ptrs) > 0 {
				resp := reply(req, dns.RcodeSuccess)
				resp.Authoritative = true
				resp.Answer = ptrs
				return resp, Local
			}
		}
	}
	if first.kind == notLocal {
		resp, kind, err := s.forward(req)
		if err != nil {
			return reply(req, dns.RcodeServerFailure), ServFail
		}
		return resp, kind
	}

	resp := reply(req, dns.RcodeSuccess)
	resp.Authoritative = first.names.zone != nil
	kind := Local
	l := first
	for step := 0; ; step++ {
		if l.kind == noData {
			if l.names.zone != nil {
				resp.Ns = append(resp.Ns, soa(l.names.apex))
			}
			if step == 0 {
				kind = NoData
			}
			break
		}
		resp.Answer = append(resp.Answer, l.records...)
		cname, ok := l.records[0].(*dns.CNAME)
		if !ok || q.Qtype == dns.TypeCNAME || q.Qtype == dns.TypeANY || step == MaxChain {
			break
		}
		l = s.table.lookup(cname.Target, q.Qtype)
		if l.kind != notLocal {
			continue
		}
		// Past the local names: the upstream servers', appended, as a stub resolver follows no
		// CNAME.
		up := new(dns.Msg)
		up.SetQuestion(cname.Target, q.Qtype)
		up.CheckingDisabled = req.CheckingDisabled
		if opt := req.IsEdns0(); opt != nil {
			up.SetEdns0(ednsSize, opt.Do())
		}
		upResp, _, err := s.forward(up)
		if err != nil {
			return reply(req, dns.RcodeServerFailure), ServFail
		}
		resp.Answer = append(resp.Answer, upResp.Answer...)
		resp.Rcode = upResp.Rcode
		if len(upResp.Answer) == 0 {
			resp.Ns = append(resp.Ns, upResp.Ns...)
		}
		break
	}
	return resp, kind
}

// reply is the response to req with rcode, and nothing in it yet: with EDNS when req has it, and
// its DO bit.
func reply(req *dns.Msg, rcode int) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetRcode(req, rcode)
	resp.RecursionAvailable = true
	if opt := req.IsEdns0(); opt != nil {
		resp.SetEdns0(ednsSize, opt.Do())
	}
	return resp
}

// forward answers req from the cache, or asks the upstream servers, and keeps their answer when
// it can be kept: with req's id, and its kind, Cached or Forwarded.
func (s *Server) forward(req *dns.Msg) (*dns.Msg, string, error) {
	if resp := s.cache.get(req); resp != nil {
		return resp, Cached, nil
	}
	resp, err := s.exchange(s.ctx, req)
	if err != nil {
		return nil, "", err
	}
	s.cache.put(req, resp)
	resp.Id = req.Id
	return resp, Forwarded, nil
}

// exchange asks the upstream servers q, in order, and returns the first answer, of whatever code,
// with an id of its own. Plain DNS is asked over UDP, and again over TCP when the answer doesn't
// fit; DNS over TLS on a connection kept open; over HTTPS by its client. Each address of a server
// given by host name is tried; then the next server.
func (s *Server) exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	errs := make([]error, 0, len(s.upstreams))
	for _, srv := range s.upstreams {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var failed []error
		if srv.transport == dnsOverHTTPS {
			m := padded(q)
			m.Id = dns.Id()
			resp, err := s.askHTTPS(ctx, srv, m)
			if err == nil {
				return unpadded(resp, q), nil
			}
			failed = append(failed, err)
		} else {
			targets := s.targets(srv)
			if len(targets) == 0 {
				s.failures[srv.label].Add(1)
				errs = append(errs, fmt.Errorf("%s: no address found by the bootstrap servers", srv.label))
				continue
			}
			for _, target := range targets {
				var resp *dns.Msg
				var err error
				if srv.transport == dnsOverTLS {
					m := padded(q)
					m.Id = dns.Id()
					if resp, err = s.askTLS(ctx, srv, m, target); err == nil {
						resp = unpadded(resp, q)
					}
				} else {
					m := q.Copy()
					m.Id = dns.Id()
					resp, err = s.ask(ctx, m, "udp", target)
					if err == nil && resp.Truncated {
						resp, err = s.ask(ctx, m, "tcp", target)
					}
				}
				if err == nil {
					return resp, nil
				}
				failed = append(failed, fmt.Errorf("%s: %w", target, err))
			}
		}
		s.failures[srv.label].Add(1)
		errs = append(errs, fmt.Errorf("%s: %w", srv.label, errors.Join(failed...)))
	}
	return nil, errors.Join(errs...)
}

// ask sends m to upstream over network, and reads its answer: over UDP whatever its size, as a
// server that sends more than the query's EDNS says still answers, and an answer of another id,
// or question, is no answer to it. It gives up when ctx is done.
func (s *Server) ask(ctx context.Context, m *dns.Msg, network, upstream string) (*dns.Msg, error) {
	c := &dns.Client{Net: network, Timeout: s.timeout}
	conn, err := c.Dial(upstream)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
	defer stop()
	conn.SetDeadline(time.Now().Add(s.timeout))
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	conn.UDPSize = dns.MaxMsgSize
	if err := conn.WriteMsg(m); err != nil {
		return nil, err
	}
	for {
		resp, err := conn.ReadMsg()
		if err != nil {
			return nil, err
		}
		if isAnswerTo(resp, m) {
			return resp, nil
		}
	}
}

// Status is a resolver's, for the report, /status.json and the metrics.
type Status struct {
	Name string `json:"name"`
	// host:port, once started.
	Listening []string `json:"listening"`
	Allow     []string `json:"allow"`
	Upstreams []string `json:"upstreams"`
	Zones     []string `json:"zones"`
	Serving   bool     `json:"serving"`
	// Why it isn't serving, when it stopped on its own.
	Error string `json:"error,omitempty"`
	// The queries answered, by kind.
	Queries map[string]uint64 `json:"queries"`
	// The addresses the bootstrap servers found for the upstream servers given by host name.
	UpstreamAddresses map[string][]string `json:"upstream_addresses,omitempty"`
	// The queries an upstream server didn't answer, by server.
	UpstreamFailures map[string]uint64 `json:"upstream_failures"`
	// The answers in the cache; and how many it holds, 0 for no cache.
	CacheEntries int `json:"cache_entries"`
	CacheSize    int `json:"cache_size"`
}

func (s *Server) Status() Status {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	status := Status{
		Name:             s.config.Name,
		Listening:        append([]string{}, s.listening...),
		Allow:            []string{},
		Upstreams:        append([]string{}, s.config.Upstreams...),
		Zones:            []string{},
		Serving:          s.serving,
		CacheEntries:     s.cache.len(),
		CacheSize:        s.config.CacheSize,
		Queries:          make(map[string]uint64),
		UpstreamFailures: make(map[string]uint64),
	}
	for _, p := range s.allow {
		status.Allow = append(status.Allow, p.String())
	}
	if s.allow == nil {
		for _, p := range s.config.Allow {
			status.Allow = append(status.Allow, p.String())
		}
	}
	for _, z := range s.config.Zones {
		status.Zones = append(status.Zones, strings.TrimSuffix(z.Name, "."))
	}
	if s.err != nil {
		status.Error = s.err.Error()
	}
	for k, v := range s.queries {
		status.Queries[k] = v.Load()
	}
	for k, v := range s.failures {
		status.UpstreamFailures[k] = v.Load()
	}
	for upstream, n := range s.named {
		n.mutex.Lock()
		if len(n.addresses) > 0 {
			if status.UpstreamAddresses == nil {
				status.UpstreamAddresses = make(map[string][]string)
			}
			status.UpstreamAddresses[upstream] = append([]string{}, n.addresses...)
		}
		n.mutex.Unlock()
	}
	return status
}
