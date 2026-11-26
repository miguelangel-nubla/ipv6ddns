package resolver

import (
	"crypto/tls"
	"maps"
	"net"
	"net/http"
	"slices"
	"strings"

	"github.com/miekg/dns"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/certfile"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/listen"
)

// route is an encrypted entry of a socket, with the resolver that answers it. A socket that
// listeners share has one of each, in their order: the first, the default, is of the resolver
// that opens it; the others are told of it alone.
type route struct {
	s *Server
	e EncryptedListen
}

// certificate is the certificate the route shows.
func (r route) certificate() *certfile.Certificate { return r.s.certificateOf(r.e) }

// sharedKey is the socket of an address of an entry, as Share groups them: tls://10.2.3.75:853.
func sharedKey(transport, address string) string { return transport + "://" + address }

// Share has the servers share the sockets of their encrypted entries that listeners share, as
// the configuration marks them Shared: each socket is opened once, by the server of its first
// listener, which hands each client to the listener of the name its TLS handshake asks. Before
// Start, of every server that has such an entry: one left out opens its own, which can't listen.
func Share(servers []*Server) error {
	groups := make(map[string][]route)
	for _, s := range servers {
		for _, e := range s.config.Encrypted {
			if !e.Shared {
				continue
			}
			addresses, err := listen.Addresses([]listen.Entry{e.Entry})
			if err != nil {
				return err
			}
			for _, a := range addresses {
				k := sharedKey(e.Transport, a)
				groups[k] = append(groups[k], route{s, e})
			}
		}
	}
	for k, routes := range groups {
		slices.SortStableFunc(routes, func(a, b route) int { return a.e.Rank - b.e.Rank })
		for _, r := range routes {
			if r.s.shared == nil {
				r.s.shared = make(map[string][]route)
			}
			r.s.shared[k] = routes
		}
	}
	return nil
}

// opens tells whether the server opens the socket of e at k: its own, or of a share its first.
func (s *Server) opens(e EncryptedListen, k string) bool {
	routes := s.shared[k]
	return len(routes) == 0 || routes[0].s == s && routes[0].e.Listener == e.Listener
}

// routesOf are the routes of the socket of e at k, which s opens.
func (s *Server) routesOf(e EncryptedListen, k string) []route {
	if routes := s.shared[k]; len(routes) > 0 {
		return routes
	}
	return []route{{s, e}}
}

// choose is the route of a client that asks name in its TLS handshake: of the first listener whose
// server name, or certificate, is for it; or, of none, as a client by address alone asks, of the
// first, the default.
func choose(routes []route, name string) route {
	if len(routes) > 1 && name != "" {
		for _, r := range routes {
			if r.e.ServerName != "" && certfile.Matches(r.e.ServerName, name) || r.certificate().Covers(name) {
				return r
			}
		}
	}
	return routes[0]
}

// tlsConfig is the configuration of TLS of a socket of the routes, which speaks protocols: of one,
// its certificate's; of several, that of the route chosen by the name the client asks.
func tlsConfig(routes []route, protocols ...string) *tls.Config {
	if len(routes) == 1 {
		return routes[0].certificate().Config(protocols...)
	}
	// One of each, made once: the keys of its session tickets are kept.
	configs := make(map[*certfile.Certificate]*tls.Config)
	for _, r := range routes {
		if c := r.certificate(); configs[c] == nil {
			configs[c] = c.Config(protocols...)
		}
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: protocols,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			return configs[choose(routes, hello.ServerName).certificate()], nil
		}}
}

// serverNameOf is the name a client of DNS over TLS asked in its handshake: "" of none.
func serverNameOf(w dns.ResponseWriter) string {
	if c, ok := w.(dns.ConnectionStater); ok {
		if state := c.ConnectionState(); state != nil {
			return state.ServerName
		}
	}
	return ""
}

// sharedSocket answers the queries of a socket of DNS over TLS that listeners share: each by the
// resolver of the listener its client asked, with that listener's allow.
type sharedSocket []route

func (h sharedSocket) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	r := choose(h, serverNameOf(w))
	if r.s.isStopping() {
		// Its resolver is shut down: the client asks again, elsewhere.
		_ = w.Close()
		return
	}
	// The server checks a signature with the keys of the first's resolver alone: of another's, it
	// would be taken unchecked, or checked with a key of the same name and another secret. Refused.
	if r.s != h[0].s && (req.IsTsig() != nil || req.Opcode == dns.OpcodeUpdate) && !req.Response {
		r.s.queries[Refused].Add(1)
		_ = w.WriteMsg(reply(req, dns.RcodeRefused))
		return
	}
	r.s.serveDNS(w, req, r.e.Allow)
}

// answerHTTPSOf answers a request of DNS over HTTPS to the entry e, or the web server's that
// shares it.
func (s *Server) answerHTTPSOf(w http.ResponseWriter, r *http.Request, e EncryptedListen) {
	if s.isStopping() {
		http.Error(w, "the resolver is shut down", http.StatusServiceUnavailable)
		return
	}
	if e.Web != "" {
		s.answerHTTPSOrWeb(w, r, e.Web, e.Allow)
		return
	}
	s.answerHTTPS(w, r, e.Allow)
}

// isStopping tells whether the server is shut down, or shutting down.
func (s *Server) isStopping() bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.stopping
}

// sharedAddr is the address of a socket another server opens, as it listens there: every address,
// of a port alone, is [::]'s, as Go listens there.
func sharedAddr(transport, address string) net.Addr {
	host, port, _ := net.SplitHostPort(address)
	if host == "" {
		address = net.JoinHostPort("::", port)
	}
	if transport == TransportQUIC {
		a, _ := net.ResolveUDPAddr("udp", address)
		return a
	}
	a, _ := net.ResolveTCPAddr("tcp", address)
	return a
}

// serverName is the name the clients ask the entry e by, as DDR tells it: its listener's server
// name, while its certificate is for it, or else the certificate's first name that is no
// wildcard; "" of none. A server name the certificate, renewed, is no longer for is logged, once.
func (s *Server) serverName(e EncryptedListen) string {
	if e.ServerName == "" {
		return certificateName(s, e)
	}
	cert := s.certificateOf(e)
	covered := cert != nil && cert.Covers(e.ServerName)
	s.uncoveredMutex.Lock()
	warn := !covered && !s.uncovered[e.Listener]
	if s.uncovered == nil {
		s.uncovered = make(map[string]bool)
	}
	s.uncovered[e.Listener] = !covered
	s.uncoveredMutex.Unlock()
	if covered {
		return dns.Fqdn(certfile.Canonical(e.ServerName))
	}
	if warn && s.config.Warnf != nil {
		s.config.Warnf("%s: listener %s: its certificate %s is no longer for its server_name %s: the clients are told its own name instead", s.config.Path, e.Listener, e.CertificateName, e.ServerName)
	}
	return certificateName(s, e)
}

// SharedStatus is a socket a resolver's listener shares with others.
type SharedStatus struct {
	// tls://10.2.3.75:853
	Address  string `json:"address"`
	Listener string `json:"listener"`
	// The name its clients ask, that DDR tells: "" of none.
	Name string `json:"name,omitempty"`
	// Whether it answers the clients that ask no name of another: the first listener.
	Default bool `json:"default"`
	// The other listeners there.
	With []string `json:"with"`
}

// sharedStatus is the status of the sockets the server's listeners share.
func (s *Server) sharedStatus() []SharedStatus {
	var result []SharedStatus
	for _, k := range slices.Sorted(maps.Keys(s.shared)) {
		routes := s.shared[k]
		for i, r := range routes {
			if r.s != s {
				continue
			}
			st := SharedStatus{Address: k, Listener: r.e.Listener, Name: strings.TrimSuffix(s.serverName(r.e), "."), Default: i == 0, With: []string{}}
			for _, o := range routes {
				if o.e.Listener != r.e.Listener {
					st.With = append(st.With, o.e.Listener)
				}
			}
			result = append(result, st)
		}
	}
	return result
}
