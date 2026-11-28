package resolver

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/certfile"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/listen"
	"github.com/quic-go/quic-go"
)

// The encrypted transports a resolver answers over, as a listen entry names them by its scheme,
// tls://, https:// or quic://, and their default ports.
const (
	TransportTLS   = "tls"
	TransportHTTPS = "https"
	TransportQUIC  = "quic"

	// DNS over QUIC's, RFC 9250, over UDP: the same number as DNS over TLS's, over TCP.
	DefaultQUICPort = "853"
)

// DoHPath is where DNS over HTTPS answers, as RFC 8484's example, and as clients ask by default.
const DoHPath = "/dns-query"

// The application protocols of TLS that each transport says it speaks, as RFC 7858 and RFC 9250
// name them.
const (
	alpnTLS  = "dot"
	alpnQUIC = "doq"
)

// The error codes of DNS over QUIC, RFC 9250, that a connection is closed with.
const (
	doqNoError       quic.ApplicationErrorCode = 0x0
	doqProtocolError quic.ApplicationErrorCode = 0x2
)

// encryptedTimeout is how long a client has to send its query, or take its answer, over an
// encrypted transport, as over plain TCP.
const encryptedTimeout = 10 * time.Second

// EncryptedListen is a listen entry of an encrypted transport.
type EncryptedListen struct {
	// TransportTLS, TransportHTTPS or TransportQUIC.
	Transport string
	Entry     listen.Entry
	// As written, for errors.
	Line string
	// The certificate it shows, of a listener's entry: none, the resolver's.
	Certificate     *certfile.Certificate
	CertificateName string
	// The clients it answers, of a listener's entry: none, the resolver's. Config.Allow, when
	// given, replaces it.
	Allow []netip.Prefix
	// Of HTTPS: the web server whose handler SetWeb gave by this name answers every path but
	// DoHPath. None: those paths are not found.
	Web string
	// Of a listener's entry: its name, and its place among the listeners, as written, the first 0.
	Listener string
	Rank     int
	// The name the clients ask the listener by, which its certificate is for: none, the
	// certificate's first.
	ServerName string
	// Whether other listeners share its socket, of the same transport, address and port: Share
	// has one server open it, which tells the listeners apart by the name the client asks.
	Shared bool
}

// DefaultPortOf is the port an entry of transport has when it gives none.
func DefaultPortOf(transport string) string {
	switch transport {
	case TransportTLS:
		return DefaultTLSPort
	case TransportHTTPS:
		return DefaultHTTPSPort
	case TransportQUIC:
		return DefaultQUICPort
	}
	return DefaultPort
}

// encryptedListeners are the sockets of the encrypted transports, open before anything is served.
type encryptedListeners struct {
	tls, https []net.Listener
	quic       []net.PacketConn
	// Of each of tls, https and quic, in their order: its routes, one of an entry of its own.
	tlsOf, httpsOf, quicOf [][]route
	// host:port with its scheme, as the status says it, and the addresses themselves.
	listening []string
	listened  []listenedAddr
	// The sockets of each listener's entries, by its name, as listening tells them.
	byListener map[string][]string
}

// open listens on every address of e, over its transport: TCP for TLS and HTTPS, UDP for QUIC. An
// address of a socket that listeners share, and another server opens, is only told.
func (l *encryptedListeners) open(s *Server, e EncryptedListen) error {
	addresses, err := listen.Addresses([]listen.Entry{e.Entry})
	if err != nil {
		return err
	}
	if l.byListener == nil {
		l.byListener = map[string][]string{}
	}
	// Each socket of the entry, of its listener's.
	of := func(text string) {
		if e.Listener != "" && !slices.Contains(l.byListener[e.Listener], text) {
			l.byListener[e.Listener] = append(l.byListener[e.Listener], text)
		}
	}
	for _, a := range addresses {
		k := sharedKey(e.Transport, a)
		if !s.opens(e, k) {
			addr := sharedAddr(e.Transport, a)
			text := e.Transport + "://" + addr.String()
			if !slices.Contains(l.listening, text) {
				l.listening = append(l.listening, text)
			}
			of(text)
			l.listened = append(l.listened, listenedAt(addr, a))
			continue
		}
		routes := s.routesOf(e, k)
		udp, tcp := networks(a)
		if e.Transport == TransportQUIC {
			c, err := net.ListenPacket(udp, a)
			if err != nil {
				return err
			}
			l.quic = append(l.quic, c)
			l.quicOf = append(l.quicOf, routes)
			l.listening = append(l.listening, e.Transport+"://"+c.LocalAddr().String())
			of(e.Transport + "://" + c.LocalAddr().String())
			l.listened = append(l.listened, listenedAt(c.LocalAddr(), a))
			continue
		}
		tl, err := net.Listen(tcp, a)
		if err != nil {
			return err
		}
		if e.Transport == TransportTLS {
			l.tls = append(l.tls, tl)
			l.tlsOf = append(l.tlsOf, routes)
		} else {
			l.https = append(l.https, tl)
			l.httpsOf = append(l.httpsOf, routes)
		}
		l.listening = append(l.listening, e.Transport+"://"+tl.Addr().String())
		of(e.Transport + "://" + tl.Addr().String())
		l.listened = append(l.listened, listenedAt(tl.Addr(), a))
	}
	return nil
}

// close closes every socket open.
func (l *encryptedListeners) close() {
	for _, tl := range slices.Concat(l.tls, l.https) {
		tl.Close()
	}
	for _, c := range l.quic {
		c.Close()
	}
}

// serveHTTPS answers DNS over HTTPS on the listeners, over HTTP/1.1 and HTTP/2. Of a socket that
// listeners share, each request is the listener's of the name of its TLS handshake, whatever its
// Host: the certificate shown was that one's.
func (s *Server) serveHTTPS(listeners []net.Listener, routes [][]route) {
	for i, l := range listeners {
		of := routes[i]
		handler := func(w http.ResponseWriter, r *http.Request) {
			name := ""
			if r.TLS != nil {
				name = r.TLS.ServerName
			}
			c := choose(of, name)
			c.s.answerHTTPSOf(w, r, c.e)
		}
		srv := &http.Server{
			Handler:           http.HandlerFunc(handler),
			TLSConfig:         tlsConfig(of, "h2", "http/1.1"),
			ReadHeaderTimeout: encryptedTimeout,
			ReadTimeout:       encryptedTimeout,
			WriteTimeout:      encryptedTimeout,
			IdleTimeout:       2 * time.Minute,
			ErrorLog:          nil,
		}
		s.mutex.Lock()
		s.https = append(s.https, srv)
		s.mutex.Unlock()
		go func() {
			err := srv.ServeTLS(l, "", "")
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			s.stopped(err)
		}()
	}
}

// Name is the resolver's, of the configuration.
func (s *Server) Name() string { return s.config.Name }

// SetWeb gives the handler of a web server, by the name the HTTPS entries it shares give as their
// Web: it answers there every path but DoHPath, and checks its own allow. Before Start.
func (s *Server) SetWeb(name string, h http.Handler) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.web == nil {
		s.web = make(map[string]http.Handler)
	}
	s.web[name] = h
}

// answerHTTPSOrWeb answers DNS over HTTPS at DoHPath, and has the web server of name answer every
// other path.
func (s *Server) answerHTTPSOrWeb(w http.ResponseWriter, r *http.Request, name string, allow []netip.Prefix) {
	if r.URL.Path == DoHPath {
		s.answerHTTPS(w, r, allow)
		return
	}
	s.mutex.Lock()
	web := s.web[name]
	s.mutex.Unlock()
	if web == nil {
		http.NotFound(w, r)
		return
	}
	web.ServeHTTP(w, r)
}

// answerHTTPS answers a query of DNS over HTTPS, RFC 8484: a GET with the message in base64url, as
// dns, or a POST with it as the body.
func (s *Server) answerHTTPS(w http.ResponseWriter, r *http.Request, allow []netip.Prefix) {
	if r.URL.Path != DoHPath {
		http.NotFound(w, r)
		return
	}
	var wire []byte
	var err error
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query().Get("dns")
		if q == "" {
			http.Error(w, "no dns parameter", http.StatusBadRequest)
			return
		}
		// Without padding, as RFC 8484 sends it, but taken with it too.
		wire, err = base64.RawURLEncoding.DecodeString(trimPadding(q))
	case http.MethodPost:
		if r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "the body must be application/dns-message", http.StatusUnsupportedMediaType)
			return
		}
		wire, err = io.ReadAll(io.LimitReader(r.Body, dns.MaxMsgSize+1))
		if err == nil && len(wire) > dns.MaxMsgSize {
			http.Error(w, "message too large", http.StatusRequestEntityTooLarge)
			return
		}
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "use GET or POST", http.StatusMethodNotAllowed)
		return
	}
	req := new(dns.Msg)
	if err != nil || req.Unpack(wire) != nil {
		http.Error(w, "not a DNS message", http.StatusBadRequest)
		return
	}
	remote, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if err != nil {
		http.Error(w, "no client address", http.StatusBadRequest)
		return
	}
	local, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	resp := s.respond(req, client{remote, allow, local})
	if resp == nil {
		http.Error(w, "not a query", http.StatusBadRequest)
		return
	}
	packed, err := resp.Pack()
	if err != nil {
		http.Error(w, "the answer doesn't pack", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "max-age="+strconv.Itoa(int(freshness(resp))))
	// Its length, of every answer: Go says it alone of a body within its buffer, of 4 KB, and
	// clients read the message by it, as dig, which took a larger one, as a name's signed with
	// ML-DSA-44, for one shorter than its header.
	w.Header().Set("Content-Length", strconv.Itoa(len(packed)))
	// A client gone: nothing to do.
	_, _ = w.Write(packed)
}

// trimPadding drops the padding of a base64 text.
func trimPadding(s string) string {
	for len(s) > 0 && s[len(s)-1] == '=' {
		s = s[:len(s)-1]
	}
	return s
}

// freshness is how long an answer can be kept, in seconds, as RFC 8484 has a cache of HTTP keep
// it: its smallest TTL, of its records, the SOA's of an answer without any, or none.
func freshness(resp *dns.Msg) uint32 {
	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		return 0
	}
	var least *uint32
	for _, rr := range slices.Concat(resp.Answer, resp.Ns) {
		ttl := rr.Header().Ttl
		if soa, ok := rr.(*dns.SOA); ok && len(resp.Answer) == 0 {
			ttl = min(ttl, soa.Minttl)
		}
		if least == nil || ttl < *least {
			least = &ttl
		}
	}
	if least == nil {
		return 0
	}
	return *least
}

// serveQUIC answers DNS over QUIC, RFC 9250, on the sockets: each query on a stream of its own. Of
// a socket that listeners share, each connection is the listener's of the name of its handshake.
func (s *Server) serveQUIC(conns []net.PacketConn, routes [][]route) {
	for i, c := range conns {
		of := routes[i]
		// No 0-RTT, which quic-go leaves off unless asked: a query replayed is answered twice.
		l, err := quic.Listen(c, tlsConfig(of, alpnQUIC), &quic.Config{
			MaxIdleTimeout:     30 * time.Second,
			MaxIncomingStreams: 100,
		})
		if err != nil {
			s.stopped(fmt.Errorf("DNS over QUIC on %s: %w", c.LocalAddr(), err))
			c.Close()
			continue
		}
		s.mutex.Lock()
		s.quic = append(s.quic, l)
		s.quicSockets = append(s.quicSockets, c)
		s.mutex.Unlock()
		s.quicAccepting.Go(func() {
			for {
				// Once the listener is closed, it gives the connections it has yet, then the error.
				conn, err := l.Accept(s.ctx)
				if err != nil {
					s.mutex.Lock()
					stopping := s.stopping
					s.mutex.Unlock()
					if !stopping {
						s.stopped(fmt.Errorf("DNS over QUIC on %s: %w", c.LocalAddr(), err))
					}
					return
				}
				r := choose(of, conn.ConnectionState().TLS.ServerName)
				// Registered here, not in its goroutine: one registered later than Shutdown looks
				// was closed after its socket, and its client never told.
				if !r.s.registerQUIC(conn) {
					_ = conn.CloseWithError(doqNoError, "")
					continue
				}
				go r.s.serveQUICConn(conn, r.e.Allow)
			}
		})
	}
}

// registerQUIC registers a connection of DNS over QUIC, for Shutdown to close: false when the
// server is shut down, or, of a socket another server opened, not started yet, as the client then
// asks again.
func (s *Server) registerQUIC(conn *quic.Conn) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.stopping || !s.started {
		return false
	}
	if s.quicConns == nil {
		s.quicConns = make(map[*quic.Conn]struct{})
	}
	s.quicConns[conn] = struct{}{}
	return true
}

// serveQUICConn answers the streams of a connection of DNS over QUIC, registered, until it closes.
func (s *Server) serveQUICConn(conn *quic.Conn, allow []netip.Prefix) {
	defer func() {
		s.mutex.Lock()
		delete(s.quicConns, conn)
		s.mutex.Unlock()
	}()
	for {
		stream, err := conn.AcceptStream(s.ctx)
		if err != nil {
			return
		}
		go s.answerQUIC(conn, stream, allow)
	}
}

// answerQUIC answers the query of a stream: the message, after its length in two bytes, with the
// ID 0. A stream that breaks the protocol closes its connection, as RFC 9250 has it; one that
// ends before its message is reset, both ways, so that the client sees no empty answer.
func (s *Server) answerQUIC(conn *quic.Conn, stream *quic.Stream, allow []netip.Prefix) {
	defer stream.Close()
	// A stream that can't have one is one already gone, which the reads then say.
	_ = stream.SetDeadline(time.Now().Add(encryptedTimeout))
	var length [2]byte
	if _, err := io.ReadFull(stream, length[:]); err != nil {
		resetQUIC(stream)
		return
	}
	wire := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err := io.ReadFull(stream, wire); err != nil {
		resetQUIC(stream)
		return
	}
	req := new(dns.Msg)
	if req.Unpack(wire) != nil || req.Id != 0 {
		_ = conn.CloseWithError(doqProtocolError, "a message that is no query of DNS over QUIC")
		return
	}
	resp := s.respond(req, client{conn.RemoteAddr(), allow, conn.LocalAddr()})
	if resp == nil {
		_ = conn.CloseWithError(doqProtocolError, "not a query")
		return
	}
	// The length is of two bytes, as over TCP: an answer past it is truncated, as there.
	resp.Truncate(dns.MaxMsgSize)
	packed, err := resp.Pack()
	if err != nil {
		stream.CancelWrite(quic.StreamErrorCode(doqProtocolError))
		return
	}
	out := make([]byte, 2, 2+len(packed))
	binary.BigEndian.PutUint16(out, uint16(len(packed)))
	// A client gone, or a stream it reset: nothing to do.
	_, _ = stream.Write(append(out, packed...))
}

// resetQUIC resets the stream both ways, with the protocol's error: its Close after is nothing.
func resetQUIC(stream *quic.Stream) {
	stream.CancelRead(quic.StreamErrorCode(doqProtocolError))
	stream.CancelWrite(quic.StreamErrorCode(doqProtocolError))
}

// shutdownEncrypted stops answering over HTTPS and QUIC: the answers being made over HTTPS are
// waited for, until ctx is done, and the connections of QUIC are closed, and then its UDP
// sockets, which a listener of QUIC given its socket leaves open when it closes. A connection is
// closed while its socket is open, for its client to be told: one that is not hears nothing,
// and waits for its idle timeout.
func (s *Server) shutdownEncrypted(ctx context.Context) {
	s.mutex.Lock()
	https, listeners, sockets := s.https, s.quic, s.quicSockets
	s.mutex.Unlock()
	var wg sync.WaitGroup
	for _, srv := range https {
		// Its time over, the connections left are closed with the program: nothing to do.
		wg.Go(func() { _ = srv.Shutdown(ctx) })
	}
	wg.Wait()
	// quic-go closes the handshakes still going, and gives the connections it has queued: the
	// loops close those, as the server is stopping, and end.
	for _, l := range listeners {
		l.Close()
	}
	s.quicAccepting.Wait()
	s.mutex.Lock()
	conns := slices.Collect(maps.Keys(s.quicConns))
	s.mutex.Unlock()
	for _, c := range conns {
		_ = c.CloseWithError(doqNoError, "")
	}
	for _, c := range sockets {
		c.Close()
	}
}
