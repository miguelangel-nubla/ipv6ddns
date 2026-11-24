package resolver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"
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
	// host:port with its scheme, as the status says it, and the addresses themselves.
	listening []string
	listened  []net.Addr
}

// open listens on every address of e, over its transport: TCP for TLS and HTTPS, UDP for QUIC.
func (l *encryptedListeners) open(e EncryptedListen) error {
	addresses, err := listen.Addresses([]listen.Entry{e.Entry})
	if err != nil {
		return err
	}
	for _, a := range addresses {
		udp, tcp := networks(a)
		if e.Transport == TransportQUIC {
			c, err := net.ListenPacket(udp, a)
			if err != nil {
				return err
			}
			l.quic = append(l.quic, c)
			l.listening = append(l.listening, e.Transport+"://"+c.LocalAddr().String())
			l.listened = append(l.listened, c.LocalAddr())
			continue
		}
		tl, err := net.Listen(tcp, a)
		if err != nil {
			return err
		}
		if e.Transport == TransportTLS {
			l.tls = append(l.tls, tl)
		} else {
			l.https = append(l.https, tl)
		}
		l.listening = append(l.listening, e.Transport+"://"+tl.Addr().String())
		l.listened = append(l.listened, tl.Addr())
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

// serveHTTPS answers DNS over HTTPS on the listeners, over HTTP/1.1 and HTTP/2.
func (s *Server) serveHTTPS(listeners []net.Listener, cert *certificate) {
	for _, l := range listeners {
		srv := &http.Server{
			Handler:           http.HandlerFunc(s.answerHTTPS),
			TLSConfig:         cert.config("h2", "http/1.1"),
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

// answerHTTPS answers a query of DNS over HTTPS, RFC 8484: a GET with the message in base64url, as
// dns, or a POST with it as the body.
func (s *Server) answerHTTPS(w http.ResponseWriter, r *http.Request) {
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
	resp := s.respond(req, remote)
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

// serveQUIC answers DNS over QUIC, RFC 9250, on the sockets: each query on a stream of its own.
func (s *Server) serveQUIC(conns []net.PacketConn, cert *certificate) {
	for _, c := range conns {
		l, err := quic.Listen(c, cert.config(alpnQUIC), &quic.Config{
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
		s.mutex.Unlock()
		go func() {
			for {
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
				go s.serveQUICConn(conn)
			}
		}()
	}
}

// serveQUICConn answers the streams of a connection of DNS over QUIC, until it closes.
func (s *Server) serveQUICConn(conn *quic.Conn) {
	s.mutex.Lock()
	if s.stopping {
		s.mutex.Unlock()
		_ = conn.CloseWithError(doqNoError, "")
		return
	}
	if s.quicConns == nil {
		s.quicConns = make(map[*quic.Conn]struct{})
	}
	s.quicConns[conn] = struct{}{}
	s.mutex.Unlock()
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
		go s.answerQUIC(conn, stream)
	}
}

// answerQUIC answers the query of a stream: the message, after its length in two bytes, with the
// ID 0. A stream that breaks the protocol closes its connection, as RFC 9250 has it.
func (s *Server) answerQUIC(conn *quic.Conn, stream *quic.Stream) {
	defer stream.Close()
	// A stream that can't have one is one already gone, which the reads then say.
	_ = stream.SetDeadline(time.Now().Add(encryptedTimeout))
	var length [2]byte
	if _, err := io.ReadFull(stream, length[:]); err != nil {
		stream.CancelRead(quic.StreamErrorCode(doqProtocolError))
		return
	}
	wire := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err := io.ReadFull(stream, wire); err != nil {
		stream.CancelRead(quic.StreamErrorCode(doqProtocolError))
		return
	}
	req := new(dns.Msg)
	if req.Unpack(wire) != nil || req.Id != 0 {
		_ = conn.CloseWithError(doqProtocolError, "a message that is no query of DNS over QUIC")
		return
	}
	resp := s.respond(req, conn.RemoteAddr())
	if resp == nil {
		_ = conn.CloseWithError(doqProtocolError, "not a query")
		return
	}
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

// shutdownEncrypted stops answering over HTTPS and QUIC: the answers being made over HTTPS are
// waited for, until ctx is done, and the connections of QUIC are closed.
func (s *Server) shutdownEncrypted(ctx context.Context) {
	s.mutex.Lock()
	https, listeners := s.https, s.quic
	conns := make([]*quic.Conn, 0, len(s.quicConns))
	for c := range s.quicConns {
		conns = append(conns, c)
	}
	s.mutex.Unlock()
	var wg sync.WaitGroup
	for _, srv := range https {
		// Its time over, the connections left are closed with the program: nothing to do.
		wg.Go(func() { _ = srv.Shutdown(ctx) })
	}
	wg.Wait()
	for _, l := range listeners {
		l.Close()
	}
	for _, c := range conns {
		_ = c.CloseWithError(doqNoError, "")
	}
}

// certificate is the certificate the encrypted transports show, read from its files, and read
// again when they change: a renewed certificate is shown without a restart. One that doesn't read
// keeps the one before, and the log says why.
type certificate struct {
	certFile, keyFile string
	errorf            func(string, ...any)

	mutex           sync.Mutex
	cert            *tls.Certificate
	certMod, keyMod time.Time
	checked         time.Time
	failed          string
}

// certificateCheck is how often the files are looked at, at most: when a client connects.
var certificateCheck = 5 * time.Second

// loadCertificate reads the certificate and its key, which must be a pair.
func loadCertificate(certFile, keyFile string, errorf func(string, ...any)) (*certificate, error) {
	c := &certificate{certFile: certFile, keyFile: keyFile, errorf: errorf}
	if err := c.load(); err != nil {
		return nil, err
	}
	return c, nil
}

// load reads the files, with the mutex held or before anything else has the certificate.
func (c *certificate) load() error {
	certMod, keyMod, err := modTimes(c.certFile, c.keyFile)
	if err != nil {
		return err
	}
	pair, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		return fmt.Errorf("%s and %s: %w", c.certFile, c.keyFile, err)
	}
	c.cert, c.certMod, c.keyMod, c.checked = &pair, certMod, keyMod, time.Now()
	return nil
}

// modTimes are when the files changed last.
func modTimes(certFile, keyFile string) (certMod, keyMod time.Time, err error) {
	ci, err := os.Stat(certFile)
	if err != nil {
		return certMod, keyMod, err
	}
	ki, err := os.Stat(keyFile)
	if err != nil {
		return certMod, keyMod, err
	}
	return ci.ModTime(), ki.ModTime(), nil
}

// get is the certificate to show a client: read again first, if its files changed.
func (c *certificate) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if time.Since(c.checked) >= certificateCheck {
		c.checked = time.Now()
		certMod, keyMod, err := modTimes(c.certFile, c.keyFile)
		if err == nil && (!certMod.Equal(c.certMod) || !keyMod.Equal(c.keyMod)) {
			err = c.load()
		}
		if err != nil {
			if err.Error() != c.failed {
				c.failed = err.Error()
				c.errorf("the certificate of the encrypted transports doesn't read again, and the one before is shown: %s", err)
			}
		} else {
			c.failed = ""
		}
	}
	return c.cert, nil
}

// config is the TLS configuration of a transport that speaks the protocols given.
func (c *certificate) config(protocols ...string) *tls.Config {
	return &tls.Config{GetCertificate: c.get, MinVersion: tls.VersionTLS12, NextProtos: protocols}
}

// CertificateStatus is the certificate the encrypted transports show: the names it is for, and
// until when.
type CertificateStatus struct {
	Names    []string  `json:"names"`
	NotAfter time.Time `json:"not_after"`
	// Why the files didn't read again, while the one before is shown.
	Error string `json:"error,omitempty"`
}

// status is the certificate's status.
func (c *certificate) status() *CertificateStatus {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	st := &CertificateStatus{Error: c.failed}
	leaf := c.cert.Leaf
	if leaf == nil && len(c.cert.Certificate) > 0 {
		leaf, _ = x509.ParseCertificate(c.cert.Certificate[0])
	}
	if leaf != nil {
		st.Names = leaf.DNSNames
		for _, ip := range leaf.IPAddresses {
			st.Names = append(st.Names, ip.String())
		}
		if len(st.Names) == 0 && leaf.Subject.CommonName != "" {
			st.Names = []string{leaf.Subject.CommonName}
		}
		st.NotAfter = leaf.NotAfter
	}
	return st
}
