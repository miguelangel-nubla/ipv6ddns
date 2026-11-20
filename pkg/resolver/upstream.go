package resolver

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// The default ports of the encrypted transports: DNS over TLS's, RFC 7858, and HTTPS's, RFC 8484.
const (
	DefaultTLSPort   = "853"
	DefaultHTTPSPort = "443"
)

// IdleTimeout is how long a connection to an encrypted upstream server is kept open with no
// query, for the next: then it is closed.
const IdleTimeout = 30 * time.Second

// paddingBlock is the size that an encrypted query is padded to a multiple of, as RFC 8467
// recommends: the name asked, its length, is less of a tell.
const paddingBlock = 128

// The transports of an upstream server.
const (
	plainDNS     = ""
	dnsOverTLS   = "tls"
	dnsOverHTTPS = "https"
)

// upstreamServer is an upstream server: plain DNS, at host:port; DNS over TLS, tls://host:port; or over
// HTTPS, https://host:port/path. Its host is an address, or a host name the bootstrap servers find.
type upstreamServer struct {
	// As the configuration has it, for the status and the metrics.
	label     string
	transport string
	// An address, or a host name, absolute, which named finds.
	host, port string
	// Of DNS over HTTPS.
	url   string
	named *namedUpstream

	// Of DNS over TLS: the connections open, kept for the next query.
	dot *dotPool
	// Of DNS over HTTPS: its client, made at Start.
	doh *http.Client
}

// parseServer reads an upstream server as the configuration checked it: host:port, tls://host or
// https://host/path, a port or not.
func parseServer(s string) (*upstreamServer, error) {
	if !strings.Contains(s, "://") {
		host, port, err := net.SplitHostPort(s)
		if err != nil {
			return nil, err
		}
		return &upstreamServer{label: s, transport: plainDNS, host: host, port: port}, nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	srv := &upstreamServer{label: s, host: strings.ToLower(u.Hostname()), port: u.Port()}
	switch strings.ToLower(u.Scheme) {
	case "tls":
		srv.transport = dnsOverTLS
		if srv.port == "" {
			srv.port = DefaultTLSPort
		}
	case "https":
		srv.transport = dnsOverHTTPS
		if srv.port == "" {
			srv.port = DefaultHTTPSPort
		}
		srv.url = "https://" + net.JoinHostPort(srv.host, srv.port) + u.EscapedPath()
	default:
		return nil, fmt.Errorf("the scheme %s", u.Scheme)
	}
	return srv, nil
}

// isName tells whether the server's host is a host name, not an address.
func (srv *upstreamServer) isName() bool {
	_, err := netip.ParseAddr(srv.host)
	return err != nil
}

// tlsConfig is the TLS of the server: its certificate verified, for its host, against roots, the
// system's when nil.
func (srv *upstreamServer) tlsConfig(roots *x509.CertPool) *tls.Config {
	return &tls.Config{ServerName: strings.TrimSuffix(srv.host, "."), RootCAs: roots, MinVersion: tls.VersionTLS12}
}

// open makes the clients of an encrypted server: of DNS over HTTPS, one, over HTTP/2, which
// connects to the addresses targets gives, and never asks the system's resolver.
func (srv *upstreamServer) open(s *Server) {
	switch srv.transport {
	case dnsOverTLS:
		srv.dot = &dotPool{idle: make(map[string][]*dotConn), config: srv.tlsConfig(s.roots)}
	case dnsOverHTTPS:
		dialer := &net.Dialer{Timeout: s.timeout}
		transport := &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				targets := s.targets(srv)
				if len(targets) == 0 {
					return nil, errors.New("no address found by the bootstrap servers")
				}
				var errs []error
				for _, target := range targets {
					c, err := dialer.DialContext(ctx, network, target)
					if err == nil {
						return c, nil
					}
					errs = append(errs, err)
				}
				return nil, errors.Join(errs...)
			},
			TLSClientConfig:     srv.tlsConfig(s.roots),
			ForceAttemptHTTP2:   true,
			IdleConnTimeout:     IdleTimeout,
			TLSHandshakeTimeout: s.timeout,
			MaxIdleConnsPerHost: 4,
		}
		// A redirect is no answer: the server is the one given.
		srv.doh = &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
}

// close closes the connections the server keeps.
func (srv *upstreamServer) close() {
	if srv.dot != nil {
		srv.dot.closeAll()
	}
	if srv.doh != nil {
		srv.doh.CloseIdleConnections()
	}
}

// dotPool is the connections to a server of DNS over TLS, kept open between queries, by the
// address each is to: one query at a time on each, as many open as queries at once, each closed
// after IdleTimeout without one.
type dotPool struct {
	config *tls.Config

	mutex  sync.Mutex
	idle   map[string][]*dotConn
	closed bool
}

type dotConn struct {
	*dns.Conn
	// Closes it, idle for too long: stopped, it wasn't.
	timer *time.Timer
}

// take is an idle connection to target, or nil for none.
func (p *dotPool) take(target string) *dotConn {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	for conns := p.idle[target]; len(conns) > 0; conns = p.idle[target] {
		c := conns[len(conns)-1]
		p.idle[target] = conns[:len(conns)-1]
		if c.timer.Stop() {
			return c
		}
	}
	return nil
}

// put keeps c for the next query to target.
func (p *dotPool) put(target string, c *dotConn) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if p.closed {
		c.Close()
		return
	}
	c.timer = time.AfterFunc(IdleTimeout, func() {
		p.mutex.Lock()
		defer p.mutex.Unlock()
		conns := p.idle[target]
		for i, other := range conns {
			if other == c {
				p.idle[target] = append(conns[:i:i], conns[i+1:]...)
				break
			}
		}
		c.Close()
	})
	p.idle[target] = append(p.idle[target], c)
}

func (p *dotPool) closeAll() {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.closed = true
	for target, conns := range p.idle {
		for _, c := range conns {
			if c.timer.Stop() {
				c.Close()
			}
		}
		delete(p.idle, target)
	}
}

// askTLS sends m to target over a connection of DNS over TLS, one kept open or a new one, and reads
// its answer. A connection kept that fails, as one the server closed meanwhile, is tried again on
// a new one.
func (s *Server) askTLS(ctx context.Context, srv *upstreamServer, m *dns.Msg, target string) (*dns.Msg, error) {
	deadline := time.Now().Add(s.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if c := srv.dot.take(target); c != nil {
		if resp, err := exchangeOn(ctx, c, m, deadline); err == nil {
			srv.dot.put(target, c)
			return resp, nil
		}
		c.Close()
	}
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Deadline: deadline}, Config: srv.dot.config}
	raw, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, err
	}
	c := &dotConn{Conn: &dns.Conn{Conn: raw}}
	resp, err := exchangeOn(ctx, c, m, deadline)
	if err != nil {
		c.Close()
		return nil, err
	}
	srv.dot.put(target, c)
	return resp, nil
}

// exchangeOn writes m on c and reads its answer, until deadline, or ctx is done: an answer of
// another id, or question, is none.
func exchangeOn(ctx context.Context, c *dotConn, m *dns.Msg, deadline time.Time) (*dns.Msg, error) {
	c.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { c.SetDeadline(time.Now()) })
	defer stop()
	if err := c.WriteMsg(m); err != nil {
		return nil, err
	}
	for {
		resp, err := c.ReadMsg()
		if err != nil {
			return nil, err
		}
		if isAnswerTo(resp, m) {
			return resp, nil
		}
	}
}

// isAnswerTo tells whether resp is the answer to m: its id, and its question.
func isAnswerTo(resp, m *dns.Msg) bool {
	return resp.Id == m.Id && len(resp.Question) == len(m.Question) && (len(m.Question) == 0 || strings.EqualFold(resp.Question[0].Name, m.Question[0].Name) && resp.Question[0].Qtype == m.Question[0].Qtype)
}

// askHTTPS sends m to a server of DNS over HTTPS, POST, as RFC 8484 has it, with the id 0, which
// an HTTP cache would want; the answer is given m's id.
func (s *Server) askHTTPS(ctx context.Context, srv *upstreamServer, m *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	q := m.Copy()
	q.Id = 0
	body, err := q.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := srv.doh.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status %s", resp.Status)
	}
	if t := resp.Header.Get("Content-Type"); !strings.HasPrefix(t, "application/dns-message") {
		return nil, fmt.Errorf("an answer of the type %q, not application/dns-message", t)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, dns.MaxMsgSize+1))
	if err != nil {
		return nil, err
	}
	answer := new(dns.Msg)
	if err := answer.Unpack(data); err != nil {
		return nil, err
	}
	if !isAnswerTo(answer, q) {
		return nil, errors.New("an answer to another question")
	}
	answer.Id = m.Id
	return answer, nil
}

// padded is m as it goes encrypted: with EDNS, and padded to a multiple of paddingBlock, as RFC
// 7830 and 8467 have it.
func padded(m *dns.Msg) *dns.Msg {
	m = m.Copy()
	opt := m.IsEdns0()
	if opt == nil {
		m.SetEdns0(ednsSize, false)
		opt = m.IsEdns0()
	}
	var options []dns.EDNS0
	for _, o := range opt.Option {
		if o.Option() != dns.EDNS0PADDING {
			options = append(options, o)
		}
	}
	opt.Option = options
	length := m.Len()
	// The option's code and length are 4 bytes.
	padding := (paddingBlock - (length+4)%paddingBlock) % paddingBlock
	opt.Option = append(opt.Option, &dns.EDNS0_PADDING{Padding: make([]byte, padding)})
	return m
}

// unpadded is resp, the answer over an encrypted transport to query, as the client is to have
// it: without the padding, and without EDNS when query had none, which padded added.
func unpadded(resp, query *dns.Msg) *dns.Msg {
	for i := 0; i < len(resp.Extra); i++ {
		opt, ok := resp.Extra[i].(*dns.OPT)
		if !ok {
			continue
		}
		if query.IsEdns0() == nil {
			resp.Extra = append(resp.Extra[:i], resp.Extra[i+1:]...)
			i--
			continue
		}
		var options []dns.EDNS0
		for _, o := range opt.Option {
			if o.Option() != dns.EDNS0PADDING {
				options = append(options, o)
			}
		}
		opt.Option = options
	}
	return resp
}
