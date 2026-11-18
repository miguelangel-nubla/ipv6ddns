package source

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/config"
	"go.uber.org/zap"
	"golang.org/x/net/dns/dnsmessage"
)

func addrs(t *testing.T, f fetcher) ([]string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := f(ctx)
	var s []string
	for _, a := range got {
		s = append(s, a.String())
	}
	slices.Sort(s)
	return s, err
}

func TestCommand(t *testing.T) {
	cfg := config.Source{Type: config.SourceCommand, Command: "printf", Args: []string{"%s", "192.0.2.1\n\n 2001:db8::1 \nfe80::1%eth0\n"}}
	got, err := addrs(t, commandFetcher(cfg, t.TempDir()))
	if err != nil || !slices.Equal(got, []string{"192.0.2.1", "2001:db8::1", "fe80::1"}) {
		t.Errorf("got %v, %v", got, err)
	}

	cfg.Args = []string{"%s", "192.0.2.1\nnot an address\n"}
	got, err = addrs(t, commandFetcher(cfg, t.TempDir()))
	if err == nil || !strings.Contains(err.Error(), "not an address") || !slices.Equal(got, []string{"192.0.2.1"}) {
		t.Errorf("a line that isn't an address: got %v, %v, want the others and an error", got, err)
	}

	failing := config.Source{Type: config.SourceCommand, Command: "sh", Args: []string{"-c", "echo broken >&2; exit 3"}}
	if _, err := addrs(t, commandFetcher(failing, t.TempDir())); err == nil || !strings.Contains(err.Error(), "broken") {
		t.Errorf("a failing command: got %v, want its stderr in the error", err)
	}
}

// echoServer answers every request with body, on network ("tcp4" or "tcp6").
func echoServer(t *testing.T, network, body string, status int) string {
	t.Helper()
	address := "127.0.0.1:0"
	if network == "tcp6" {
		address = "[::1]:0"
	}
	listener, err := net.Listen(network, address)
	if err != nil {
		t.Skipf("no %s loopback: %v", network, err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	server.Listener = listener
	server.Start()
	t.Cleanup(server.Close)
	return server.URL
}

func TestHTTP(t *testing.T) {
	v4 := echoServer(t, "tcp4", "203.0.113.7\n", http.StatusOK)
	v6 := echoServer(t, "tcp6", "2001:db8::7", http.StatusOK)
	broken := echoServer(t, "tcp4", "oops", http.StatusInternalServerError)
	wrongFamily := echoServer(t, "tcp4", "2001:db8::9", http.StatusOK)

	got, err := addrs(t, httpFetcher([]int{4, 6}, nil, map[int][]string{4: {broken, wrongFamily, v4}, 6: {v6}}))
	if err != nil || !slices.Equal(got, []string{"2001:db8::7", "203.0.113.7"}) {
		t.Errorf("got %v, %v, want both, from the third IPv4 service", got, err)
	}

	// The IPv6 request goes over IPv6: an IPv4-only service can't answer it.
	got, err = addrs(t, httpFetcher([]int{6}, []string{v4}, nil))
	if err == nil || len(got) != 0 {
		t.Errorf("IPv6 from an IPv4-only service: got %v, %v, want an error", got, err)
	}

	// A family failing doesn't lose the other.
	got, err = addrs(t, httpFetcher([]int{4, 6}, nil, map[int][]string{4: {v4}, 6: {broken}}))
	if err == nil || !strings.Contains(err.Error(), "IPv6") || !slices.Equal(got, []string{"203.0.113.7"}) {
		t.Errorf("got %v, %v", got, err)
	}
}

// dnsServer answers, on network ("udp4" or "udp6"), A, AAAA and TXT queries for name with answer.
func dnsServer(t *testing.T, network, name string, answer netip.Addr) string {
	t.Helper()
	address := "127.0.0.1:0"
	if network == "udp6" {
		address = "[::1]:0"
	}
	conn, err := net.ListenPacket(network, address)
	if err != nil {
		t.Skipf("no %s loopback: %v", network, err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			var query dnsmessage.Message
			if err := query.Unpack(buf[:n]); err != nil || len(query.Questions) != 1 {
				continue
			}
			q := query.Questions[0]
			reply := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, Authoritative: true}, Questions: query.Questions}
			header := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}
			if q.Name.String() == name {
				switch {
				case q.Type == dnsmessage.TypeA && answer.Is4():
					header.Type = dnsmessage.TypeA
					reply.Answers = append(reply.Answers, dnsmessage.Resource{Header: header, Body: &dnsmessage.AResource{A: answer.As4()}})
				case q.Type == dnsmessage.TypeAAAA && answer.Is6():
					header.Type = dnsmessage.TypeAAAA
					reply.Answers = append(reply.Answers, dnsmessage.Resource{Header: header, Body: &dnsmessage.AAAAResource{AAAA: answer.As16()}})
				case q.Type == dnsmessage.TypeTXT:
					header.Type = dnsmessage.TypeTXT
					reply.Answers = append(reply.Answers, dnsmessage.Resource{Header: header, Body: &dnsmessage.TXTResource{TXT: []string{answer.String()}}})
				}
			}
			packed, err := reply.Pack()
			if err == nil {
				conn.WriteTo(packed, from)
			}
		}
	}()
	return conn.LocalAddr().String()
}

func TestDNS(t *testing.T) {
	const name = "myip.example."
	a := dnsServer(t, "udp4", name, netip.MustParseAddr("203.0.113.7"))
	aaaa := dnsServer(t, "udp6", name, netip.MustParseAddr("2001:db8::7"))
	txt := dnsServer(t, "udp4", name, netip.MustParseAddr("198.51.100.8"))
	down := func() string { // a port nothing answers on
		conn, _ := net.ListenPacket("udp4", "127.0.0.1:0")
		defer conn.Close()
		return conn.LocalAddr().String()
	}()

	got, err := addrs(t, dnsFetcher([]int{4, 6}, []resolver{{name: name, servers: map[int]string{4: a, 6: aaaa}}}))
	if err != nil || !slices.Equal(got, []string{"2001:db8::7", "203.0.113.7"}) {
		t.Errorf("got %v, %v", got, err)
	}

	// The first resolver down, the second answers in a TXT record.
	got, err = addrs(t, dnsFetcher([]int{4}, []resolver{{name: name, servers: map[int]string{4: down}}, {name: name, txt: true, servers: map[int]string{4: txt}}}))
	if err != nil || !slices.Equal(got, []string{"198.51.100.8"}) {
		t.Errorf("fallback: got %v, %v", got, err)
	}

	if _, err := addrs(t, dnsFetcher([]int{6}, []resolver{{name: name, servers: map[int]string{4: a}}})); err == nil {
		t.Error("no IPv6 resolver: want an error")
	}
}

func TestSourceKeepsAddressesForTheirLifetime(t *testing.T) {
	cfg := config.Source{Type: config.SourceStatic, Addresses: []string{"192.0.2.1"}}
	cfg.Interval.Duration = time.Hour
	cfg.Lifetime.Duration = 50 * time.Millisecond
	s, err := New("fixed", cfg, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ran := make(chan struct{}, 1)
	s.Start(ctx, zap.NewNop().Sugar(), func() { ran <- struct{}{} })
	select {
	case <-ran:
	case <-time.After(3 * time.Second):
		t.Fatal("not told of the run")
	}

	deadline := time.Now().Add(3 * time.Second)
	for len(s.Addresses().Get()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no address")
		}
		time.Sleep(time.Millisecond)
	}
	if got := s.Addresses().Get()[0]; got.String() != "192.0.2.1" || got.Sources()[0] != "fixed" || len(got.Hw) != 0 {
		t.Errorf("got %s from %v, MAC %v", got, got.Sources(), got.Hw)
	}
	status := s.Status(true)
	if status.Runs != 1 || status.LastSuccess == nil || status.Name != "fixed" || status.Type != "static" {
		t.Errorf("status: %+v", status)
	}

	// Not given again within its lifetime, it goes.
	time.Sleep(100 * time.Millisecond)
	if got := s.Addresses().Get(); len(got) != 0 {
		t.Errorf("after its lifetime: %v", got)
	}

	cancel()
	done := make(chan struct{})
	go func() { s.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the source did not stop")
	}
}

func TestStatusHidesTheError(t *testing.T) {
	cfg := config.Source{Type: config.SourceCommand, Command: "sh", Args: []string{"-c", "echo token=SECRET >&2; exit 1"}}
	cfg.Interval.Duration = time.Hour
	cfg.Lifetime.Duration = time.Hour
	s, _ := New("cmd", cfg, t.TempDir(), nil)
	s.run(context.Background(), zap.NewNop().Sugar())
	if got := s.Status(true); got.LastError != "<sensible data hidden>" || got.Failures != 1 {
		t.Errorf("hidden: %+v", got)
	}
	if got := s.Status(false); !strings.Contains(got.LastError, "SECRET") {
		t.Errorf("shown: %+v", got)
	}
}
