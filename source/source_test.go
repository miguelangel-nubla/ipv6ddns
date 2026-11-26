package source

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6disc"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
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

// A command that leaves something running with its output open ends at the timeout all the same.
func TestCommandTimeoutWithChild(t *testing.T) {
	leaving := config.Source{Type: config.SourceCommand, Command: "sh", Args: []string{"-c", "sleep 20 | cat"}}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := commandFetcher(leaving, t.TempDir())(ctx)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("got %v, want a timeout", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("it returned after %s, once what it started ended", elapsed)
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

	// An answer of the other family is none.
	if got, err := addrs(t, dnsFetcher([]int{6}, []resolver{{name: name, txt: true, servers: map[int]string{6: txtServer(t, "udp6", "203.0.113.7")}}})); err == nil || !strings.Contains(err.Error(), "not an IPv6 address") {
		t.Errorf("IPv4 for IPv6: got %v, %v, want an error", got, err)
	}

	// Of several TXT records, the address is the one that reads as one.
	got, err = addrs(t, dnsFetcher([]int{4}, []resolver{{name: name, txt: true, servers: map[int]string{4: txtServer(t, "udp4", "v=whatever", " 203.0.113.9 ")}}}))
	if err != nil || !slices.Equal(got, []string{"203.0.113.9"}) {
		t.Errorf("several TXT records: got %v, %v", got, err)
	}

	// With a client's subnet beside it, the query was relayed: the address is the relay's.
	got, err = addrs(t, dnsFetcher([]int{4}, []resolver{{name: name, txt: true, servers: map[int]string{4: txtServer(t, "udp4", "192.0.2.53", "edns0-client-subnet 203.0.113.0/24")}}}))
	if err == nil || !strings.Contains(err.Error(), "relayed") || len(got) != 0 {
		t.Errorf("a relayed query: got %v, %v, want an error", got, err)
	}
}

// txtServer answers, on network, every TXT query with records, and no other.
func txtServer(t *testing.T, network string, records ...string) string {
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
			if q.Type == dnsmessage.TypeTXT {
				header := dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 60}
				for _, record := range records {
					reply.Answers = append(reply.Answers, dnsmessage.Resource{Header: header, Body: &dnsmessage.TXTResource{TXT: []string{record}}})
				}
			}
			if packed, err := reply.Pack(); err == nil {
				conn.WriteTo(packed, from)
			}
		}
	}()
	return conn.LocalAddr().String()
}

// A service that hangs has its share of the run's time, and the next one is asked.
func TestHangingServiceLeavesTimeForTheNext(t *testing.T) {
	silent, err := net.Listen("tcp4", "127.0.0.1:0") // accepts, in its backlog, and never answers
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	v4 := echoServer(t, "tcp4", "203.0.113.7", http.StatusOK)
	v6 := echoServer(t, "tcp6", "2001:db8::7", http.StatusOK)
	fetch := func(f fetcher) ([]string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		got, err := f(ctx)
		var s []string
		for _, a := range got {
			s = append(s, a.String())
		}
		return s, err
	}

	got, err := fetch(httpFetcher([]int{4}, []string{"http://" + silent.Addr().String(), v4}, nil))
	if err != nil || !slices.Equal(got, []string{"203.0.113.7"}) {
		t.Errorf("http: got %v, %v, want the second service's answer", got, err)
	}
	// A family whose services all hang leaves the other its time.
	got, err = fetch(httpFetcher([]int{4, 6}, nil, map[int][]string{4: {"http://" + silent.Addr().String()}, 6: {v6}}))
	if err == nil || !strings.Contains(err.Error(), "IPv4") || !slices.Equal(got, []string{"2001:db8::7"}) {
		t.Errorf("http, a family hanging: got %v, %v, want the IPv6 address and the IPv4 error", got, err)
	}

	const name = "myip.example."
	mute, err := net.ListenPacket("udp4", "127.0.0.1:0") // takes the queries, and never answers
	if err != nil {
		t.Fatal(err)
	}
	defer mute.Close()
	a := dnsServer(t, "udp4", name, netip.MustParseAddr("203.0.113.7"))
	got, err = fetch(dnsFetcher([]int{4}, []resolver{
		{name: name, servers: map[int]string{4: mute.LocalAddr().String()}},
		{name: name, servers: map[int]string{6: "[::1]:53"}}, // not of the family: no share of the time
		{name: name, servers: map[int]string{4: a}},
	}))
	if err != nil || !slices.Equal(got, []string{"203.0.113.7"}) {
		t.Errorf("dns: got %v, %v, want the second resolver's answer", got, err)
	}
}

func TestAttempt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for left, want := range map[int]time.Duration{3: 20 * time.Second, 2: 30 * time.Second, 1: time.Minute, 0: time.Minute} {
		actx, cancel := attempt(ctx, left)
		deadline, _ := actx.Deadline()
		if got := time.Until(deadline); got > want || got < want-time.Second {
			t.Errorf("%d left of a minute: %s, want %s", left, got, want)
		}
		cancel()
	}
	actx, cancel := attempt(context.Background(), 3)
	defer cancel()
	if _, ok := actx.Deadline(); ok {
		t.Error("a deadline of a run without one")
	}
}

func TestRunTimeout(t *testing.T) {
	for interval, want := range map[time.Duration]time.Duration{
		time.Second:      500 * time.Millisecond, // the least the configuration takes
		2 * time.Second:  time.Second,
		10 * time.Second: 9 * time.Second,
		time.Minute:      59 * time.Second,
		5 * time.Minute:  time.Minute,
	} {
		s := &Source{}
		s.config.Interval.Duration = interval
		if got := s.runTimeout(); got != want {
			t.Errorf("interval %s: %s, want %s", interval, got, want)
		}
	}
}

// Trigger runs the source once more: before it starts or during a run, several times or one.
func TestTrigger(t *testing.T) {
	cfg := config.Source{Type: config.SourceStatic}
	cfg.Interval.Duration, cfg.Lifetime.Duration = time.Hour, time.Hour
	fetching, release := make(chan struct{}), make(chan struct{})
	s := &Source{name: "test", config: cfg, addrs: ipv6disc.NewAddrCollection(), trigger: make(chan struct{}, 1),
		fetch: func(context.Context) ([]netip.Addr, error) {
			fetching <- struct{}{}
			<-release
			return nil, nil
		}}
	runs := func() int { return s.Status(false).Runs }
	next := func(what string) {
		t.Helper()
		select {
		case <-fetching:
		case <-time.After(3 * time.Second):
			t.Fatalf("%s: no run", what)
		}
	}
	none := func(what string) {
		t.Helper()
		select {
		case <-fetching:
			t.Fatalf("%s: a run", what)
		case <-time.After(100 * time.Millisecond):
		}
	}

	s.Trigger() // before it starts: kept
	s.Trigger()
	ctx, cancel := context.WithCancel(context.Background())
	ran := make(chan struct{}, 10)
	s.Start(ctx, zap.NewNop().Sugar(), func() { ran <- struct{}{} })
	next("the start")
	s.Trigger() // during a run: one more, for the three
	s.Trigger()
	release <- struct{}{}
	next("triggered")
	release <- struct{}{}
	none("triggers already served")
	if got := runs(); got != 2 {
		t.Errorf("%d runs, want 2", got)
	}

	// Stopped during a run: no failure, nothing told, and it ends.
	s.Trigger()
	next("triggered again")
	for len(ran) > 0 {
		<-ran
	}
	cancel()
	close(release)
	done := make(chan struct{})
	go func() { s.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the source did not stop")
	}
	if st := s.Status(false); st.Runs != 2 || st.Failures != 0 || len(ran) != 0 {
		t.Errorf("stopped during a run: %+v, told of %d runs", st, len(ran))
	}
}

// Addresses with a zone, or IPv4 ones written as IPv6, as a command, a list or an entity can give:
// each is one address, whatever its form, and goes when no longer given.
func TestSourceRunAddressForms(t *testing.T) {
	cfg := config.Source{Type: config.SourceStatic}
	cfg.Interval.Duration, cfg.Lifetime.Duration = time.Hour, 3*time.Hour
	var give []netip.Addr
	s := &Source{name: "test", config: cfg, addrs: ipv6disc.NewAddrCollection(), trigger: make(chan struct{}, 1),
		fetch: func(context.Context) ([]netip.Addr, error) { return give, nil }}
	run := func(addrs ...string) []string {
		give = nil
		for _, a := range addrs {
			give = append(give, netip.MustParseAddr(a))
		}
		s.run(context.Background(), zap.NewNop().Sugar())
		var got []string
		for _, a := range s.Addresses().Get() {
			got = append(got, a.Addr.String())
		}
		slices.Sort(got)
		return got
	}
	// One address by zone: the collection knows it without, and keeps the first form given.
	want := []string{"::ffff:192.0.2.1", "fe80::1%eth0"}
	if got := run("fe80::1%eth0", "::ffff:192.0.2.1", "fe80::1%eth1"); !slices.Equal(got, want) {
		t.Errorf("first: %v, want %v", got, want)
	}
	if got := run("fe80::1%eth1", "::ffff:192.0.2.1"); !slices.Equal(got, want) {
		t.Errorf("given again, under another zone: %v, want %v kept", got, want)
	}
	if got := run("2001:db8::1"); !slices.Equal(got, []string{"2001:db8::1"}) {
		t.Errorf("no longer given: %v, want the new one alone", got)
	}
}

func TestSourceKeepsAddressesForTheirLifetime(t *testing.T) {
	cfg := config.Source{Type: config.SourceStatic, Addresses: []string{"192.0.2.1"}}
	cfg.Interval.Duration = time.Hour
	cfg.Lifetime.Duration = 50 * time.Millisecond
	s, err := New("fixed", cfg, "", "", nil)
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

// A run cut by the stop is no failure, and takes no address away; one cut by its own timeout is.
func TestRunCutByTheStop(t *testing.T) {
	cfg := config.Source{Type: config.SourceStatic, Addresses: []string{"192.0.2.1"}}
	cfg.Interval.Duration, cfg.Lifetime.Duration = time.Hour, time.Hour
	s, err := New("fixed", cfg, t.TempDir(), t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	logger := zap.NewNop().Sugar()
	s.run(context.Background(), logger)

	s.fetch = func(ctx context.Context) ([]netip.Addr, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	s.run(ctx, logger)
	if status := s.Status(true); status.Runs != 1 || status.Failures != 0 || len(s.Addresses().Get()) != 1 {
		t.Errorf("after a run cut by the stop: %+v, addresses %v", status, s.Addresses().Get())
	}

	cfg.Interval.Duration = 20 * time.Millisecond // the run has half of it
	s.config = cfg
	s.run(context.Background(), logger)
	if status := s.Status(true); status.Runs != 2 || status.Failures != 1 || len(s.Addresses().Get()) != 1 {
		t.Errorf("after a run that timed out: %+v, addresses %v", status, s.Addresses().Get())
	}
}

func TestStatusHidesTheError(t *testing.T) {
	cfg := config.Source{Type: config.SourceCommand, Command: "sh", Args: []string{"-c", "echo token=SECRET >&2; exit 1"}}
	cfg.Interval.Duration = time.Hour
	cfg.Lifetime.Duration = time.Hour
	s, _ := New("cmd", cfg, t.TempDir(), t.TempDir(), nil)
	s.run(context.Background(), zap.NewNop().Sugar())
	if got := s.Status(true); got.LastError != "<sensible data hidden>" || got.Failures != 1 {
		t.Errorf("hidden: %+v", got)
	}
	if got := s.Status(false); !strings.Contains(got.LastError, "SECRET") {
		t.Errorf("shown: %+v", got)
	}
}

// A run that works replaces the addresses; one that fails keeps them, for their lifetime.
func TestSourceRunReplacesWhatChanged(t *testing.T) {
	cfg := config.Source{Type: config.SourceStatic}
	cfg.Interval.Duration, cfg.Lifetime.Duration = time.Hour, 3*time.Hour
	var give []netip.Addr
	var fail error
	s := &Source{name: "test", config: cfg, addrs: ipv6disc.NewAddrCollection(), trigger: make(chan struct{}, 1),
		fetch: func(context.Context) ([]netip.Addr, error) { return give, fail }}
	run := func(err error, addrs ...string) []string {
		give, fail = nil, err
		for _, a := range addrs {
			give = append(give, netip.MustParseAddr(a))
		}
		s.run(context.Background(), zap.NewNop().Sugar())
		got := s.Addresses().Strings()
		slices.Sort(got)
		return got
	}
	if got := run(nil, "203.0.113.7"); !slices.Equal(got, []string{"203.0.113.7"}) {
		t.Errorf("first: %v", got)
	}
	if got := run(nil, "198.51.100.9"); !slices.Equal(got, []string{"198.51.100.9"}) {
		t.Errorf("the address changed: %v, want the new one alone", got)
	}
	if got := run(errors.New("down")); !slices.Equal(got, []string{"198.51.100.9"}) {
		t.Errorf("a failed run: %v, want the last kept", got)
	}
	if got := run(errors.New("IPv6: down"), "198.51.100.10"); !slices.Equal(got, []string{"198.51.100.10", "198.51.100.9"}) {
		t.Errorf("a run failed for a part: %v, want both kept", got)
	}
}

// A wait, as for Home Assistant while it restarts: no failure, the addresses kept for their
// lifetime; logged when it starts, when it outlasts the lifetime, and when it ends, and not in
// between.
func TestSourceWaits(t *testing.T) {
	cfg := config.Source{Type: config.SourceHomeAssistant}
	cfg.Interval.Duration, cfg.Lifetime.Duration = time.Hour, 100*time.Millisecond
	var give []netip.Addr
	var fail error
	s := &Source{name: "ha", config: cfg, addrs: ipv6disc.NewAddrCollection(), trigger: make(chan struct{}, 1),
		fetch: func(context.Context) ([]netip.Addr, error) { return give, fail }}
	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core).Sugar()
	run := func(err error, addrs ...string) {
		give, fail = nil, err
		for _, a := range addrs {
			give = append(give, netip.MustParseAddr(a))
		}
		s.run(context.Background(), logger)
	}
	logged := func() []string {
		var got []string
		for _, e := range logs.TakeAll() {
			if e.Level > zap.DebugLevel {
				got = append(got, e.Level.String()+": "+e.Message)
			}
		}
		return got
	}
	wait := fmt.Errorf("%w for Home Assistant to connect", ErrWaiting)

	run(nil, "203.0.113.7")
	run(wait)
	run(wait)
	if got := s.Addresses().Strings(); !slices.Equal(got, []string{"203.0.113.7"}) {
		t.Errorf("waiting: %v, want the address kept", got)
	}
	if st := s.Status(false); st.Failures != 0 || !strings.Contains(st.LastError, "waiting for Home Assistant") {
		t.Errorf("waiting: %+v", st)
	}
	if got := logged(); len(got) != 1 || !strings.HasPrefix(got[0], "info: source ha: waiting for Home Assistant to connect; its addresses stay") {
		t.Errorf("two waits logged %q, want the start once", got)
	}

	time.Sleep(150 * time.Millisecond)
	run(wait)
	run(wait)
	if got := s.Addresses().Strings(); len(got) != 0 {
		t.Errorf("after its lifetime: %v", got)
	}
	if got := logged(); len(got) != 1 || !strings.HasPrefix(got[0], "warn: source ha: still waiting for Home Assistant to connect after its lifetime") {
		t.Errorf("past its lifetime logged %q, want one warning", got)
	}

	run(nil, "203.0.113.8")
	if got := logged(); len(got) != 1 || got[0] != "info: source ha: done waiting: [203.0.113.8]" {
		t.Errorf("the end logged %q", got)
	}
	run(errors.New("broken"))
	if got := logged(); len(got) != 1 || got[0] != "error: source ha: broken" || s.Status(false).Failures != 1 {
		t.Errorf("a failure logged %q, %d failures", got, s.Status(false).Failures)
	}
}
