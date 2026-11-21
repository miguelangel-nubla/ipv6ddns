//go:build linux && integration

package main

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/miguelangel-nubla/ipv6ddns"
	"github.com/miguelangel-nubla/ipv6ddns/internal/livetest"
)

// The command at work for a while, with everything on that keeps something for a time: hosts
// that come and go, their names by mDNS, a name of a template for each at a resolver and at a
// provider, and clients asking the resolver names of its own, names it forwards and keeps in a
// small cache, and reverses. What it holds stays level: its goroutines, its open files and
// sockets, its memory, and the names of its status, as each is let go of when it is done with.
//
// A minute by default; IPV6DDNS_SOAK is how long, as 15m, for a run of its own.
func TestLiveSoak(t *testing.T) {
	length := time.Minute
	if s := os.Getenv("IPV6DDNS_SOAK"); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			t.Fatalf("IPV6DDNS_SOAK: %v", err)
		}
		length = d
	}
	lan := livetest.NewLAN(t, 23)
	router := lan.Router
	srv := lan.Machine(t, "srv", 10)
	client := lan.Machine(t, "client", 30)
	up := lan.Machine(t, "up", 40)
	var hosts []*livetest.Machine
	for i := range 4 {
		h := lan.Machine(t, fmt.Sprintf("host%d", i), 20+i)
		h.Avahi(t, fmt.Sprintf("host%d", i))
		hosts = append(hosts, h)
	}
	startUpstream(t, up, "192.0.2.53")
	provider := startProvider(t, router, 5391, "token-soak", "soak.example")

	one := configure(t, srv, router, "srv", 8053, fmt.Sprintf(`
webserver:
  listen:
    - 8053
discovery:
  lifetime: 6s
  rediscover: 2s
  protocols:
    mdns:
      enabled: true
resolvers:
  lan:
    listen: 198.18.23.0/24
    upstream: %[1]s
    cache_size: 50
credentials:
  home:
    provider: resolver
    settings:
      zone: home.arpa
%[3]stasks:
  hosts:
    filter:
      - ip:
          prefix: "%[2]s"
    endpoints:
      home:
        - "{hostname}"
        - "{n}.{hostname}"
        - "{mac}.by-mac"
      dns:
        - "{hostname}"
`, up.IPv4, lan.Prefix(), provider.credential("dns", "0s"))).start().serving()
	server := srv.IPv4.String() + ":53"

	// ask sends the resolver queries from the client's machine, each on a connection of its own,
	// over UDP and, one in five, TCP: every one is to be answered.
	asked := 0
	ask := func(round int) {
		t.Helper()
		for i := range 60 {
			m := new(dns.Msg)
			switch i % 4 {
			case 0:
				m.SetQuestion(fmt.Sprintf("host%d.home.arpa.", i%len(hosts)), dns.TypeAAAA)
			case 1:
				// A name of its own each time: asked upstream, and kept, in a cache it overflows.
				m.SetQuestion(fmt.Sprintf("r%d-q%d.example.org.", round, i), dns.TypeA)
			case 2:
				reverse, _ := dns.ReverseAddr(hosts[i%len(hosts)].IPv6.String())
				m.SetQuestion(reverse, dns.TypePTR)
			case 3:
				m.SetQuestion("kept.example.org.", dns.TypeA)
			}
			network := "udp4"
			if i%5 == 0 {
				network = "tcp4"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			conn, err := client.Dial(ctx, network, server)
			cancel()
			if err != nil {
				t.Fatalf("round %d, query %d: %v", round, i, err)
			}
			c := &dns.Conn{Conn: conn}
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			if err := c.WriteMsg(m); err != nil {
				t.Fatalf("round %d, query %d: %v", round, i, err)
			}
			resp, err := c.ReadMsg()
			c.Close()
			if err != nil || resp.Id != m.Id {
				t.Fatalf("round %d, query %d, %s over %s: %v, %v\n%s", round, i, m.Question[0].Name, network, err, resp, one.tells())
			}
			asked++
		}
	}
	// sample is what the command holds, once it is at rest: a moment after the last query.
	sample := func() ipv6ddns.ProcessStatus {
		time.Sleep(1500 * time.Millisecond)
		return one.status().Process
	}

	waitFor(t, 60*time.Second, "every host named at the resolver", func() bool {
		for i := range hosts {
			if len(dig(t, client, srv.IPv4.String(), fmt.Sprintf("host%d.home.arpa", i), "AAAA").data("AAAA")) != 1 {
				return false
			}
		}
		return true
	}, one.tells)

	// Each round a host leaves, or the one that left is back, and the clients ask: a round is
	// longer than the lifetime, so the one that left goes, with its names, every time.
	const warmUp = 3
	var base, last ipv6ddns.ProcessStatus
	mostNames := 0
	begun := time.Now()
	round := 0
	for ; time.Since(begun) < length || round < warmUp+2; round++ {
		host := hosts[(round/2)%len(hosts)]
		if round%2 == 0 {
			host.Leave(t)
		} else {
			host.Return(t)
		}
		for part := range 4 {
			ask(round*4 + part)
			time.Sleep(1500 * time.Millisecond)
		}
		last = sample()
		if round == warmUp-1 {
			base = last
		}
		mostNames = max(mostNames, len(one.status().Hostnames))
		t.Logf("round %d, %s: %d goroutines, %d open files, %d KiB of heap, %d names, %d queries", round, time.Since(begun).Round(time.Second), last.Goroutines, last.OpenFiles, last.HeapBytes/1024, len(one.status().Hostnames), asked)
	}

	if base.Goroutines == 0 || base.OpenFiles == 0 || base.HeapBytes == 0 {
		t.Fatalf("the status doesn't tell what the command holds: %+v", base)
	}
	// At rest, as it was after the first rounds: a few more at most, for what a round was in the
	// middle of; not more for every round, or query, there was.
	rounds := round - warmUp
	if last.Goroutines > base.Goroutines+10 {
		t.Errorf("%d goroutines after %d more rounds and %d queries, %d before them", last.Goroutines, rounds, asked, base.Goroutines)
	}
	if last.OpenFiles > base.OpenFiles+8 {
		t.Errorf("%d open files after %d more rounds and %d queries, %d before them", last.OpenFiles, rounds, asked, base.OpenFiles)
	}
	if limit := max(2*base.HeapBytes, base.HeapBytes+16<<20); last.HeapBytes > limit {
		t.Errorf("%d KiB of heap after %d more rounds and %d queries, %d KiB before them", last.HeapBytes/1024, rounds, asked, base.HeapBytes/1024)
	}
	// Each of the four hosts has its name and its numbered one at the resolver, and its name at
	// the provider; and every machine of the link, these and the four others, the name of its
	// MAC. No more names than that, ever, as those of a host that left are forgotten.
	const machines = 8
	if most := 3*len(hosts) + machines; mostNames > most {
		t.Errorf("the status had %d names at most: more than the %d there can be", mostNames, most)
	}
	if st := one.status().Resolvers[0]; st.CacheEntries > 50 || st.Queries["servfail"] != 0 {
		t.Errorf("the resolver: %d answers kept of 50 at most, %d queries failed", st.CacheEntries, st.Queries["servfail"])
	}
	if errs := one.logged("error"); len(errs) > 0 {
		t.Errorf("it logged errors: %v", errs)
	}
}
