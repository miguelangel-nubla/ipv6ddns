//go:build linux && integration

package main

import (
	"fmt"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/internal/livetest"
)

// The command started while its machine is off the link, and the command killed in the middle of
// an update, then started again: it carries on as one that never stopped would, with the records
// at the provider what the peer has, and nothing written twice or left behind.
func TestLiveRestart(t *testing.T) {
	lan := livetest.NewLAN(t, 24)
	router := lan.Router
	srv := lan.Machine(t, "srv", 10)
	peer := lan.Machine(t, "peer", 20)
	dns := startProvider(t, router, 5392, "token-restart", "restart.example")
	const domain = "peer.restart.example"
	config := fmt.Sprintf(`
webservers:
  main:
    listen:
      - 8053
discovery:
  lifetime: 30s
  rediscover: 3s
tasks:
  peer:
    filter:
      - mac:
          address: "%s"
        ip:
          prefix: "%s"
    endpoints:
      dns:
        - peer
credentials:
%s`, peer.MAC, lan.Prefix(), dns.credential("dns", "1s"))

	// Started off the link: no provider, no peer. It runs, and waits.
	srv.Leave(t)
	one := configure(t, srv, router, "srv", 8053, config).start()
	time.Sleep(5 * time.Second)
	select {
	case <-one.exited:
		t.Fatalf("it ended, started off the link: %v\n%s", one.err, one.tells())
	default:
	}
	if writes := dns.changes(); len(writes) != 0 {
		t.Fatalf("written to, off the link: %v", writes)
	}
	// Back: it finds the peer, and writes its record.
	srv.Return(t)
	one.serving()
	waitFor(t, 60*time.Second, "the peer's record, once the link is back", func() bool { return dns.has(domain, peer.IPv6) }, one.tells, dns.tells)

	// The peer moves to another address: the update that follows it is held at the provider, and
	// the command killed meanwhile, as by a power cut, nothing of it let go in order. The write
	// held is then dropped: the records stay as they were before it.
	moved := netip.MustParseAddr("fd00:c612:24::99")
	seen, release := dns.stall(domain)
	peer.IP(t, "addr", "add", moved.String()+"/64", "dev", peer.Interface, "nodad")
	peer.IP(t, "addr", "del", peer.IPv6.String()+"/64", "dev", peer.Interface)
	select {
	case <-seen:
	case <-time.After(60 * time.Second):
		release()
		t.Fatalf("no update of the peer's new address\n%s\n%s", one.tells(), dns.tells())
	}
	one.cmd.Process.Signal(syscall.SIGKILL)
	<-one.exited
	release()
	if !dns.has(domain, peer.IPv6) {
		t.Fatalf("killed in the middle of an update, the records are %v", dns.addresses(domain))
	}

	// Started again: the records are what the peer has, the old one taken off and the new one
	// added, once each.
	before := len(dns.changes())
	one.start().serving()
	waitFor(t, 60*time.Second, "the peer's new record alone, after the restart", func() bool { return dns.has(domain, moved) }, one.tells, dns.tells)
	time.Sleep(3 * time.Second)
	if !dns.has(domain, moved) {
		t.Errorf("the records changed again: %v", dns.addresses(domain))
	}
	after := dns.changes()[before:]
	if len(after) != 2 {
		t.Errorf("the writes after the restart: %v, want the old record deleted and the new one added", after)
	}
	dns.mutex.Lock()
	refused := dns.refusals
	dns.mutex.Unlock()
	if len(refused) != 0 {
		t.Errorf("writes the provider refused, as a record added twice or one deleted that wasn't: %v", refused)
	}

	// And it goes on as before: the peer leaves, and its record goes after its lifetime.
	peer.Leave(t)
	waitFor(t, 90*time.Second, "the peer's record to go once it left", func() bool { return dns.has(domain) }, one.tells, dns.tells)
	one.terminate()
}
