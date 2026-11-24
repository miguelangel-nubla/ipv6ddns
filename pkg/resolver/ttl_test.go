package resolver

import (
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// capTTL is the zone's TTL but where an address expires sooner: then the time left, in whole
// seconds, 1 at least. No expiry, or a zero one, is never.
func TestCapTTL(t *testing.T) {
	now := time.Now()
	at := func(d time.Duration) func() time.Time { return func() time.Time { return now.Add(d) } }
	zero := func() time.Time { return time.Time{} }
	for name, c := range map[string]struct {
		expires []func() time.Time
		want    uint32
	}{
		"none":            {nil, 60},
		"never":           {[]func() time.Time{nil, zero}, 60},
		"later":           {[]func() time.Time{at(time.Hour)}, 60},
		"sooner":          {[]func() time.Time{at(time.Hour), at(42500 * time.Millisecond)}, 42},
		"under a second":  {[]func() time.Time{at(300 * time.Millisecond)}, 1},
		"already expired": {[]func() time.Time{at(-time.Minute)}, 1},
	} {
		if got := capTTL(time.Minute, c.expires, now); got != c.want {
			t.Errorf("%s: %d, want %d", name, got, c.want)
		}
	}
}

// The answer has one TTL, capped by the soonest expiry of its own records alone, asked as it
// answers: an address seen again, which expires later, isn't set again.
func TestAnswerTTLCappedByExpiry(t *testing.T) {
	cfg, addresses := testConfig(t)
	s := start(t, cfg)
	// v4 is moved while the server reads it, from its own goroutine.
	var v4 atomic.Int64
	v4.Store(time.Now().Add(20 * time.Second).UnixNano())
	v6 := time.Now().Add(10 * time.Second)
	addresses.SetExpiring("nas.home.arpa.", []Address{
		{Addr: netip.MustParseAddr("192.168.1.10"), Expires: func() time.Time { return time.Unix(0, v4.Load()) }},
		{Addr: netip.MustParseAddr("192.168.1.11")},
		{Addr: netip.MustParseAddr("fd00::10"), Expires: func() time.Time { return v6 }},
	})
	ttls := func(qtype uint16) []uint32 {
		var got []uint32
		for _, rr := range query(t, s, "udp", "nas.home.arpa.", qtype, nil).Answer {
			got = append(got, rr.Header().Ttl)
		}
		return got
	}
	// The zone's is 30s.
	if got := ttls(dns.TypeA); len(got) != 2 || got[0] != got[1] || got[0] < 18 || got[0] > 20 {
		t.Errorf("A: %v, want 19 or so for both", got)
	}
	if got := ttls(dns.TypeAAAA); len(got) != 1 || got[0] < 8 || got[0] > 10 {
		t.Errorf("AAAA: %v, want 9 or so", got)
	}
	// ANY has both families' addresses: the soonest of all of them.
	if got := ttls(dns.TypeANY); len(got) != 3 || got[0] != got[1] || got[1] != got[2] || got[0] < 8 || got[0] > 10 {
		t.Errorf("ANY: %v, want 9 or so for all three", got)
	}
	v4.Store(time.Now().Add(time.Hour).UnixNano())
	if got := ttls(dns.TypeA); len(got) != 2 || got[0] != 30 || got[1] != 30 {
		t.Errorf("A, seen again: %v, want the zone's, 30", got)
	}
}

// An address given twice expires with the later; never, if either does.
func TestSetExpiringTwice(t *testing.T) {
	now := time.Now()
	a := NewAddresses()
	soon, late := func() time.Time { return now.Add(time.Second) }, func() time.Time { return now.Add(time.Hour) }
	a.SetExpiring("x.", []Address{{Addr: netip.MustParseAddr("fe80::1%eth0"), Expires: soon}, {Addr: netip.MustParseAddr("fe80::1"), Expires: late}})
	if got := a.expiring("x."); len(got) != 1 || !got[0].Expires().Equal(now.Add(time.Hour)) {
		t.Errorf("twice: %v", got)
	}
	a.SetExpiring("x.", []Address{{Addr: netip.MustParseAddr("fe80::1"), Expires: soon}, {Addr: netip.MustParseAddr("fe80::1")}})
	if got := a.expiring("x."); len(got) != 1 || got[0].Expires != nil {
		t.Errorf("once never: %v", got)
	}
}
