package listen

import (
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	for _, tt := range []struct {
		list string
		want string
	}{
		{"8053", ":8053"},
		{":8053", ":8053"},
		{"192.0.2.1", "192.0.2.1:80"},
		{"192.0.2.1:8053", "192.0.2.1:8053"},
		{"2001:db8::1", "[2001:db8::1]:80"},
		{"[2001:db8::1]", "[2001:db8::1]:80"},
		{"[2001:db8::1]:8053", "[2001:db8::1]:8053"},
		{"myhost", "myhost:80"},
		{"myhost:8053", "myhost:8053"},
		{"fe80::1%eth0", "[fe80::1%eth0]:80"},
		{"10.2.3.9/24", "10.2.3.0/24 port 80"},
		{"fd00::1/64", "fd00::/64 port 80"},
		{"192.0.2.1, [2001:db8::1]:8053 ,myhost,9000", "192.0.2.1:80 [2001:db8::1]:8053 myhost:80 :9000"},
		{"8053,:8053", ":8053"},
		// One spelling of a port, so the repeated are told.
		{"8053,08053,:08053", ":8053"},
		{"192.0.2.1:08053,192.0.2.1:8053", "192.0.2.1:8053"},
		{"0.0.0.0:8053,[::]:8053", "0.0.0.0:8053 [::]:8053"},
		// One spelling of an address too, with a port or without.
		{"[0:0:0:0:0:0:0:1]:8053", "[::1]:8053"},
		{"[2001:DB8::1]:8053", "[2001:db8::1]:8053"},
		{"2001:0db8:0::0001", "[2001:db8::1]:80"},
		{"[FE80::1%eth0]:8053", "[fe80::1%eth0]:8053"},
		// An IPv4-mapped address is the IPv4 one it holds, which is the socket it opens.
		{"::ffff:192.0.2.1", "192.0.2.1:80"},
		{"[::ffff:192.0.2.1]:8053", "192.0.2.1:8053"},
		{"[::ffff:c000:201]:8053", "192.0.2.1:8053"},
		// A host name is as written: its case is the resolver's to tell.
		{"MyHost:8053", "MyHost:8053"},
		// Only its syntax is read here: what isn't an address is a host name, resolved at start.
		{"1.2.3", "1.2.3:80"},
	} {
		entries, err := Parse(strings.Split(tt.list, ","), "80")
		if err != nil {
			t.Errorf("%q: %v", tt.list, err)
			continue
		}
		var got []string
		for _, e := range entries {
			got = append(got, e.String())
		}
		if strings.Join(got, " ") != tt.want {
			t.Errorf("%q: %q, want %q", tt.list, got, tt.want)
		}
	}
}

// One address in two spellings is one entry, and one address to listen on: not two, of which the
// second finds the first's socket.
func TestSpellings(t *testing.T) {
	for _, list := range [][]string{
		{"[::1]:8053", "[0:0:0:0:0:0:0:1]:8053"},
		{"::1", "[0:0::1]:80"},
		{"[2001:db8::1]:8053", "[2001:DB8::1]:8053"},
		{"127.0.0.1", "[::ffff:127.0.0.1]:80"},
		{"127.0.0.1:8053", "[::ffff:7f00:1]:8053", "[0:0:0:0:0:ffff:127.0.0.1]:08053"},
	} {
		entries, err := Parse(list, "80")
		if err != nil {
			t.Errorf("%q: %v", list, err)
			continue
		}
		if len(entries) != 1 {
			t.Errorf("%q: the entries %v, one address twice", list, entries)
		}
		addresses, err := Addresses(entries)
		if err != nil {
			t.Errorf("%q: %v", list, err)
			continue
		}
		if len(addresses) != 1 {
			t.Errorf("%q: listens on %q, one address twice", list, addresses)
		}
	}
	// Entries made without Parse, as each of a listener's is given alone, are told too.
	a, _ := Addresses([]Entry{{Host: "0:0::1", Port: "8053"}})
	b, _ := Addresses([]Entry{{Host: "::1", Port: "8053"}})
	if len(a) != 1 || len(b) != 1 || a[0] != b[0] {
		t.Errorf("one address in two spellings, an entry each: %q and %q", a, b)
	}
	// Two addresses stay two.
	if entries, _ := Parse([]string{"[::1]:8053", "127.0.0.1:8053", "[::]:8053", "0.0.0.0:8053"}, "80"); len(entries) != 4 {
		t.Errorf("four addresses: %v", entries)
	}
}

// And it listens: once.
func TestListenSpellings(t *testing.T) {
	entries, err := Parse([]string{"127.0.0.1:18653", "[::ffff:127.0.0.1]:18653", "[::ffff:7f00:1]:18653"}, "80")
	if err != nil {
		t.Fatal(err)
	}
	listeners, err := Listen(entries)
	if err != nil {
		t.Fatalf("one address in three spellings doesn't listen: %v", err)
	}
	for _, l := range listeners {
		l.Close()
	}
	if len(listeners) != 1 {
		t.Errorf("%d listeners, want 1", len(listeners))
	}
}

func TestParseRefuses(t *testing.T) {
	for _, list := range []string{"0", "65536", "192.0.2.1:0", "myhost:http", "192.0.2.1,", ",", "[2001:db8::1", "2001:db8::1]:80", "a:b:c",
		"10.2.3.0/33", "10.2.3.0/24:8053", "myhost/24", "+8053", "-8053", "192.0.2.1:+8053", "myhost:-1", "192.0.2.1:65536",
		// A zone can hold anything, a bracket too: what doesn't read back as it was given.
		"::%]"} {
		if got, err := Parse(strings.Split(list, ","), "80"); err == nil {
			t.Errorf("%q: %v, want an error", list, got)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"8053", "192.0.2.1,[2001:db8::1]:8053", "myhost", "fe80::1%eth0", ",", "a:b:c", "10.0.0.0/8"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, list string) {
		entries, err := Parse(strings.Split(list, ","), "80")
		if err != nil {
			return
		}
		for _, e := range entries {
			if n, err := strconv.Atoi(e.Port); err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != e.Port {
				t.Errorf("%q gives %v, with an invalid port", list, e)
			}
			if !e.Network.IsValid() {
				if _, _, err := net.SplitHostPort(net.JoinHostPort(e.Host, e.Port)); err != nil {
					t.Errorf("%q gives %v: %v", list, e, err)
				} // An address is in its one spelling.
				if ip, err := netip.ParseAddr(e.Host); err == nil && (ip.String() != e.Host || ip.Is4In6() && ip.Zone() == "") {
					t.Errorf("%q gives %v, an address in another spelling than %s", list, e, ip)
				}
			}
		}
	})
}

func TestListen(t *testing.T) {
	// localhost resolves to 127.0.0.1 here too: one listener each, not an error for the repeat.
	entries, err := Parse([]string{"127.0.0.1:18996", "127.0.0.1:18997", "localhost:18996"}, "80")
	if err != nil {
		t.Fatal(err)
	}
	listeners, err := Listen(entries)
	if err != nil {
		t.Fatal(err)
	}
	if len(listeners) < 2 {
		t.Fatalf("got %d listeners, want at least 2", len(listeners))
	}
	for _, l := range listeners {
		defer l.Close()
		go http.Serve(l, http.NotFoundHandler())
		response, err := http.Get("http://" + l.Addr().String() + "/")
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
	}
	if _, err := Listen(entries[:1]); err == nil {
		t.Error("listening twice on one address: want an error")
	}
	ifaces, all, err := Interfaces(listeners)
	if err != nil || all || len(ifaces) != 1 || ifaces[0].Flags&net.FlagLoopback == 0 {
		t.Errorf("the interfaces of 127.0.0.1: %v, all %v, %v", ifaces, all, err)
	}
}

// A network: each address of the machine in it, and only those.
func TestListenNetwork(t *testing.T) {
	entries, err := Parse([]string{"127.0.0.0/8"}, "18998")
	if err != nil {
		t.Fatal(err)
	}
	addresses, err := Addresses(entries)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addresses {
		host, port, _ := net.SplitHostPort(a)
		if ip, err := netip.ParseAddr(host); err != nil || !ip.IsLoopback() || port != "18998" {
			t.Errorf("127.0.0.0/8 gives %s", a)
		}
	}
	if len(addresses) == 0 {
		t.Error("127.0.0.0/8: no address")
	}
	if _, err := Addresses([]Entry{{Network: netip.MustParsePrefix("192.0.2.200/32"), Port: "80"}}); err == nil {
		t.Error("a network the machine has no address in: want an error")
	}
}

func TestInterfacesAll(t *testing.T) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, all, err := Interfaces([]net.Listener{l}); err != nil || !all {
		t.Errorf("listening on all addresses: all %v, %v", all, err)
	}
}

// freePort is a port nothing listens on, on any address.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_, port, _ := net.SplitHostPort(l.Addr().String())
	return port
}

// 0.0.0.0 is the IPv4 addresses and [::] the IPv6 ones: both can be listed, and one alone doesn't
// listen on the other family. Go alone would have either be both, where the system does, as Linux.
func TestListenFamilies(t *testing.T) {
	if l, err := net.Listen("tcp6", "[::1]:0"); err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	} else {
		l.Close()
	}
	listenFamilies(t, "127.0.0.1", "::1")
}

// listenFamilies checks which of two addresses of the machine's, an IPv4 one and an IPv6 one,
// each list of entries is reached at.
func listenFamilies(t *testing.T, ipv4, ipv6 string) {
	port := freePort(t)
	for _, c := range []struct {
		entries    []string
		listeners  int
		ipv4, ipv6 bool
		all        bool
	}{
		{[]string{"0.0.0.0:" + port}, 1, true, false, true},
		{[]string{"[::]:" + port}, 1, false, true, true},
		{[]string{"0.0.0.0:" + port, "[::]:" + port}, 2, true, true, true},
		{[]string{"[::]:" + port, "0.0.0.0:" + port}, 2, true, true, true},
		// A port alone is both, with one socket, where the system has those: Linux, unless its
		// net.ipv6.bindv6only was set.
		{[]string{port}, 1, true, true, true},
		{[]string{ipv4 + ":" + port}, 1, true, false, false},
		{[]string{"[" + ipv6 + "]:" + port}, 1, false, true, false},
		{[]string{ipv4 + ":" + port, "[" + ipv6 + "]:" + port}, 2, true, true, false},
	} {
		entries, err := Parse(c.entries, "80")
		if err != nil {
			t.Fatal(err)
		}
		listeners, err := Listen(entries)
		if err != nil {
			t.Errorf("%v: %v", c.entries, err)
			continue
		}
		if len(listeners) != c.listeners {
			t.Errorf("%v: %d listeners, want %d", c.entries, len(listeners), c.listeners)
		}
		if _, all, err := Interfaces(listeners); err != nil || all != c.all {
			t.Errorf("%v: all addresses %v, %v, want %v", c.entries, all, err, c.all)
		}
		for address, want := range map[string]bool{ipv4: c.ipv4, ipv6: c.ipv6} {
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(address, port), 5*time.Second)
			if err == nil {
				conn.Close()
			}
			if got := err == nil; got != want {
				t.Errorf("%v: reached at %s: %v, want %v (%v)", c.entries, address, got, want, err)
			}
		}
		for _, l := range listeners {
			l.Close()
		}
	}
}

// An address that can't be listened on closes those opened before it.
func TestListenClosesOnFailure(t *testing.T) {
	taken, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	port := freePort(t)
	entries, err := Parse([]string{"127.0.0.1:" + port, taken.Addr().String()}, "80")
	if err != nil {
		t.Fatal(err)
	}
	if listeners, err := Listen(entries); err == nil {
		t.Fatalf("an address in use: got %d listeners, want an error", len(listeners))
	}
	again, err := Listen(entries[:1])
	if err != nil {
		t.Fatalf("the first address was left open: %v", err)
	}
	again[0].Close()
}

func TestHolds(t *testing.T) {
	linkLocal := []net.Addr{&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)}}
	lan := net.Interface{Index: 2, Name: "eth0"}
	vlan := net.Interface{Index: 7, Name: "eth0.10"}
	for _, tt := range []struct {
		zone      string
		lan, vlan bool
	}{
		{"", true, true}, // no zone: by the address alone
		{"eth0", true, false},
		{"eth0.10", false, true},
		{"7", false, true}, // an interface Go has no name of
		{"eth1", false, false},
	} {
		tcp := &net.TCPAddr{IP: net.ParseIP("fe80::1"), Port: 6053, Zone: tt.zone}
		if got := holds(lan, linkLocal, tcp); got != tt.lan {
			t.Errorf("zone %q, eth0: %v", tt.zone, got)
		}
		if got := holds(vlan, linkLocal, tcp); got != tt.vlan {
			t.Errorf("zone %q, eth0.10: %v", tt.zone, got)
		}
	}
	if holds(lan, linkLocal, &net.TCPAddr{IP: net.ParseIP("fe80::2")}) {
		t.Error("another address")
	}
}
