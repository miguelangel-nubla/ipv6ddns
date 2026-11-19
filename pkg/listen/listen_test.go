package listen

import (
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"
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

func TestParseRefuses(t *testing.T) {
	for _, list := range []string{"0", "65536", "192.0.2.1:0", "myhost:http", "192.0.2.1,", ",", "[2001:db8::1", "2001:db8::1]:80", "a:b:c",
		"10.2.3.0/33", "10.2.3.0/24:8053", "myhost/24"} {
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
			if n, err := strconv.Atoi(e.Port); err != nil || n < 1 || n > 65535 {
				t.Errorf("%q gives %v, with an invalid port", list, e)
			}
			if !e.Network.IsValid() {
				if _, _, err := net.SplitHostPort(net.JoinHostPort(e.Host, e.Port)); err != nil {
					t.Errorf("%q gives %v: %v", list, e, err)
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
