package resolver

import (
	"net"
	"net/netip"
	"testing"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/listen"
)

func TestOverlap(t *testing.T) {
	for _, c := range []struct{ a, b, want string }{
		{"127.0.0.1:53", "127.0.0.1:53", "127.0.0.1:53"},
		{"127.0.0.1:53", "127.0.0.1:5353", ""},
		{"127.0.0.1:53", "127.0.0.2:53", ""},
		{"[::1]:53", "[0:0:0:0:0:0:0:1]:53", "[::1]:53"},
		// A port alone is every address, of both families.
		{":53", "127.0.0.1:53", "127.0.0.1:53"},
		{"[fd00::2]:53", ":53", "[fd00::2]:53"},
		{":53", ":53", ":53"},
		{":53", "0.0.0.0:53", "0.0.0.0:53"},
		{":53", ":54", ""},
		// Every address of a family, and one of it; not one of the other.
		{"0.0.0.0:53", "192.168.1.2:53", "192.168.1.2:53"},
		{"[fd00::2]:53", "[::]:53", "[fd00::2]:53"},
		{"0.0.0.0:53", "[fd00::2]:53", ""},
		{"[::]:53", "192.168.1.2:53", ""},
		{"0.0.0.0:53", "[::]:53", ""},
	} {
		if got := overlap(c.a, c.b); got != c.want {
			t.Errorf("%s and %s: %q, want %q", c.a, c.b, got, c.want)
		}
		if got := overlap(c.b, c.a); (got == "") != (c.want == "") {
			t.Errorf("%s and %s: %q, want %q", c.b, c.a, got, c.want)
		}
	}
}

// Two resolvers whose entries are two spellings of one address and port are told at the start,
// before either listens: each entry is quoted as written.
func TestCheckListen(t *testing.T) {
	loopback := netip.MustParsePrefix("127.0.0.0/8")
	// What localhost is, here: its first address is the one told.
	local, err := net.LookupHost("localhost")
	if err != nil || len(local) == 0 {
		t.Fatalf("localhost: %v %v", local, err)
	}
	type entries struct {
		listen []listen.Entry
		lines  []string
	}
	server := func(name string, e entries) *Server {
		t.Helper()
		cfg, _ := testConfig(t, "192.0.2.1:53")
		cfg.Name, cfg.Path, cfg.Listen, cfg.ListenLines = name, "resolvers."+name, e.listen, e.lines
		s, err := New(cfg, nil)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	for _, c := range []struct {
		name     string
		lab, lan entries
		want     string
	}{
		{"a network and an address in it",
			entries{[]listen.Entry{{Network: loopback, Port: "53"}}, []string{"127.0.0.0/8"}},
			entries{[]listen.Entry{{Host: "127.0.0.1", Port: "53"}}, []string{"127.0.0.1"}},
			"resolvers lab and lan both listen on 127.0.0.1:53: lab as 127.0.0.0/8, lan as 127.0.0.1: an address and port is one resolver's"},
		{"a host name and its address",
			entries{[]listen.Entry{{Host: "10.255.255.1", Port: "53"}, {Host: local[0], Port: "5353"}}, []string{"10.255.255.1", local[0] + ":5353"}},
			entries{[]listen.Entry{{Host: "localhost", Port: "5353"}}, []string{"localhost:5353"}},
			"resolvers lab and lan both listen on " + net.JoinHostPort(local[0], "5353") + ": lab as " + local[0] + ":5353, lan as localhost:5353: an address and port is one resolver's"},
		{"a port alone and an address",
			entries{[]listen.Entry{{Port: "5353"}}, []string{"5353"}},
			entries{[]listen.Entry{{Host: "127.0.0.1", Port: "5353"}}, []string{"127.0.0.1:5353"}},
			"resolvers lab and lan both listen on 127.0.0.1:5353: lab as 5353, lan as 127.0.0.1:5353: an address and port is one resolver's"},
		{"an IPv6 address and a port alone",
			entries{[]listen.Entry{{Host: "::1", Port: "53"}}, []string{"[::1]"}},
			entries{[]listen.Entry{{Port: "53"}}, []string{":53"}},
			"resolvers lab and lan both listen on [::1]:53: lab as [::1], lan as :53: an address and port is one resolver's"},
		{"two ports alone, spelled apart",
			entries{[]listen.Entry{{Port: "53"}}, []string{"53"}},
			entries{[]listen.Entry{{Port: "53"}}, []string{":53"}},
			"resolvers lab and lan both listen on every address, port 53: lab as 53, lan as :53: an address and port is one resolver's"},
		{"every IPv4 address and a network",
			entries{[]listen.Entry{{Host: "0.0.0.0", Port: "53"}}, []string{"0.0.0.0"}},
			entries{[]listen.Entry{{Network: loopback, Port: "53"}}, []string{"127.0.0.0/8"}},
			"resolvers lab and lan both listen on 127.0.0.1:53: lab as 0.0.0.0, lan as 127.0.0.0/8: an address and port is one resolver's"},
		// With no text of the entries, as they read.
		{"entries without their text",
			entries{[]listen.Entry{{Network: loopback, Port: "53"}}, nil},
			entries{[]listen.Entry{{Host: "127.0.0.1", Port: "53"}}, nil},
			"resolvers lab and lan both listen on 127.0.0.1:53: lab as 127.0.0.0/8 port 53, lan as 127.0.0.1:53: an address and port is one resolver's"},
		{"a network with no address of the machine",
			entries{[]listen.Entry{{Network: netip.MustParsePrefix("203.0.113.0/24"), Port: "53"}}, []string{"203.0.113.0/24"}},
			entries{[]listen.Entry{{Host: "127.0.0.1", Port: "53"}}, []string{"127.0.0.1"}},
			"resolvers.lab.listen: 203.0.113.0/24: no address of the machine in it"},
		{"other ports",
			entries{[]listen.Entry{{Network: loopback, Port: "53"}}, nil},
			entries{[]listen.Entry{{Host: "127.0.0.1", Port: "5353"}, {Port: "54"}}, nil}, ""},
		{"other families",
			entries{[]listen.Entry{{Host: "::", Port: "53"}}, nil},
			entries{[]listen.Entry{{Host: "127.0.0.1", Port: "53"}, {Host: "0.0.0.0", Port: "53"}}, nil}, ""},
		{"one resolver's own entries",
			entries{[]listen.Entry{{Network: loopback, Port: "53"}, {Host: "127.0.0.1", Port: "53"}, {Port: "53"}}, nil},
			entries{[]listen.Entry{{Host: "127.0.0.1", Port: "5353"}}, nil}, ""},
		// Any free port, as the tests ask: never another's.
		{"port 0",
			entries{[]listen.Entry{{Host: "127.0.0.1", Port: "0"}}, nil},
			entries{[]listen.Entry{{Host: "127.0.0.1", Port: "0"}}, nil}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := CheckListen([]*Server{server("lab", c.lab), server("lan", c.lan)})
			switch {
			case c.want == "" && err != nil:
				t.Errorf("got %v, want no error", err)
			case c.want != "" && (err == nil || err.Error() != c.want):
				t.Errorf("got %v\nwant %s", err, c.want)
			}
		})
	}
	if err := CheckListen(nil); err != nil {
		t.Error(err)
	}
}
