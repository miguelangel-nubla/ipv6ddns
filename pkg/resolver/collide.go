package resolver

import (
	"fmt"
	"net"
	"net/netip"
	"slices"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/listen"
)

// bound is an address a resolver's entry listens on.
type bound struct {
	resolver string
	// The entry, as written.
	entry string
	// host:port: the host "" for every address, of both families.
	address string
	// The protocols it listens over: plain DNS's are UDP and TCP.
	protocols []string
	// Of an entry that listeners share, its socket, by sharedKey: those of one are no collision.
	shared string
}

// Protocol is the protocol of IP a transport listens over: TCP for DNS over TLS and over HTTPS,
// UDP for DNS over QUIC.
func Protocol(transport string) string {
	if transport == TransportQUIC {
		return "udp"
	}
	return "tcp"
}

// overlap is the address that a and b both listen on, host:port, or "" for none: of the same port,
// the same address; or one every address, a port alone, and the other any; or one every address
// of a family, 0.0.0.0 or ::, and the other an address of it.
func overlap(a, b string) string {
	ha, pa, _ := net.SplitHostPort(a)
	hb, pb, _ := net.SplitHostPort(b)
	if pa != pb {
		return ""
	}
	if ha == hb {
		return a
	}
	if ha == "" {
		return b
	}
	if hb == "" {
		return a
	}
	ia, errA := netip.ParseAddr(ha)
	ib, errB := netip.ParseAddr(hb)
	if errA != nil || errB != nil {
		return ""
	}
	ia, ib = ia.Unmap(), ib.Unmap()
	switch {
	case ia == ib:
		return a
	case ia.Is4() != ib.Is4():
		return ""
	case ia.IsUnspecified():
		return b
	case ib.IsUnspecified():
		return a
	}
	return ""
}

// Overlap is overlap, for the configuration's check of the entries listeners share.
func Overlap(a, b string) string { return overlap(a, b) }

// CheckListen tells of two resolvers that would listen on one address and port, however their
// entries spell it: a network and an address in it, a host name and its address, a port alone and
// any address. Each entry is read as Start reads it, before anything listens. The entries of one
// socket that listeners share, as Share has them, are none.
func CheckListen(servers []*Server) error {
	var all []bound
	for _, s := range servers {
		add := func(e listen.Entry, text, transport string, shared bool, protocols ...string) error {
			addresses, err := listen.Addresses([]listen.Entry{e})
			if err != nil {
				return fmt.Errorf("%s: %w", s.config.Path, err)
			}
			for _, a := range addresses {
				// Any port that is free: never another's.
				if _, port, _ := net.SplitHostPort(a); port == "0" {
					continue
				}
				b := bound{resolver: s.config.Name, entry: text, address: a, protocols: protocols}
				if shared {
					b.shared = sharedKey(transport, a)
				}
				all = append(all, b)
			}
			return nil
		}
		for i, e := range s.config.Listen {
			text := e.String()
			if i < len(s.config.ListenLines) {
				text = s.config.ListenLines[i]
			}
			if err := add(e, text, "", false, "udp", "tcp"); err != nil {
				return err
			}
		}
		for _, e := range s.config.Encrypted {
			if err := add(e.Entry, e.Line, e.Transport, e.Shared, Protocol(e.Transport)); err != nil {
				return err
			}
		}
	}
	for i, a := range all {
		for _, b := range all[i+1:] {
			if a.resolver == b.resolver || a.shared != "" && a.shared == b.shared || !slices.ContainsFunc(a.protocols, func(p string) bool { return slices.Contains(b.protocols, p) }) {
				continue
			}
			if at := overlap(a.address, b.address); at != "" {
				shown := at
				if host, port, _ := net.SplitHostPort(at); host == "" {
					shown = "every address, port " + port
				}
				return fmt.Errorf("resolvers %s and %s both listen on %s: %s as %s, %s as %s: an address and port can belong to only one resolver", a.resolver, b.resolver, shown, a.resolver, a.entry, b.resolver, b.entry)
			}
		}
	}
	return nil
}
