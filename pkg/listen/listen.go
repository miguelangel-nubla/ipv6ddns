// Package listen reads where to listen, as the web server and the Home Assistant device take it:
// a list of ports, addresses, networks of the machine's addresses, and host names.
//
//	8053, :8053                         that port, on all addresses, IPv4 and IPv6
//	0.0.0.0:8053, [::]:8053             that port, on all IPv4 addresses, or all IPv6 ones
//	192.0.2.1:8053, [2001:db8::1]:8053  that address and port
//	192.0.2.1, 2001:db8::1              that address, on the default port
//	10.2.3.0/24, fd00::/64              each address of the machine in that network, on the default port
//	myhost:8053, myhost                 each address the name resolves to, at start
//
// Networks and host names are read once, when listening starts: an address the machine gets
// later isn't listened on.
package listen

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Entry is where to listen, of a list.
type Entry struct {
	// An address, a host name, or none, for all addresses. An address is in one spelling, as
	// spelled has it, so the repeated are told.
	Host string
	// Or a network of the machine's addresses, when valid.
	Network netip.Prefix
	// In decimal, with no sign or leading zeros: one spelling, so the repeated are told.
	Port string
}

func (e Entry) String() string {
	if e.Network.IsValid() {
		return e.Network.String() + " port " + e.Port
	}
	return net.JoinHostPort(e.Host, e.Port)
}

// Rules tells the entries a list takes, for errors.
const Rules = "use a port, an address, a network as 10.2.3.0/24, or a host name, each with or without :port"

// Parse reads entries, giving those without a port defaultPort; it drops the repeated, however
// each is written: [::1]:8053 and [0:0:0:0:0:0:0:1]:8053 are one.
func Parse(entries []string, defaultPort string) ([]Entry, error) {
	var result []Entry
	for _, s := range entries {
		e, err := parseEntry(strings.TrimSpace(s), defaultPort)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(result, e) {
			result = append(result, e)
		}
	}
	return result, nil
}

func parseEntry(entry, defaultPort string) (Entry, error) {
	if entry == "" {
		return Entry{}, errors.New("an empty entry: " + Rules)
	}
	// A port alone. Before anything else: a bare number would otherwise be a host name.
	if _, err := strconv.Atoi(entry); err == nil {
		return checked(Entry{Port: entry}, entry)
	}
	if strings.Contains(entry, "/") {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			return Entry{}, fmt.Errorf("%q: write a network as 10.2.3.0/24 or fd00::/64, without a port: it uses the default one", entry)
		}
		return checked(Entry{Network: prefix.Masked(), Port: defaultPort}, entry)
	}
	// An IP address with no port: an IPv6 one, bracketed or not, would confuse SplitHostPort.
	unbracketed := entry
	if strings.HasPrefix(entry, "[") && strings.HasSuffix(entry, "]") {
		unbracketed = entry[1 : len(entry)-1]
	}
	if _, err := netip.ParseAddr(unbracketed); err == nil {
		return checked(Entry{Host: spelled(unbracketed), Port: defaultPort}, entry)
	}
	if host, port, err := net.SplitHostPort(entry); err == nil {
		return checked(Entry{Host: spelled(host), Port: port}, entry)
	}
	if strings.ContainsAny(entry, ":[]") {
		return Entry{}, fmt.Errorf("%q: %s", entry, Rules)
	}
	return checked(Entry{Host: entry, Port: defaultPort}, entry)
}

// spelled is host in its one spelling, when it is an address: 0:0::1 and ::1, or 2001:DB8::1 and
// 2001:db8::1, are one address, which listens once. An IPv4-mapped one, ::ffff:192.0.2.1, is the
// IPv4 address it holds, as network has it: the two are one socket. A host name is as it was.
func spelled(host string) string {
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	if ip.Is4In6() && ip.Zone() == "" {
		ip = ip.Unmap()
	}
	return ip.String()
}

func checked(e Entry, entry string) (Entry, error) {
	// No sign, as "+8053", which net would take.
	n, err := strconv.ParseUint(e.Port, 10, 16)
	if err != nil || n < 1 {
		return Entry{}, fmt.Errorf("%q: not a valid port", entry)
	}
	e.Port = strconv.FormatUint(n, 10)
	if e.Network.IsValid() {
		return e, nil
	}
	// A zone can hold anything, brackets too: the address must read back.
	address := net.JoinHostPort(e.Host, e.Port)
	if h, p, err := net.SplitHostPort(address); err != nil || h != e.Host || p != e.Port {
		return Entry{}, fmt.Errorf("%q: %s", entry, Rules)
	}
	return e, nil
}

// Addresses are the host:port addresses entries listen on, each once: a host name's, those it
// resolves to; a network's, the machine's addresses in it, but link-local ones, which need their
// interface.
func Addresses(entries []Entry) ([]string, error) {
	var result []string
	add := func(host, port string) {
		// Spelled once more: a host name's addresses are as the system's resolver writes them, and
		// an entry may be made without Parse.
		if a := net.JoinHostPort(spelled(host), port); !slices.Contains(result, a) {
			result = append(result, a)
		}
	}
	for _, e := range entries {
		switch {
		case e.Network.IsValid():
			ips, err := machineAddresses()
			if err != nil {
				return nil, err
			}
			found := false
			for _, ip := range ips {
				if e.Network.Contains(ip) {
					add(ip.String(), e.Port)
					found = true
				}
			}
			if !found {
				return nil, fmt.Errorf("%s: none of this machine's addresses is in it", e.Network)
			}
		case e.Host == "":
			add("", e.Port)
		default:
			if _, err := netip.ParseAddr(e.Host); err == nil {
				add(e.Host, e.Port)
				continue
			}
			ips, err := net.LookupHost(e.Host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				add(ip, e.Port)
			}
		}
	}
	return result, nil
}

func machineAddresses() ([]netip.Addr, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var result []netip.Addr
	for _, a := range addrs {
		if ipNet, ok := a.(*net.IPNet); ok && !ipNet.IP.IsLinkLocalUnicast() {
			if ip, ok := netip.AddrFromSlice(ipNet.IP); ok {
				result = append(result, ip.Unmap())
			}
		}
	}
	return result, nil
}

// Listen opens every address of entries, over TCP: a bad one stops it, closing the others, rather
// than leaving part of the list up. An address listens over its family alone, so 0.0.0.0 is all
// the IPv4 addresses, and not the IPv6 ones too, as Go would have it; no address is both.
func Listen(entries []Entry) ([]net.Listener, error) {
	addresses, err := Addresses(entries)
	if err != nil {
		return nil, err
	}
	var listeners []net.Listener
	for _, a := range addresses {
		l, err := net.Listen(network(a), a)
		if err != nil {
			for _, l := range listeners {
				l.Close()
			}
			return nil, err
		}
		listeners = append(listeners, l)
	}
	return listeners, nil
}

// network is the network to listen on address over: of its family for an IP address, both for none.
func network(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return "tcp"
	}
	ip, err := netip.ParseAddr(host)
	switch {
	case err != nil:
		return "tcp"
	case ip.Unmap().Is4():
		return "tcp4"
	default:
		return "tcp6"
	}
}

// Interfaces are the interfaces of the machine that hold the addresses listeners listen on; all,
// whether one listens on every address.
func Interfaces(listeners []net.Listener) (ifaces []net.Interface, all bool, err error) {
	machine, err := net.Interfaces()
	if err != nil {
		return nil, false, err
	}
	for _, l := range listeners {
		tcp, ok := l.Addr().(*net.TCPAddr)
		if !ok {
			continue
		}
		if tcp.IP.IsUnspecified() {
			return nil, true, nil
		}
		for _, iface := range machine {
			addrs, _ := iface.Addrs()
			if holds(iface, addrs, tcp) &&
				!slices.ContainsFunc(ifaces, func(i net.Interface) bool { return i.Index == iface.Index }) {
				ifaces = append(ifaces, iface)
			}
		}
	}
	return ifaces, false, nil
}

// holds tells whether iface, with addrs, has the address tcp listens on. A link-local one names
// its interface, as its zone: another with the same address, as a VLAN of it, isn't listened on.
func holds(iface net.Interface, addrs []net.Addr, tcp *net.TCPAddr) bool {
	if tcp.Zone != "" && tcp.Zone != iface.Name && tcp.Zone != strconv.Itoa(iface.Index) {
		return false
	}
	for _, a := range addrs {
		if ipNet, ok := a.(*net.IPNet); ok && ipNet.IP.Equal(tcp.IP) {
			return true
		}
	}
	return false
}
