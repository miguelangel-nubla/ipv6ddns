// Package listen reads where to listen, as the web server and the Home Assistant device take it:
// a list of ports, addresses, networks of the machine's addresses, and host names.
//
//	8053, :8053                         that port, on all addresses
//	192.0.2.1:8053, [2001:db8::1]:8053  that address and port
//	192.0.2.1, 2001:db8::1              that address, on the default port
//	10.2.3.0/24, fd00::/64              each address of the machine in that network, on the default port
//	myhost:8053, myhost                 each address the name resolves to, at start
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
	// An address, a host name, or none, for all addresses.
	Host string
	// Or a network of the machine's addresses, when valid.
	Network netip.Prefix
	Port    string
}

func (e Entry) String() string {
	if e.Network.IsValid() {
		return e.Network.String() + " port " + e.Port
	}
	return net.JoinHostPort(e.Host, e.Port)
}

// Rules tells the entries a list takes, for errors.
const Rules = "a port, an address, a network as 10.2.3.0/24, or a host name, each with :port or not"

// Parse reads entries, giving those without a port defaultPort; it drops the repeated.
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
			return Entry{}, fmt.Errorf("%q: a network is as 10.2.3.0/24 or fd00::/64, and takes the default port", entry)
		}
		return checked(Entry{Network: prefix.Masked(), Port: defaultPort}, entry)
	}
	// An IP address with no port: an IPv6 one, bracketed or not, would confuse SplitHostPort.
	unbracketed := entry
	if strings.HasPrefix(entry, "[") && strings.HasSuffix(entry, "]") {
		unbracketed = entry[1 : len(entry)-1]
	}
	if ip, err := netip.ParseAddr(unbracketed); err == nil {
		return checked(Entry{Host: ip.String(), Port: defaultPort}, entry)
	}
	if host, port, err := net.SplitHostPort(entry); err == nil {
		return checked(Entry{Host: host, Port: port}, entry)
	}
	if strings.ContainsAny(entry, ":[]") {
		return Entry{}, fmt.Errorf("%q: %s", entry, Rules)
	}
	return checked(Entry{Host: entry, Port: defaultPort}, entry)
}

func checked(e Entry, entry string) (Entry, error) {
	if n, err := strconv.Atoi(e.Port); err != nil || n < 1 || n > 65535 {
		return Entry{}, fmt.Errorf("%q: an invalid port", entry)
	}
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
		if a := net.JoinHostPort(host, port); !slices.Contains(result, a) {
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
				return nil, fmt.Errorf("%s: no address of the machine in it", e.Network)
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
// than leaving part of the list up.
func Listen(entries []Entry) ([]net.Listener, error) {
	addresses, err := Addresses(entries)
	if err != nil {
		return nil, err
	}
	var listeners []net.Listener
	for _, a := range addresses {
		l, err := net.Listen("tcp", a)
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
			for _, a := range addrs {
				if ipNet, ok := a.(*net.IPNet); ok && ipNet.IP.Equal(tcp.IP) &&
					!slices.ContainsFunc(ifaces, func(i net.Interface) bool { return i.Index == iface.Index }) {
					ifaces = append(ifaces, iface)
				}
			}
		}
	}
	return ifaces, false, nil
}
