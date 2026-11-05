package main

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const defaultWebserverPort = "80"

// parseListenList turns a comma-separated list of addresses, host names and ports into host:port
// pairs. An empty host means all addresses; an entry with no port gets the default one.
func parseListenList(list string) ([]string, error) {
	var result []string
	seen := make(map[string]bool)
	for _, entry := range strings.Split(list, ",") {
		address, err := parseListenEntry(strings.TrimSpace(entry))
		if err != nil {
			return nil, err
		}
		if !seen[address] {
			seen[address] = true
			result = append(result, address)
		}
	}
	return result, nil
}

func parseListenEntry(entry string) (string, error) {
	if entry == "" {
		return "", fmt.Errorf("empty entry")
	}
	// A port alone. Before anything else: a bare number would otherwise be a host name.
	if _, err := strconv.Atoi(entry); err == nil {
		return checkedListenAddress("", entry, entry)
	}
	// An IP address with no port: an IPv6 one, bracketed or not, would confuse SplitHostPort.
	unbracketed := entry
	if strings.HasPrefix(entry, "[") && strings.HasSuffix(entry, "]") {
		unbracketed = entry[1 : len(entry)-1]
	}
	if ip, err := netip.ParseAddr(unbracketed); err == nil {
		return checkedListenAddress(ip.String(), defaultWebserverPort, entry)
	}
	if host, port, err := net.SplitHostPort(entry); err == nil {
		return checkedListenAddress(host, port, entry)
	}
	if strings.ContainsAny(entry, ":[]") {
		return "", fmt.Errorf("invalid entry %q", entry)
	}
	return checkedListenAddress(entry, defaultWebserverPort, entry)
}

func checkedListenAddress(host, port, entry string) (string, error) {
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("invalid port in %q", entry)
	}
	return net.JoinHostPort(host, port), nil
}

// listenAll opens every address, so a bad one stops the start instead of leaving part of the list
// up. A host name listens on each address it resolves to.
func listenAll(addresses []string) ([]net.Listener, error) {
	var listeners []net.Listener
	fail := func(err error) ([]net.Listener, error) {
		for _, listener := range listeners {
			listener.Close()
		}
		return nil, err
	}
	seen := make(map[string]bool)
	for _, address := range addresses {
		expanded, err := expandHostName(address)
		if err != nil {
			return fail(err)
		}
		for _, a := range expanded {
			if seen[a] {
				continue
			}
			seen[a] = true
			listener, err := net.Listen("tcp", a)
			if err != nil {
				return fail(err)
			}
			listeners = append(listeners, listener)
		}
	}
	return listeners, nil
}

func expandHostName(address string) ([]string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if _, err := netip.ParseAddr(host); host == "" || err == nil {
		return []string{address}, nil
	}
	ips, err := net.LookupHost(host)
	if err != nil {
		return nil, err
	}
	var result []string
	for _, ip := range ips {
		result = append(result, net.JoinHostPort(ip, port))
	}
	return result, nil
}
