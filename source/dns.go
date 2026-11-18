package source

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// A resolver answers a query with the address it sees the query from.
type resolver struct {
	// The name to query: its A or AAAA records, or its TXT one when txt.
	name string
	txt  bool
	// The resolver's server, host:port, by family.
	servers map[int]string
}

// defaultResolvers are two resolvers run by different companies, tried in order.
var defaultResolvers = []resolver{
	{name: "myip.opendns.com.", servers: map[int]string{4: "208.67.222.222:53", 6: "[2620:119:35::35]:53"}},
	{name: "o-o.myaddr.l.google.com.", txt: true, servers: map[int]string{4: "216.239.32.10:53", 6: "[2001:4860:4802:32::a]:53"}},
}

// dnsFetcher asks, for each family, the resolvers in order until one answers with an address of the
// family: the query goes over that family, so it is the network's public one.
func dnsFetcher(families []int, resolvers []resolver) fetcher {
	return func(ctx context.Context) ([]netip.Addr, error) {
		var addrs []netip.Addr
		var errs []error
		for _, family := range families {
			addr, err := resolve(ctx, family, resolvers)
			if err != nil {
				errs = append(errs, fmt.Errorf("IPv%d: %w", family, err))
				continue
			}
			addrs = append(addrs, addr)
		}
		return addrs, errors.Join(errs...)
	}
}

func resolve(ctx context.Context, family int, resolvers []resolver) (netip.Addr, error) {
	var errs []error
	for _, r := range resolvers {
		server, ok := r.servers[family]
		if !ok {
			continue
		}
		addr, err := r.ask(ctx, family, server)
		if err == nil && !ofFamily(addr, family) {
			err = fmt.Errorf("answered %s, not an IPv%d address", addr, family)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s at %s: %w", strings.TrimSuffix(r.name, "."), server, err))
			continue
		}
		return addr.Unmap(), nil
	}
	if len(errs) == 0 {
		return netip.Addr{}, fmt.Errorf("no resolver for IPv%d", family)
	}
	return netip.Addr{}, errors.Join(errs...)
}

func (r resolver) ask(ctx context.Context, family int, server string) (netip.Addr, error) {
	network := fmt.Sprintf("udp%d", family)
	dialer := &net.Dialer{}
	client := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, server)
		},
	}

	if r.txt {
		records, err := client.LookupTXT(ctx, r.name)
		if err != nil {
			return netip.Addr{}, err
		}
		for _, record := range records {
			if addr, err := netip.ParseAddr(strings.TrimSpace(record)); err == nil {
				return addr, nil
			}
		}
		return netip.Addr{}, fmt.Errorf("no address in the TXT records %q", records)
	}

	ipNetwork := fmt.Sprintf("ip%d", family)
	addrs, err := client.LookupNetIP(ctx, ipNetwork, r.name)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(addrs) == 0 {
		return netip.Addr{}, errors.New("no address")
	}
	return addrs[0], nil
}
