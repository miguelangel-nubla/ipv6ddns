package source

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// defaultEchoURLs are services that answer with the address they see the request from, by family,
// each run by another company.
var defaultEchoURLs = map[int][]string{
	4: {"https://api.ipify.org", "https://ipv4.icanhazip.com", "https://v4.ident.me"},
	6: {"https://api6.ipify.org", "https://ipv6.icanhazip.com", "https://v6.ident.me"},
}

// httpFetcher asks, for each family, the echo services in order until one answers with an address
// of the family: the request goes over that family, so it is the network's public one. urls,
// when given, are asked for every family, in place of defaults.
func httpFetcher(families []int, urls []string, defaults map[int][]string) fetcher {
	return func(ctx context.Context) ([]netip.Addr, error) {
		var addrs []netip.Addr
		var errs []error
		for _, family := range families {
			candidates := urls
			if len(candidates) == 0 {
				candidates = defaults[family]
			}
			addr, err := echo(ctx, family, candidates)
			if err != nil {
				errs = append(errs, fmt.Errorf("IPv%d: %w", family, err))
				continue
			}
			addrs = append(addrs, addr)
		}
		return addrs, errors.Join(errs...)
	}
}

func echo(ctx context.Context, family int, urls []string) (netip.Addr, error) {
	network := fmt.Sprintf("tcp%d", family)
	dialer := &net.Dialer{}
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
		Proxy: http.ProxyFromEnvironment,
	}}
	defer client.CloseIdleConnections()

	var errs []error
	for _, url := range urls {
		addr, err := ask(ctx, client, url)
		if err == nil && !ofFamily(addr, family) {
			err = fmt.Errorf("answered %s, not an IPv%d address", addr, family)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", url, err))
			continue
		}
		return addr.Unmap(), nil
	}
	return netip.Addr{}, errors.Join(errs...)
}

func ask(ctx context.Context, client *http.Client, url string) (netip.Addr, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	request.Header.Set("Accept", "text/plain")
	response, err := client.Do(request)
	if err != nil {
		return netip.Addr{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("status %s", response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 256))
	if err != nil {
		return netip.Addr{}, err
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(string(body)))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("not an address: %q", strings.TrimSpace(string(body)))
	}
	return addr, nil
}
