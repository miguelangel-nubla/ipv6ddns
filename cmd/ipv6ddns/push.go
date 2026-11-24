package main

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns"
	"github.com/miguelangel-nubla/ipv6ddns/source"
)

// pushPath is where a router sends its addresses, as to a DynDNS service of the dyndns2 protocol.
const pushPath = "/nic/update"

// refusedWait is how long a refused password waits for its answer: it slows guessing.
var refusedWait = time.Second

// pushHandler takes the addresses a router sends to a push source, as the dyndns2 protocol has it:
// hostname names the source, or several, separated by commas; myip has the addresses, separated by
// commas, and myipv6 IPv6 ones, as some routers send them apart; without either, the address the
// request came from, if it is public. The password is the HTTP basic one, or password in the URL,
// where a router can't send basic. Each source answers with a line, good or nochg and its
// addresses; a failure with the dyndns2 word, and an HTTP status that isn't 200, for the routers
// that read the status alone.
func pushHandler(worker *ipv6ddns.Worker) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		logger := worker.Logger()
		fail := func(status int, word, why string) {
			logger.Warnf("%s from %s: %s", pushPath, r.RemoteAddr, why)
			if status == http.StatusUnauthorized {
				w.Header().Set("WWW-Authenticate", `Basic realm="ipv6ddns"`)
				time.Sleep(refusedWait)
			}
			w.WriteHeader(status)
			fmt.Fprintln(w, word)
		}
		if err := r.ParseForm(); err != nil {
			fail(http.StatusBadRequest, "911", "the request doesn't read: "+err.Error())
			return
		}
		password, hasBasic := "", false
		if _, p, ok := r.BasicAuth(); ok {
			password, hasBasic = p, true
		}
		if !hasBasic {
			password = r.Form.Get("password")
		}

		var hosts []string
		for _, h := range strings.Split(r.Form.Get("hostname"), ",") {
			if h = strings.TrimSpace(h); h != "" {
				hosts = append(hosts, h)
			}
		}
		if len(hosts) == 0 {
			fail(http.StatusBadRequest, "notfqdn", "no hostname: give the name of the push source")
			return
		}

		var addrs []netip.Addr
		for _, key := range []string{"myip", "myipv6"} {
			for _, v := range strings.Split(r.Form.Get(key), ",") {
				// An empty value is no address: as a router sends without IPv6.
				if v = strings.TrimSpace(v); v == "" {
					continue
				}
				ip, err := netip.ParseAddr(v)
				if err != nil {
					fail(http.StatusBadRequest, "911", fmt.Sprintf("%s=%q is not an address", key, v))
					return
				}
				addrs = append(addrs, ip.Unmap())
			}
		}
		if len(addrs) == 0 {
			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			ip, err := netip.ParseAddr(host)
			if err != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
				fail(http.StatusBadRequest, "911", "no myip, and the request comes from a private address, which is no public one: give myip")
				return
			}
			addrs = []netip.Addr{ip.Unmap()}
		}

		// Every source, and its password, before any takes the addresses: a request refused
		// changes nothing.
		sources := make([]*source.Source, 0, len(hosts))
		for _, h := range hosts {
			s, ok := worker.PushSource(h)
			if !ok {
				fail(http.StatusNotFound, "nohost", fmt.Sprintf("hostname %q is no push source", h))
				return
			}
			if !s.Accepts(password) {
				fail(http.StatusUnauthorized, "badauth", fmt.Sprintf("the password of source %s is refused", h))
				return
			}
			sources = append(sources, s)
		}
		var answer []string
		for i, s := range sources {
			h := hosts[i]
			changed, err := s.Push(addrs)
			if err != nil {
				logger.Errorf("%s", err)
			}
			word := "nochg"
			if changed {
				word = "good"
				logger.Infof("source %s: %v, pushed from %s", h, s.Addresses().Strings(), r.RemoteAddr)
			}
			answer = append(answer, word+" "+strings.Join(sortedAddresses(s.Addresses().Strings()), ","))
		}
		fmt.Fprintln(w, strings.Join(answer, "\n"))
	})
}

// sortedAddresses are the addresses in order, IPv4 first.
func sortedAddresses(addrs []string) []string {
	ips := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if ip, err := netip.ParseAddr(a); err == nil {
			ips = append(ips, ip)
		}
	}
	slices.SortFunc(ips, netip.Addr.Compare)
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return out
}
