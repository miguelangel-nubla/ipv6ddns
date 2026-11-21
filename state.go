package ipv6ddns

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/ddns"

	"github.com/miguelangel-nubla/ipv6disc/pkg/pretty"
)

// State holds the host names to update, by provider and endpoint. Its providers and endpoints are
// built once, and don't change after; an endpoint's names do, those of the tasks' templates, which
// come and go with the hosts.
type State struct {
	providers map[string]*Provider
}

type Provider struct {
	endpoints map[string]*Endpoint
}

// Endpoint is a credential: a DNS service, with the host names it updates.
type Endpoint struct {
	ddns.Service
	// The host names, by their first spelling in the configuration.
	hostnames map[string]*Hostname
	// The same, by the name of their records: see recordName.
	names map[string]*Hostname
	// For the two maps: the names of a template are added, and taken out, while the status reads.
	mutex sync.RWMutex
	// One update of the service at a time, whatever the name: the providers read the records and
	// then change them, some over a session each, and all the names of a task change at once.
	updateMutex sync.Mutex
}

func NewState() *State {
	return &State{
		providers: make(map[string]*Provider),
	}
}

func NewProvider() *Provider {
	return &Provider{
		endpoints: make(map[string]*Endpoint),
	}
}

func NewEndpoint(service ddns.Service) *Endpoint {
	return &Endpoint{
		Service:   service,
		hostnames: make(map[string]*Hostname),
		names:     make(map[string]*Hostname),
	}
}

// list returns the endpoint's host names as they are now, by their spelling, and those spellings
// in order.
func (e *Endpoint) list() ([]string, map[string]*Hostname) {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	return slices.Sorted(maps.Keys(e.hostnames)), maps.Clone(e.hostnames)
}

// PrettyPrint is the page of the names: a summary, and each name of each endpoint, with how its
// updates go, and its addresses, each with how long it has left, how long it has been seen, and
// what has it, lined up.
func (s *State) PrettyPrint(prefix string, hideSensible bool) string {
	type named struct {
		domain string
		status hostnameStatus
	}
	var t pretty.Table
	var all []named
	byEndpoint := map[string][]named{}
	for _, providerKey := range slices.Sorted(maps.Keys(s.providers)) {
		provider := s.providers[providerKey]
		for _, endpointKey := range slices.Sorted(maps.Keys(provider.endpoints)) {
			endpoint := provider.endpoints[endpointKey]
			keys, hostnames := endpoint.list()
			for _, hostnameKey := range keys {
				n := named{endpoint.Domain(hostnameKey), hostnames[hostnameKey].status()}
				all = append(all, n)
				byEndpoint[providerKey+"\x00"+endpointKey] = append(byEndpoint[providerKey+"\x00"+endpointKey], n)
			}
		}
	}
	with, failing := 0, 0
	for _, n := range all {
		if len(n.status.addrs.Get()) > 0 {
			with++
		}
		if n.status.updateError != nil {
			failing++
		}
	}
	t.Line(fmt.Sprintf("DNS: %d names, %d with addresses, %d without; %d failing", len(all), with, len(all)-with, failing))
	now := time.Now()
	for _, providerKey := range slices.Sorted(maps.Keys(s.providers)) {
		t.Line("    Provider: " + providerKey)
		for _, endpointKey := range slices.Sorted(maps.Keys(s.providers[providerKey].endpoints)) {
			t.Line("        Endpoint: " + endpointKey)
			for _, n := range byEndpoint[providerKey+"\x00"+endpointKey] {
				writeHostnameStatus(&t, "            ", n.domain, n.status, hideSensible, now)
			}
		}
	}
	return t.Render(prefix)
}

// writeHostnameStatus adds a name to t: a line of it and how its updates go, and a row of each of
// its addresses, of the MAC and what saw it for a discovered one, of its source for one without a
// MAC.
func writeHostnameStatus(t *pretty.Table, indent, domain string, status hostnameStatus, hideSensible bool, now time.Time) {
	line := indent + domain + ":"
	if status.updateRunning {
		line += " (update running)"
	}
	if status.nextUpdateTime.After(now) {
		why := ""
		switch status.nextUpdateReason {
		case updateDebounce:
			why = fmt.Sprintf(", waiting for the %s debounce", status.debounce)
		case updateRetry:
			why = ", retrying after the error"
		}
		line += fmt.Sprintf(" (next update: %v%s)", status.nextUpdateTime.Sub(now).Round(time.Second), why)
	}
	if !status.updatedTime.IsZero() {
		line += fmt.Sprintf(" (last update: %s)", status.updatedTime.Format(time.RFC3339))
	}
	if status.updateError != nil {
		err := status.updateError.Error()
		if hideSensible {
			err = "<sensible data hidden>"
		}
		line += fmt.Sprintf(" (last update error: %s)", err)
	}
	t.Line(line)

	addrs := status.addrs.Get()
	if len(addrs) == 0 {
		gone := "(no address)"
		if !status.emptiedTime.IsZero() {
			gone = fmt.Sprintf("(no address: the last one went %s ago)", strings.TrimSpace(pretty.Up(now.Sub(status.emptiedTime))))
		}
		t.Line(indent + "    " + gone)
		return
	}
	for _, addr := range addrs {
		ip := addr.WithZone("").String()
		if addr.Is6() {
			ip = "[" + ip + "]"
		}
		sources := strings.Join(addr.Sources(), ", ")
		rest := "source " + sources
		if len(addr.Hw) > 0 {
			rest = addr.Hw.String() + "  " + sources
		}
		t.Row(indent+"    "+ip, addr.GetExpiration().Sub(now), now.Sub(addr.FirstSeen()), rest)
	}
}
