package ipv6ddns

import (
	"fmt"
	"io"
	"maps"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/resolver"
	"github.com/miguelangel-nubla/ipv6ddns/source"
	"github.com/miguelangel-nubla/ipv6disc"
)

// Status is the state of the worker, to serve as JSON.
type Status struct {
	Hostnames  []HostnameStatus `json:"hostnames"`
	Discovered []DiscoveredHost `json:"discovered"`
	// The protocols of the local discovery that run, as the configuration names them: those
	// enabled whose family is on, and listens.
	Protocols []string          `json:"protocols"`
	Sources   []source.Status   `json:"sources"`
	Resolvers []resolver.Status `json:"resolvers"`
	// The certificates of the configuration, by name.
	Certificates []CertificateStatus `json:"certificates,omitempty"`
	// The program itself: its goroutines, its memory, its open files.
	Process ProcessStatus `json:"process"`
}

type HostnameStatus struct {
	Provider  string   `json:"provider"`
	Endpoint  string   `json:"endpoint"`
	Hostname  string   `json:"hostname"`
	Domain    string   `json:"domain"`
	Addresses []string `json:"addresses"`

	LastUpdate *time.Time `json:"last_update,omitempty"`
	NextUpdate *time.Time `json:"next_update,omitempty"`
	// Why the next update waits: debounce, retry, after an error, or asked.
	NextUpdateReason string `json:"next_update_reason,omitempty"`
	// When it lost its last address, while it has none.
	Emptied       *time.Time `json:"emptied,omitempty"`
	UpdateRunning bool       `json:"update_running"`
	// The error of the last update, if it failed.
	LastError string `json:"last_error,omitempty"`
	Updates   int    `json:"updates"`
	Failures  int    `json:"failures"`
}

type DiscoveredHost struct {
	MAC string `json:"mac"`
	// The names of the host: what it, or its router, says it is called, as discovery learns them.
	Names     []DiscoveredName    `json:"names,omitempty"`
	Addresses []DiscoveredAddress `json:"addresses"`
}

// DiscoveredName is a name a host has, and what said it: protocols of the local discovery, as
// mdns, or plugins by their name.
type DiscoveredName struct {
	Name    string   `json:"name"`
	Sources []string `json:"sources"`
	// When it was first said, and until when it stays: the last of those of Said.
	FirstSeen time.Time `json:"first_seen"`
	Expires   time.Time `json:"expires"`
	// Each that said it, with its own times.
	Said []DiscoveredNameSource `json:"said"`
}

// DiscoveredNameSource is one that said a name: a protocol, on an interface or none; or a report, of
// a plugin, from a table, as its router's leases.
type DiscoveredNameSource struct {
	Source    string    `json:"source"`
	Interface string    `json:"interface,omitempty"`
	Reported  bool      `json:"reported,omitempty"`
	From      string    `json:"from,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Expires   time.Time `json:"expires"`
}

type DiscoveredAddress struct {
	Address string    `json:"address"`
	Expires time.Time `json:"expires"`
	Sources []string  `json:"sources"`
	// An address of the machine ipv6ddns runs on, which the self filters take; and, of those, a
	// temporary IPv6 privacy address.
	Self      bool `json:"self,omitempty"`
	Temporary bool `json:"temporary,omitempty"`
	// How it was seen: a record of each protocol and way, or report, each with its own times, as
	// a filter's ip.seen reads them.
	Seen []DiscoveredRecord `json:"seen"`
}

// DiscoveredRecord is one way an address was seen: by a protocol, and how; or reported by a plugin,
// or the kernel, from one of its tables.
type DiscoveredRecord struct {
	Protocol  string    `json:"protocol,omitempty"`
	Way       string    `json:"way,omitempty"`
	Reported  *Reporter `json:"reported,omitempty"`
	On        string    `json:"interface,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Expires   time.Time `json:"expires"`
}

// Reporter is what reported an address, and from which of its tables.
type Reporter struct {
	By   string `json:"by"`
	Type string `json:"type,omitempty"`
	From string `json:"from,omitempty"`
}

// discoveredRecords are an address's records, for the status.
func discoveredRecords(addr *ipv6disc.Addr) []DiscoveredRecord {
	records := []DiscoveredRecord{}
	for _, r := range addr.Records() {
		d := DiscoveredRecord{Protocol: r.Protocol, Way: string(r.Way), On: r.On, FirstSeen: r.FirstSeen, LastSeen: r.LastSeen, Expires: r.Expiration()}
		if r.Reported() {
			d.Reported = &Reporter{By: r.By, Type: r.Type, From: r.From}
		}
		records = append(records, d)
	}
	return records
}

// Status returns the state of the host names and of the discovery. hideSensible hides the errors,
// which can tell secrets.
func (w *Worker) Status(hideSensible bool) Status {
	status := Status{Hostnames: []HostnameStatus{}, Discovered: []DiscoveredHost{}, Protocols: []string{}, Sources: []source.Status{}, Resolvers: []resolver.Status{}}
	status.Process = processStatus()

	for _, r := range w.resolvers {
		status.Resolvers = append(status.Resolvers, r.Status())
	}
	if len(w.certs) > 0 {
		status.Certificates = w.certificateStatuses()
	}

	for _, name := range slices.Sorted(maps.Keys(w.sources)) {
		status.Sources = append(status.Sources, w.sources[name].Status(hideSensible))
	}

	for _, providerKey := range slices.Sorted(maps.Keys(w.State.providers)) {
		provider := w.State.providers[providerKey]
		for _, endpointKey := range slices.Sorted(maps.Keys(provider.endpoints)) {
			endpoint := provider.endpoints[endpointKey]
			keys, hostnames := endpoint.list()
			for _, hostnameKey := range keys {
				s := hostnames[hostnameKey].status()
				h := HostnameStatus{
					Provider:      providerKey,
					Endpoint:      endpointKey,
					Hostname:      hostnameKey,
					Domain:        endpoint.Domain(hostnameKey),
					Addresses:     s.addrs.Strings(),
					UpdateRunning: s.updateRunning,
					Updates:       s.updates,
					Failures:      s.failures,
				}
				if !s.updatedTime.IsZero() {
					h.LastUpdate = &s.updatedTime
				}
				if s.nextUpdateTime.After(time.Now()) {
					h.NextUpdate = &s.nextUpdateTime
					h.NextUpdateReason = s.nextUpdateReason
				}
				if !s.emptiedTime.IsZero() {
					h.Emptied = &s.emptiedTime
				}
				if s.updateError != nil {
					h.LastError = s.updateError.Error()
					if hideSensible {
						h.LastError = "<sensible data hidden>"
					}
				}
				status.Hostnames = append(status.Hostnames, h)
			}
		}
	}

	status.Protocols = append(status.Protocols, w.discWorker.Protocols()...)
	all := w.discWorker.GetAll()
	names := w.discWorker.AllNames()
	for _, mac := range slices.Sorted(maps.Keys(all)) {
		host := DiscoveredHost{MAC: mac}
		for _, name := range names[mac] {
			n := DiscoveredName{Name: name.Name, Sources: name.Sources, FirstSeen: name.FirstSeen, Expires: name.Expiration, Said: []DiscoveredNameSource{}}
			for _, s := range name.Said {
				n.Said = append(n.Said, DiscoveredNameSource{Source: s.Source, Interface: s.On, Reported: s.Reported, From: s.From,
					FirstSeen: s.FirstSeen, LastSeen: s.LastSeen, Expires: s.Expiration()})
			}
			host.Names = append(host.Names, n)
		}
		for _, addr := range all[mac].Get() {
			host.Addresses = append(host.Addresses, DiscoveredAddress{
				Address: addr.WithZone("").String(),
				Expires: addr.GetExpiration(),
				Sources: addr.Sources(),

				Self:      addr.Self(),
				Temporary: addr.Temporary(),
				Seen:      discoveredRecords(addr),
			})
		}
		if len(host.Addresses) > 0 {
			status.Discovered = append(status.Discovered, host)
		}
	}
	return status
}

// ProcessStatus is what the program itself takes: what grows without end when something is never
// let go, to watch over days.
type ProcessStatus struct {
	Goroutines int `json:"goroutines"`
	// The memory of the heap in use, in bytes.
	HeapBytes uint64 `json:"heap_bytes"`
	// The open files and sockets: where the system tells, as Linux; 0 elsewhere.
	OpenFiles int `json:"open_files"`
}

func processStatus() ProcessStatus {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	p := ProcessStatus{Goroutines: runtime.NumGoroutine(), HeapBytes: m.HeapInuse}
	if entries, err := os.ReadDir("/proc/self/fd"); err == nil {
		// Less the one that reads the folder.
		p.OpenFiles = max(len(entries)-1, 0)
	}
	return p
}

// WriteMetrics writes the status as Prometheus metrics, in their text format.
func (s Status) WriteMetrics(out io.Writer) error {
	var b strings.Builder
	metric := func(name, kind, help string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, kind)
	}
	labels := func(h HostnameStatus, extra ...string) string {
		pairs := []string{"provider", h.Provider, "endpoint", h.Endpoint, "hostname", h.Domain}
		pairs = append(pairs, extra...)
		var l []string
		for i := 0; i < len(pairs); i += 2 {
			l = append(l, fmt.Sprintf(`%s="%s"`, pairs[i], labelValue(pairs[i+1])))
		}
		return "{" + strings.Join(l, ",") + "}"
	}

	metric("ipv6ddns_hostname_addresses", "gauge", "The addresses a host name has.")
	for _, h := range s.Hostnames {
		fmt.Fprintf(&b, "ipv6ddns_hostname_addresses%s %d\n", labels(h), len(h.Addresses))
	}
	metric("ipv6ddns_hostname_updates_total", "counter", "The updates of a host name's records, by result.")
	for _, h := range s.Hostnames {
		fmt.Fprintf(&b, "ipv6ddns_hostname_updates_total%s %d\n", labels(h, "result", "success"), h.Updates-h.Failures)
		fmt.Fprintf(&b, "ipv6ddns_hostname_updates_total%s %d\n", labels(h, "result", "failure"), h.Failures)
	}
	metric("ipv6ddns_hostname_last_update_failed", "gauge", "1 when the last update of a host name failed.")
	for _, h := range s.Hostnames {
		failed := 0
		if h.LastError != "" {
			failed = 1
		}
		fmt.Fprintf(&b, "ipv6ddns_hostname_last_update_failed%s %d\n", labels(h), failed)
	}
	metric("ipv6ddns_hostname_last_success_timestamp_seconds", "gauge", "When a host name's records were last updated.")
	for _, h := range s.Hostnames {
		if h.LastUpdate != nil {
			fmt.Fprintf(&b, "ipv6ddns_hostname_last_success_timestamp_seconds%s %d\n", labels(h), h.LastUpdate.Unix())
		}
	}

	sourceLabels := func(name string, extra ...string) string {
		l := fmt.Sprintf(`source="%s"`, labelValue(name))
		for i := 0; i < len(extra); i += 2 {
			l += fmt.Sprintf(`,%s="%s"`, extra[i], labelValue(extra[i+1]))
		}
		return "{" + l + "}"
	}
	metric("ipv6ddns_source_addresses", "gauge", "The addresses a source gives.")
	for _, src := range s.Sources {
		fmt.Fprintf(&b, "ipv6ddns_source_addresses%s %d\n", sourceLabels(src.Name), len(src.Addresses))
	}
	metric("ipv6ddns_source_runs_total", "counter", "The runs of a source, by result.")
	for _, src := range s.Sources {
		fmt.Fprintf(&b, "ipv6ddns_source_runs_total%s %d\n", sourceLabels(src.Name, "result", "success"), src.Runs-src.Failures)
		fmt.Fprintf(&b, "ipv6ddns_source_runs_total%s %d\n", sourceLabels(src.Name, "result", "failure"), src.Failures)
	}
	metric("ipv6ddns_source_last_success_timestamp_seconds", "gauge", "When a source last ran without an error.")
	for _, src := range s.Sources {
		if src.LastSuccess != nil {
			fmt.Fprintf(&b, "ipv6ddns_source_last_success_timestamp_seconds%s %d\n", sourceLabels(src.Name), src.LastSuccess.Unix())
		}
	}

	resolverLabels := func(name string, extra ...string) string {
		l := fmt.Sprintf(`resolver="%s"`, labelValue(name))
		for i := 0; i < len(extra); i += 2 {
			l += fmt.Sprintf(`,%s="%s"`, extra[i], labelValue(extra[i+1]))
		}
		return "{" + l + "}"
	}
	metric("ipv6ddns_resolver_serving", "gauge", "1 while a resolver answers on all its addresses.")
	for _, r := range s.Resolvers {
		serving := 0
		if r.Serving {
			serving = 1
		}
		fmt.Fprintf(&b, "ipv6ddns_resolver_serving%s %d\n", resolverLabels(r.Name), serving)
	}
	metric("ipv6ddns_resolver_queries_total", "counter", "The queries a resolver answered, by kind: local, nodata, forwarded, cached, refused, servfail.")
	for _, r := range s.Resolvers {
		for _, kind := range resolver.Kinds {
			fmt.Fprintf(&b, "ipv6ddns_resolver_queries_total%s %d\n", resolverLabels(r.Name, "kind", kind), r.Queries[kind])
		}
	}
	metric("ipv6ddns_resolver_cache_entries", "gauge", "The answers of the upstream servers a resolver keeps, in its cache.")
	for _, r := range s.Resolvers {
		fmt.Fprintf(&b, "ipv6ddns_resolver_cache_entries%s %d\n", resolverLabels(r.Name), r.CacheEntries)
	}
	metric("ipv6ddns_resolver_updates_total", "counter", "The dynamic updates a key of a resolver sent, by result: applied, refused, failed.")
	for _, r := range s.Resolvers {
		for _, k := range r.Keys {
			for _, result := range []string{resolver.UpdateApplied, resolver.UpdateRefused, resolver.UpdateFailed} {
				fmt.Fprintf(&b, "ipv6ddns_resolver_updates_total%s %d\n", resolverLabels(r.Name, "key", k.Name, "result", result), k.Updates[result])
			}
		}
	}
	metric("ipv6ddns_resolver_upstream_failures_total", "counter", "The queries an upstream server of a resolver didn't answer in time.")
	for _, r := range s.Resolvers {
		for _, upstream := range r.Upstreams {
			fmt.Fprintf(&b, "ipv6ddns_resolver_upstream_failures_total%s %d\n", resolverLabels(r.Name, "upstream", upstream), r.UpstreamFailures[upstream])
		}
	}

	addresses := 0
	for _, host := range s.Discovered {
		addresses += len(host.Addresses)
	}
	// By the names every Go program gives them, which the dashboards know.
	metric("go_goroutines", "gauge", "The goroutines there are.")
	fmt.Fprintf(&b, "go_goroutines %d\n", s.Process.Goroutines)
	metric("go_memstats_heap_inuse_bytes", "gauge", "The memory of the heap in use.")
	fmt.Fprintf(&b, "go_memstats_heap_inuse_bytes %d\n", s.Process.HeapBytes)
	if s.Process.OpenFiles > 0 {
		metric("process_open_fds", "gauge", "The open files and sockets.")
		fmt.Fprintf(&b, "process_open_fds %d\n", s.Process.OpenFiles)
	}

	metric("ipv6ddns_discovered_hosts", "gauge", "The MAC addresses discovered.")
	fmt.Fprintf(&b, "ipv6ddns_discovered_hosts %d\n", len(s.Discovered))
	metric("ipv6ddns_discovered_addresses", "gauge", "The IP addresses discovered.")
	fmt.Fprintf(&b, "ipv6ddns_discovered_addresses %d\n", addresses)

	_, err := io.WriteString(out, b.String())
	return err
}

// labelValue escapes a label value as Prometheus reads it: \\, \" and \n only.
var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

func labelValue(s string) string {
	return labelEscaper.Replace(strings.ToValidUTF8(s, "\uFFFD"))
}

// Healthy tells whether every resolver answers: nil, or why one doesn't.
func (w *Worker) Healthy() error {
	for _, r := range w.resolvers {
		if s := r.Status(); !s.Serving {
			reason := s.Error
			if reason == "" {
				reason = "not started"
			}
			return fmt.Errorf("resolver %s isn't serving: %s", s.Name, reason)
		}
	}
	return nil
}
