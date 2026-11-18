package ipv6ddns

import (
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/source"
)

// Status is the state of the worker, to serve as JSON.
type Status struct {
	Hostnames  []HostnameStatus `json:"hostnames"`
	Discovered []DiscoveredHost `json:"discovered"`
	Sources    []source.Status  `json:"sources"`
}

type HostnameStatus struct {
	Provider  string   `json:"provider"`
	Endpoint  string   `json:"endpoint"`
	Hostname  string   `json:"hostname"`
	Domain    string   `json:"domain"`
	Addresses []string `json:"addresses"`

	LastUpdate    *time.Time `json:"last_update,omitempty"`
	NextUpdate    *time.Time `json:"next_update,omitempty"`
	UpdateRunning bool       `json:"update_running"`
	// The error of the last update, if it failed.
	LastError string `json:"last_error,omitempty"`
	Updates   int    `json:"updates"`
	Failures  int    `json:"failures"`
}

type DiscoveredHost struct {
	MAC       string              `json:"mac"`
	Addresses []DiscoveredAddress `json:"addresses"`
}

type DiscoveredAddress struct {
	Address string    `json:"address"`
	Expires time.Time `json:"expires"`
	Sources []string  `json:"sources"`
	// An address of the machine ipv6ddns runs on, which the self filters take; and, of those, a
	// temporary IPv6 privacy address.
	Self      bool `json:"self,omitempty"`
	Temporary bool `json:"temporary,omitempty"`
}

// Status returns the state of the host names and of the discovery. hideSensible hides the errors,
// which can tell secrets.
func (w *Worker) Status(hideSensible bool) Status {
	status := Status{Hostnames: []HostnameStatus{}, Discovered: []DiscoveredHost{}, Sources: []source.Status{}}

	for _, name := range slices.Sorted(maps.Keys(w.sources)) {
		status.Sources = append(status.Sources, w.sources[name].Status(hideSensible))
	}

	for _, providerKey := range slices.Sorted(maps.Keys(w.State.providers)) {
		provider := w.State.providers[providerKey]
		for _, endpointKey := range slices.Sorted(maps.Keys(provider.endpoints)) {
			endpoint := provider.endpoints[endpointKey]
			for _, hostnameKey := range slices.Sorted(maps.Keys(endpoint.hostnames)) {
				s := endpoint.hostnames[hostnameKey].status()
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

	all := w.discWorker.GetAll()
	for _, mac := range slices.Sorted(maps.Keys(all)) {
		host := DiscoveredHost{MAC: mac}
		for _, addr := range all[mac].Get() {
			host.Addresses = append(host.Addresses, DiscoveredAddress{
				Address: addr.WithZone("").String(),
				Expires: addr.GetExpiration(),
				Sources: addr.Sources(),

				Self:      addr.Self(),
				Temporary: addr.Temporary(),
			})
		}
		if len(host.Addresses) > 0 {
			status.Discovered = append(status.Discovered, host)
		}
	}
	return status
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

	addresses := 0
	for _, host := range s.Discovered {
		addresses += len(host.Addresses)
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
