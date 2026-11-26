package ipv6ddns

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/source"
	"github.com/miguelangel-nubla/ipv6disc/pkg/pretty"
)

// PluginStatus is the state of a discovery plugin: when it last ran, its error then, and how many
// addresses it found, as its stats tell.
type PluginStatus struct {
	Name           string     `json:"name"`
	LastRun        *time.Time `json:"last_run,omitempty"`
	LastError      string     `json:"last_error,omitempty"`
	DiscoveryCount int        `json:"discovery_count"`
}

// pluginStatuses are the states of the plugins registered, in their order. hideSensible hides the
// errors, which can tell a router's address and user.
func (w *Worker) pluginStatuses(hideSensible bool) []PluginStatus {
	statuses := []PluginStatus{}
	for _, p := range w.plugins {
		stats := p.Stats()
		s := PluginStatus{Name: p.Name()}
		if t, ok := stats["last_run"].(time.Time); ok && !t.IsZero() {
			s.LastRun = &t
		}
		if err, ok := stats["last_error"].(string); ok && err != "" {
			s.LastError = err
			if hideSensible {
				s.LastError = "<sensible data hidden>"
			}
		}
		if n, ok := stats["discovery_count"].(int); ok {
			s.DiscoveryCount = n
		}
		statuses = append(statuses, s)
	}
	return statuses
}

// HomeAssistantStatus is the state of the device of Home Assistant's ESPHome integration: whether
// Home Assistant is connected, and since when; the states of the entities the sources read; and
// why the device isn't announced, when it isn't.
type HomeAssistantStatus struct {
	Name           string               `json:"name"`
	Connected      bool                 `json:"connected"`
	ConnectedSince *time.Time           `json:"connected_since,omitempty"`
	States         []HomeAssistantState `json:"states"`
	AnnounceError  string               `json:"announce_error,omitempty"`
}

// HomeAssistantState is an entity's state that a homeassistant source reads: Received is false
// until Home Assistant sends it, in its connection of now.
type HomeAssistantState struct {
	Entity    string `json:"entity"`
	Attribute string `json:"attribute,omitempty"`
	State     string `json:"state"`
	Received  bool   `json:"received"`
}

// homeAssistantStatus is the device's state, of the entities the sources read, by entity and
// attribute: nil without the homeassistant block.
func (w *Worker) homeAssistantStatus() *HomeAssistantStatus {
	h := w.homeAssistant
	if h == nil {
		return nil
	}
	connectedSince := h.connectedSince
	if connectedSince == nil {
		connectedSince = h.device.ConnectedSince
	}
	s := &HomeAssistantStatus{Name: h.config.Name, States: []HomeAssistantState{}}
	if since, ok := connectedSince(); ok {
		s.Connected, s.ConnectedSince = true, &since
	}
	read := map[string]HomeAssistantState{}
	for _, c := range w.config.Sources {
		if c.Type == config.SourceHomeAssistant {
			read[stateKey(c.Entity, c.Attribute)] = HomeAssistantState{Entity: c.Entity, Attribute: c.Attribute}
		}
	}
	h.mutex.Lock()
	for _, key := range slices.Sorted(maps.Keys(read)) {
		e := read[key]
		e.State, e.Received = h.states[key]
		s.States = append(s.States, e)
	}
	s.AnnounceError = h.announceError
	h.mutex.Unlock()
	return s
}

// sourcesPage tells, of each source, its addresses and how its runs go; and of Home Assistant's
// device, whether it is connected and the states the sources read:
// nothing of what the configuration hasn't. The
// plugins' runs are the discovery's, on its page.
func sourcesPage(prefix string, sources []source.Status, ha *HomeAssistantStatus) pretty.Page {
	var page pretty.Page
	plain := func(format string, args ...any) {
		page.Add(pretty.Span{Text: prefix + fmt.Sprintf(format, args...)})
	}
	detail := func(format string, args ...any) {
		page.Add(pretty.As(pretty.Detail, prefix+fmt.Sprintf(format, args...)))
	}
	at := func(t *time.Time) string {
		if t == nil {
			return "never"
		}
		return t.Format(time.RFC3339)
	}
	if len(sources) > 0 {
		failing := 0
		for _, s := range sources {
			if s.LastError != "" {
				failing++
			}
		}
		role := pretty.Plain
		if failing > 0 {
			role = pretty.Error
		}
		page.Add(pretty.Span{Text: prefix}, pretty.As(pretty.Heading, "Sources:"), pretty.Span{Text: fmt.Sprintf(" %d, ", len(sources))}, pretty.As(role, fmt.Sprintf("%d failing", failing)))
	}
	for _, s := range sources {
		page.Add(pretty.As(pretty.Name, prefix+"    "+s.Name), pretty.Span{Text: " (" + s.Type + ")"})
		addresses := "none"
		if len(s.Addresses) > 0 {
			addresses = strings.Join(s.Addresses, ", ")
		}
		plain("        Addresses: %s", addresses)
		if s.Prefix != "" {
			plain("        Prefix: %s", s.Prefix)
		}
		detail("        Runs: %d, failures %d, last run %s, last success %s", s.Runs, s.Failures, at(s.LastRun), at(s.LastSuccess))
		if s.LastError != "" {
			page.Add(pretty.Span{Text: prefix + "        "}, pretty.As(pretty.Error, "(last error: "+s.LastError+")"))
		}
	}
	if ha != nil {
		if len(page) > 0 {
			page.Add()
		}
		state := pretty.As(pretty.Warn, "not connected")
		if ha.Connected {
			state = pretty.As(pretty.OK, "connected since "+ha.ConnectedSince.Format(time.RFC3339))
		}
		page.Add(pretty.Span{Text: prefix}, pretty.As(pretty.Heading, "Home Assistant:"), pretty.Span{Text: " " + ha.Name + ", "}, state)
		for _, e := range ha.States {
			of := e.Entity
			if e.Attribute != "" {
				of += " (" + e.Attribute + ")"
			}
			if e.Received {
				plain("    %s: %q", of, e.State)
			} else {
				page.Add(pretty.Span{Text: prefix + "    " + of + ": "}, pretty.As(pretty.Warn, "not sent yet"))
			}
		}
		if ha.AnnounceError != "" {
			page.Add(pretty.Span{Text: prefix + "    "}, pretty.As(pretty.Error, "(not announced: "+ha.AnnounceError+")"))
		}
	}
	return page
}
