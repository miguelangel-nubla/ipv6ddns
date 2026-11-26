package ipv6ddns

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/resolver"
	"github.com/miguelangel-nubla/ipv6disc/pkg/pretty"
)

// ListenerStatus is a listener of the configuration: its entries, the sockets open of them, its
// certificate and server_name, the servers that use it, and its allow.
type ListenerStatus struct {
	Name string `json:"name"`
	// As written: dns://[::]:53, https://192.168.1.2.
	Listen []string `json:"listen"`
	// The sockets open of its entries, each with its scheme, by its resolver and its web server:
	// none before they serve.
	Sockets []string `json:"sockets"`
	// Its certificate, of certificates, by its name; and the name the clients ask, as written.
	TLS        string `json:"tls,omitempty"`
	ServerName string `json:"server_name,omitempty"`
	// The servers that use it, by name: none of either.
	Resolver  string `json:"resolver,omitempty"`
	Webserver string `json:"webserver,omitempty"`
	// The clients its servers answer, unless a server gives its own allow: none, every client a
	// server's own allow, or of none, the resolver's networks, says.
	Allow []string `json:"allow"`
}

// WebserverStatus is a web server of the configuration: the listeners it serves on, the sockets
// it opens itself, and the HTTPS of the listeners it shares, which their resolver opens.
type WebserverStatus struct {
	Name      string   `json:"name"`
	Listeners []string `json:"listeners"`
	// The sockets it opens, of HTTP and of HTTPS, each with its scheme: none before it serves.
	Sockets []string `json:"sockets"`
	// The HTTPS entries of its listeners that a resolver opens, as written, by the listener's
	// name: none without.
	Shared map[string][]string `json:"shared,omitempty"`
	// Its own allow, which replaces its listeners': none, theirs.
	Allow []string `json:"allow"`
}

// WebListening notes the sockets a web server opened of a listener's entries, each with its
// scheme, as http://[::]:8053: for the status.
func (w *Worker) WebListening(listener string, sockets ...string) {
	w.webMutex.Lock()
	defer w.webMutex.Unlock()
	if w.webSockets == nil {
		w.webSockets = map[string][]string{}
	}
	for _, s := range sockets {
		if !slices.Contains(w.webSockets[listener], s) {
			w.webSockets[listener] = append(w.webSockets[listener], s)
		}
	}
}

// webListening are the sockets the web servers opened, by the listener's name.
func (w *Worker) webListening() map[string][]string {
	w.webMutex.Lock()
	defer w.webMutex.Unlock()
	out := map[string][]string{}
	for name, sockets := range w.webSockets {
		out[name] = slices.Clone(sockets)
	}
	return out
}

// listenerStatuses are the listeners' statuses, by name's order: the sockets of each, its
// resolver's and its web server's.
func (w *Worker) listenerStatuses() []ListenerStatus {
	sockets := w.webListening()
	opened := map[string][]string{}
	for _, r := range w.resolvers {
		for name, s := range r.Status().ListenerSockets {
			opened[name] = append(opened[name], s...)
		}
	}
	out := make([]ListenerStatus, 0, len(w.config.Listeners))
	for _, name := range slices.Sorted(maps.Keys(w.config.Listeners)) {
		l := w.config.Listeners[name]
		st := ListenerStatus{Name: name, Listen: slices.Clone([]string(l.Listen)), Sockets: append(opened[name], sockets[name]...),
			TLS: l.TLS, ServerName: l.ServerName, Resolver: strings.TrimPrefix(l.Resolver, "resolvers."),
			Webserver: strings.TrimPrefix(l.Web, "webservers."), Allow: []string{}}
		if st.Sockets == nil {
			st.Sockets = []string{}
		}
		for _, p := range l.Allowed {
			st.Allow = append(st.Allow, p.String())
		}
		out = append(out, st)
	}
	return out
}

// webserverStatuses are the web servers' statuses, by name's order.
func (w *Worker) webserverStatuses() []WebserverStatus {
	sockets := w.webListening()
	out := make([]WebserverStatus, 0, len(w.config.Webservers))
	for _, name := range slices.Sorted(maps.Keys(w.config.Webservers)) {
		web := w.config.Webservers[name]
		st := WebserverStatus{Name: name, Listeners: slices.Clone([]string(web.Listeners)), Sockets: []string{}, Allow: []string{}}
		for _, ln := range web.Listeners {
			st.Sockets = append(st.Sockets, sockets[ln]...)
		}
		for _, sh := range web.Shared {
			if st.Shared == nil {
				st.Shared = map[string][]string{}
			}
			st.Shared[sh.Listener] = slices.Clone(sh.Lines)
		}
		st.Allow = append(st.Allow, web.Allow...)
		out = append(out, st)
	}
	return out
}

// listenersPage tells, of each listener, where it listens, the sockets open, its certificate, the
// servers that use it and its allow; and of each web server, where it serves: nothing without
// either.
func (w *Worker) listenersPage(prefix string) pretty.Page {
	return listenersPage(prefix, w.listenerStatuses(), w.webserverStatuses())
}

// listenersPage is the page of the listeners and web servers of those statuses.
func listenersPage(prefix string, listeners []ListenerStatus, webservers []WebserverStatus) pretty.Page {
	var page pretty.Page
	plain := func(format string, args ...any) {
		page.Add(pretty.Span{Text: prefix + fmt.Sprintf(format, args...)})
	}
	// An empty list says what it means.
	list := func(items []string, empty string) string {
		if len(items) == 0 {
			return empty
		}
		return strings.Join(items, ", ")
	}
	if len(listeners) > 0 {
		page.Add(pretty.Span{Text: prefix}, pretty.As(pretty.Heading, "Listeners:"))
	}
	for _, l := range listeners {
		page.Add(pretty.As(pretty.Name, prefix+"    "+l.Name))
		plain("        Listen: %s", list(l.Listen, "none"))
		plain("        Sockets: %s", list(l.Sockets, "none yet"))
		if l.TLS != "" {
			name := l.ServerName
			if name == "" {
				name = "its certificate's first"
			}
			plain("        TLS: %s, server name %s", l.TLS, name)
		}
		var users []string
		if l.Resolver != "" {
			users = append(users, "resolver "+l.Resolver)
		}
		if l.Webserver != "" {
			users = append(users, "web server "+l.Webserver)
		}
		plain("        Used by: %s", list(users, "none"))
		plain("        Allow: %s", list(l.Allow, "none, its servers'"))
	}
	if len(webservers) > 0 {
		if len(page) > 0 {
			page.Add()
		}
		page.Add(pretty.Span{Text: prefix}, pretty.As(pretty.Heading, "Web servers:"))
	}
	for _, s := range webservers {
		page.Add(pretty.As(pretty.Name, prefix+"    "+s.Name))
		plain("        Listeners: %s", list(s.Listeners, "none"))
		plain("        Sockets: %s", list(s.Sockets, "none yet"))
		// The HTTPS its listeners' resolvers open, and serve it on, at every path but theirs.
		for _, ln := range slices.Sorted(maps.Keys(s.Shared)) {
			plain("        Shared: %s, listener %s, with its resolver, at every path but %s", strings.Join(s.Shared[ln], ", "), ln, resolver.DoHPath)
		}
		plain("        Allow: %s", list(s.Allow, "none, its listeners'"))
	}
	return page
}
