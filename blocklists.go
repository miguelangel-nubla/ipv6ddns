package ipv6ddns

import (
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/blocklist"
	"github.com/miguelangel-nubla/ipv6disc/pkg/pretty"
)

// setUpBlocklists makes the blocklists the resolvers' blocks name, each once, with the names of its
// copy in the state folder: by name. A copy that doesn't read is logged, and the list waits for
// its download.
func (w *Worker) setUpBlocklists() map[string]*blocklist.List {
	lists := map[string]*blocklist.List{}
	for _, r := range w.config.Resolvers {
		if r.Spec.Block == nil {
			continue
		}
		for _, name := range r.Spec.Block.Lists {
			if lists[name] != nil {
				continue
			}
			c := w.config.Blocklists[name]
			lists[name] = blocklist.New(blocklist.Config{Name: name, URL: c.URL, Interval: c.IntervalOf().Duration,
				Folder: filepath.Join(w.config.StateFolder, blocklist.Folder), Infof: w.logger.Infof, Warnf: w.logger.Warnf})
		}
	}
	for _, name := range slices.Sorted(maps.Keys(lists)) {
		l := lists[name]
		if err := l.Load(); err != nil {
			w.logger.Warnf("blocklist %s: its copy doesn't read: %s: it is downloaded again", name, err)
		} else if s := l.Status(); s.Names > 0 {
			w.logger.Infof("blocklist %s: %d names, of its copy of %s", name, s.Names, s.LastSuccess.Local().Format(time.DateTime))
		}
		w.blocklists = append(w.blocklists, l)
	}
	return lists
}

// blocklistStatuses are the blocklists', each with the resolvers that block its names. hideSensible
// hides their errors, and their URLs' users and queries, which can tell secrets.
func (w *Worker) blocklistStatuses(hideSensible bool) []blocklist.Status {
	statuses := make([]blocklist.Status, 0, len(w.blocklists))
	for _, l := range w.blocklists {
		s := l.Status()
		for _, name := range slices.Sorted(maps.Keys(w.config.Resolvers)) {
			if b := w.config.Resolvers[name].Spec.Block; b != nil && slices.Contains(b.Lists, s.Name) {
				s.Resolvers = append(s.Resolvers, name)
			}
		}
		if hideSensible {
			s.URL = blocklist.Redacted(s.URL, "<sensible data hidden>")
			if s.LastError != "" {
				s.LastError = "<sensible data hidden>"
			}
		}
		statuses = append(statuses, s)
	}
	return statuses
}

// blocklistsPage tells, of each blocklist, where it is from, its names, and its downloads: nothing
// without blocklists.
func (w *Worker) blocklistsPage(prefix string, hideSensible bool) pretty.Page {
	return blocklistsPage(prefix, w.blocklistStatuses(hideSensible))
}

// blocklistsPage is the page of the blocklists of those statuses.
func blocklistsPage(prefix string, statuses []blocklist.Status) pretty.Page {
	if len(statuses) == 0 {
		return nil
	}
	var page pretty.Page
	plain := func(format string, args ...any) {
		page.Add(pretty.Span{Text: prefix + fmt.Sprintf(format, args...)})
	}
	when := func(t *time.Time) string {
		if t == nil {
			return "never"
		}
		return t.Local().Format(time.DateTime)
	}
	page.Add(pretty.Span{Text: prefix}, pretty.As(pretty.Heading, "Blocklists:"), pretty.Span{Text: fmt.Sprintf(" %d", len(statuses))})
	for _, s := range statuses {
		// A list without names blocks nothing: in red, as a resolver not serving all it should.
		state := pretty.As(pretty.OK, fmt.Sprintf("%d names", s.Names))
		if s.Names == 0 {
			state = pretty.As(pretty.Error, "no names: not downloaded yet, and no copy")
		}
		page.Add(pretty.As(pretty.Name, prefix+"    "+s.Name), pretty.Span{Text: ": "}, state,
			pretty.Span{Text: fmt.Sprintf(", %.1f MiB", float64(s.Bytes)/(1<<20))})
		plain("        URL: %s", s.URL)
		plain("        Resolvers: %s", strings.Join(s.Resolvers, ", "))
		if s.Unreadable > 0 {
			page.Add(pretty.Span{Text: prefix + "        Unreadable: "}, pretty.As(pretty.Warn, fmt.Sprintf("%d lines", s.Unreadable)))
		}
		plain("        Last success: %s, every %s", when(s.LastSuccess), time.Duration(s.Interval)*time.Second)
		refresh := pretty.Line{{Text: prefix + "        Last refresh: " + when(s.LastRefresh)}}
		if s.LastError != "" {
			refresh = append(refresh, pretty.Span{Text: " "}, pretty.As(pretty.Warn, "(failed: "+s.LastError+")"))
		}
		page.Add(refresh...)
		next := "now"
		if s.NextRefresh != nil {
			next = when(s.NextRefresh)
		}
		page.Add(pretty.As(pretty.Detail, prefix+"        Next refresh: "+next))
	}
	return page
}
