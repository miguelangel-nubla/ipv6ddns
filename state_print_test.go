package ipv6ddns

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/miguelangel-nubla/ipv6disc/pkg/pretty"
)

// A name says why its next update waits, the debounce or a retry after an error, and when it lost
// its last address; and each address has its time left, how long it was seen, its MAC and what
// saw it, lined up.
func TestPrettyPrintHostname(t *testing.T) {
	render := func(h *Hostname) string {
		var tb pretty.Table
		writeHostnameStatus(&tb, "", "nas.example.com", h.status(), true, time.Now())
		return tb.Render("")
	}

	fail := errors.New("the provider refused")
	failing := true
	h := NewHostname(func(*ipv6disc.AddrCollection) error {
		if failing {
			return fail
		}
		return nil
	}, time.Hour, time.Hour)
	t.Cleanup(h.Stop)
	h.SetAddrCollection(collection(addr(macA, "2001:db8::a")))
	page := render(h)
	if !regexp.MustCompile(`nas\.example\.com: \(next update: (59m59s|1h0m0s), waiting for the 1h0m0s debounce\)\n`).MatchString(page) {
		t.Errorf("waiting for the debounce:\n%s", page)
	}
	if !regexp.MustCompile(`\n    \[2001:db8::a\] +[0-9hms ]+ {2,}[0-9dhms ]+ +` + macA + `  eth0\n`).MatchString(page) {
		t.Errorf("the address's row:\n%s", page)
	}

	// It runs, and fails: a retry, after the error.
	h.ScheduleUpdate(0)
	for h.status().updateError == nil {
		time.Sleep(time.Millisecond)
	}
	if page := render(h); !strings.Contains(page, ", retrying after the error)") || !strings.Contains(page, "(last update error: <sensible data hidden>)") {
		t.Errorf("after an error:\n%s", page)
	}

	// Its last address goes.
	h.SetAddrCollection(ipv6disc.NewAddrCollection())
	if page := render(h); !regexp.MustCompile(`\n    \(no address: the last one went +0s ago\)\n`).MatchString(page) {
		t.Errorf("with no address:\n%s", page)
	}
	// And one that never had one says only that.
	never := NewHostname(func(*ipv6disc.AddrCollection) error { return nil }, 0, time.Second)
	t.Cleanup(never.Stop)
	if page := render(never); !strings.HasSuffix(page, "\n    (no address)\n") {
		t.Errorf("a name that never had an address:\n%s", page)
	}
}
