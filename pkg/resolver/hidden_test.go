package resolver

import (
	"reflect"
	"testing"
)

// The path of a DNS over HTTPS server can name an account, as NextDNS's: hidden, but /dns-query,
// which is everyone's. Two of one service stay apart.
func TestPathsHidden(t *testing.T) {
	const hidden = "<hidden>"
	for in, want := range map[string]string{
		"https://dns.nextdns.io/abc123":     "https://dns.nextdns.io/<hidden>",
		"https://dns.example.net:8443/a/b":  "https://dns.example.net:8443/<hidden>",
		"https://dns.example.net/dns-query": "https://dns.example.net/dns-query",
		"https://dns.example.net/":          "https://dns.example.net/",
		"tls://1.1.1.1":                     "tls://1.1.1.1",
		"1.1.1.1:53":                        "1.1.1.1:53",
		"[2606:4700:4700::1111]:53":         "[2606:4700:4700::1111]:53",
		"dns.example.net":                   "dns.example.net",
		"HTTPS://dns.nextdns.io/abc123":     "https://dns.nextdns.io/<hidden>",
	} {
		if got := PathHidden(in, hidden); got != want {
			t.Errorf("PathHidden(%q) = %q, want %q", in, got, want)
		}
	}

	shown := PathsHidden([]string{"https://dns.nextdns.io/aaa", "1.1.1.1:53", "https://dns.nextdns.io/bbb", "https://dns.nextdns.io/aaa"}, hidden)
	want := map[string]string{
		"https://dns.nextdns.io/aaa": "https://dns.nextdns.io/<hidden>",
		"1.1.1.1:53":                 "1.1.1.1:53",
		"https://dns.nextdns.io/bbb": "https://dns.nextdns.io/<hidden> 2",
	}
	if !reflect.DeepEqual(shown, want) {
		t.Errorf("PathsHidden = %v, want %v", shown, want)
	}

	status := Status{
		Upstreams:         []string{"https://dns.nextdns.io/aaa", "https://dns.nextdns.io/bbb"},
		UpstreamFailures:  map[string]uint64{"https://dns.nextdns.io/aaa": 1, "https://dns.nextdns.io/bbb": 2},
		UpstreamAddresses: map[string][]string{"https://dns.nextdns.io/aaa": {"192.0.2.1"}},
		Forwards: []ForwardStatus{{
			Domain:           "corp.example",
			Upstreams:        []string{"https://dns.corp.example/secret-path", "10.0.0.1:53"},
			UpstreamFailures: map[string]uint64{"https://dns.corp.example/secret-path": 3, "10.0.0.1:53": 0},
		}},
	}
	got := status.WithPathsHidden(hidden)
	wantStatus := Status{
		Upstreams:         []string{"https://dns.nextdns.io/<hidden>", "https://dns.nextdns.io/<hidden> 2"},
		UpstreamFailures:  map[string]uint64{"https://dns.nextdns.io/<hidden>": 1, "https://dns.nextdns.io/<hidden> 2": 2},
		UpstreamAddresses: map[string][]string{"https://dns.nextdns.io/<hidden>": {"192.0.2.1"}},
		Forwards: []ForwardStatus{{
			Domain:           "corp.example",
			Upstreams:        []string{"https://dns.corp.example/<hidden>", "10.0.0.1:53"},
			UpstreamFailures: map[string]uint64{"https://dns.corp.example/<hidden>": 3, "10.0.0.1:53": 0},
		}},
	}
	if !reflect.DeepEqual(got, wantStatus) {
		t.Errorf("WithPathsHidden:\n got %+v\nwant %+v", got, wantStatus)
	}
	// The status it was made of is as it was: its maps are not shared.
	if status.Upstreams[0] != "https://dns.nextdns.io/aaa" || status.UpstreamFailures["https://dns.nextdns.io/aaa"] != 1 || status.Forwards[0].Upstreams[0] != "https://dns.corp.example/secret-path" {
		t.Errorf("WithPathsHidden changed the status it was made of: %+v", status)
	}
}
