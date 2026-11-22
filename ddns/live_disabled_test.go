//go:build live

package ddns

import (
	"context"
	"fmt"
	"slices"
	"testing"
)

// A disabled record is the server's: an update leaves it as it is, of an address the name has or
// not, and adds none beside it, so its address stays unanswered. Each server is asked its records
// by its own API, as DNS answers no disabled one.

// liveDisabled runs the check on a name with two disabled records, one of an address it is
// updated with and one of another: disabled lists the disabled records' addresses at the server.
func liveDisabled(t *testing.T, s *liveServer, host string, disabled func() []string) {
	t.Helper()
	fqdn := host + "." + s.zone
	service, err := NewService(s.provider, s.with("ttl", s.ttls[0]))
	if err != nil {
		t.Fatal(err)
	}
	for i, ips := range [][]string{{"2001:db8::1", "2001:db8::2"}, nil} {
		if err := service.Update(host, collectionWith(ips...)); err != nil {
			t.Fatalf("update %d: %v", i+1, err)
		}
		want := []string{"AAAA 2001:db8::1"}
		if ips == nil {
			want = nil
		}
		s.expect(t, fmt.Sprintf("update %d", i+1), fqdn, s.ttls[0], want...)
		got := disabled()
		slices.Sort(got)
		if !slices.Equal(got, []string{"2001:db8::2", "2001:db8::bad"}) {
			t.Errorf("update %d: the disabled records are of %v, want both as they were", i+1, got)
		}
	}
}

func TestLiveMikrotikDisabled(t *testing.T) {
	s := &liveServer{provider: "mikrotik", settings: liveSettings(t, "IPV6DDNS_LIVE_MIKROTIK"), ttls: []string{"10m"}}
	s.zone = fmt.Sprint(s.settings["zone"])
	s.records = dnsRecords(liveEnv(t, "IPV6DDNS_LIVE_MIKROTIK_DNS"))
	service, err := NewService("mikrotik", s.with("ttl", "10m"))
	if err != nil {
		t.Fatal(err)
	}
	fqdn := "live-disabled." + s.zone
	run := func(command string, args ...string) []map[string]string {
		t.Helper()
		client, err := service.(*Mikrotik).connect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		reply, err := client.Run(append([]string{command}, args...)...)
		if err != nil {
			t.Fatalf("%s: %v", command, err)
		}
		var rows []map[string]string
		for _, re := range reply.Re {
			rows = append(rows, re.Map)
		}
		return rows
	}
	removeAll := func() {
		for _, row := range run("/ip/dns/static/print", "?name="+fqdn) {
			run("/ip/dns/static/remove", "=.id="+row[".id"])
		}
	}
	removeAll()
	t.Cleanup(removeAll)
	for _, ip := range []string{"2001:db8::2", "2001:db8::bad"} {
		run("/ip/dns/static/add", "=name="+fqdn, "=type=AAAA", "=address="+ip, "=ttl=5m", "=disabled=yes")
	}
	liveDisabled(t, s, "live-disabled", func() []string {
		var ips []string
		for _, row := range run("/ip/dns/static/print", "?name="+fqdn) {
			if row["disabled"] == "true" && row["ttl"] == "5m" {
				ips = append(ips, row["address"])
			}
		}
		return ips
	})
}
