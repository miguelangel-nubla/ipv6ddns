package ddns

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/internal/sshtest"
)

type uciSection struct {
	sectionType string
	options     map[string]string
}

// fakeUCI runs the uci commands the provider sends on a dhcp config, and counts the changes. As
// uci, it shows the changes staged as made: staged counts those not committed yet.
type fakeUCI struct {
	t        *testing.T
	sections map[string]*uciSection
	changes  int
	staged   int
	commits  int
	reloads  int
	// The commands to fail, each the times given.
	fail map[string]int
	// What dnsmasq answers with: the domain sections as they were at its last reload, and, for
	// the lookups still to come that lag counts, as they were at the one before. It answers
	// nothing while unreachable.
	served, before map[string][]string
	lag            int
	lookups        int
	unreachable    bool
}

func shellUnquote(s string) string {
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], `'\''`, "'")
	}
	return s
}

// Run runs the commands of a line, joined with &&, up to the first that fails.
func (u *fakeUCI) Run(line string) ([]byte, error) {
	var output []byte
	for _, command := range strings.Split(line, " && ") {
		out, err := u.run(command)
		output = append(output, out...)
		if err != nil {
			return output, err
		}
	}
	return output, nil
}

func (u *fakeUCI) run(command string) ([]byte, error) {
	if u.fail[command] > 0 {
		u.fail[command]--
		return nil, fmt.Errorf("%s: failed", command)
	}
	switch {
	case command == "uci changes dhcp":
		if u.staged > 0 {
			return []byte("dhcp.ipv6ddns_00000000='domain'\n"), nil
		}
		return nil, nil
	case command == "uci -X show dhcp":
		var out strings.Builder
		for _, id := range slices.Sorted(maps.Keys(u.sections)) {
			section := u.sections[id]
			fmt.Fprintf(&out, "dhcp.%s=%s\n", id, section.sectionType)
			for _, option := range slices.Sorted(maps.Keys(section.options)) {
				fmt.Fprintf(&out, "dhcp.%s.%s='%s'\n", id, option, section.options[option])
			}
		}
		return []byte(out.String()), nil
	case strings.HasPrefix(command, "uci delete dhcp."):
		id := strings.TrimPrefix(command, "uci delete dhcp.")
		if _, ok := u.sections[id]; !ok {
			return nil, fmt.Errorf("uci: Entry not found")
		}
		delete(u.sections, id)
		u.changes++
		u.staged++
	case strings.HasPrefix(command, "uci set dhcp."):
		key, value, _ := strings.Cut(strings.TrimPrefix(command, "uci set dhcp."), "=")
		id, option, isOption := strings.Cut(key, ".")
		if !isOption {
			u.sections[id] = &uciSection{sectionType: value, options: map[string]string{}}
		} else if section, ok := u.sections[id]; ok {
			section.options[option] = shellUnquote(value)
		} else {
			return nil, fmt.Errorf("uci: Entry not found")
		}
		u.changes++
		u.staged++
	case command == "uci commit dhcp":
		u.commits++
		u.staged = 0
	case command == "/etc/init.d/dnsmasq reload":
		u.reloads++
		u.before, u.served = u.served, map[string][]string{}
		for _, section := range u.sections {
			if section.sectionType == "domain" {
				name := strings.ToLower(section.options["name"])
				u.served[name] = append(u.served[name], section.options["ip"])
			}
		}
	case strings.HasPrefix(command, "nslookup "):
		// As BusyBox's nslookup writes, on OpenWrt.
		u.lookups++
		if u.unreachable {
			return []byte(";; connection timed out; no servers could be reached\n\n"), nil
		}
		name := shellUnquote(strings.Fields(command)[1])
		served := u.served
		if u.lag > 0 {
			u.lag--
			served = u.before
		}
		out := "Server:\t\t127.0.0.1\nAddress:\t127.0.0.1:53\n\n"
		ips := served[strings.ToLower(name)]
		if len(ips) == 0 {
			out += "** server can't find " + name + ": NXDOMAIN\n\n"
		}
		for _, ip := range slices.Sorted(slices.Values(ips)) {
			out += "Name:\t" + name + "\nAddress: " + ip + "\n\n"
		}
		return []byte(out), nil
	default:
		return nil, fmt.Errorf("unexpected command: %s", command)
	}
	return nil, nil
}

func (u *fakeUCI) Close() error { return nil }

func (u *fakeUCI) domainIPs(name string) []string {
	var ips []string
	for _, section := range u.sections {
		if section.sectionType == "domain" && section.options["name"] == name {
			ip, _ := canonicalIP(section.options["ip"])
			ips = append(ips, ip)
		}
	}
	slices.Sort(ips)
	return ips
}

func TestOpenWrtUpdate(t *testing.T) {
	uci := &fakeUCI{t: t, sections: map[string]*uciSection{
		"cfg01dnsmasq": {"dnsmasq", map[string]string{"domain": "lan"}},
		// A static lease of the same name and address: not a DNS record of the provider's.
		"cfg02host":   {"host", map[string]string{"name": "nas.lan", "ip": obsoleteIP}},
		"cfg03domain": {"domain", map[string]string{"name": "nas.lan", "ip": wantedAsSet}},
		"cfg04domain": {"domain", map[string]string{"name": "nas.lan", "ip": obsoleteIP}},
		"cfg05domain": {"domain", map[string]string{"name": "nas.lan", "ip": wantedIP}}, // a duplicate
		"cfg06domain": {"domain", map[string]string{"name": "other.lan", "ip": obsoleteIP}},
	}}
	service := &OpenWrt{Address: "router", Username: "root", Zone: "lan", dial: func() (commandRunner, error) { return uci, nil }}

	if err := service.Update("nas", desired()); err != nil {
		t.Fatal(err)
	}
	if got, want := uci.domainIPs("nas.lan"), []string{newIPv4, wantedIP, newIP}; !slices.Equal(got, want) {
		t.Errorf("nas.lan: got %v, want %v", got, want)
	}
	if host, ok := uci.sections["cfg02host"]; !ok || host.options["ip"] != obsoleteIP {
		t.Errorf("the host section changed: %+v", host)
	}
	if got := uci.domainIPs("other.lan"); len(got) != 1 {
		t.Errorf("other.lan: got %v", got)
	}
	if uci.commits != 1 || uci.reloads != 1 {
		t.Errorf("got %d commits and %d reloads, want 1 of each", uci.commits, uci.reloads)
	}

	changes := uci.changes
	if err := service.Update("nas", desired()); err != nil {
		t.Fatal(err)
	}
	if uci.changes != changes || uci.commits != 1 || uci.reloads != 1 {
		t.Errorf("the second update changed the config")
	}
}

// dnsmasq answers for a name whatever its case, with the domain sections that have it in any, as
// a real one showed, tools/live-providers.sh: they are the name's, to keep or to delete, and not
// to add again beside them.
func TestOpenWrtNameInAnotherCase(t *testing.T) {
	uci := &fakeUCI{t: t, sections: map[string]*uciSection{
		"cfg03domain": {"domain", map[string]string{"name": "NAS.lan", "ip": wantedAsSet}},
		"cfg04domain": {"domain", map[string]string{"name": "Nas.LAN", "ip": obsoleteIP}},
	}}
	service := &OpenWrt{Address: "router", Username: "root", Zone: "lan", dial: func() (commandRunner, error) { return uci, nil }}

	if err := service.Update("nas", collectionWith(wantedIP)); err != nil {
		t.Fatal(err)
	}
	if _, kept := uci.sections["cfg03domain"]; !kept || len(uci.sections) != 1 || uci.changes != 1 {
		t.Errorf("got the sections %v after %d changes, want the one of %s kept and the other deleted, in one", slices.Sorted(maps.Keys(uci.sections)), uci.changes, wantedIP)
	}
}

// An update that fails after its changes are staged, at the commit or at the reload, finds nothing
// to change the next time: it must commit and reload all the same, as what dnsmasq serves is still
// the old.
func TestOpenWrtRetryAfterFailure(t *testing.T) {
	for _, tt := range []struct {
		failing string
		// The retry is of a new process, which doesn't remember the failure.
		restarted bool
		commits   int
	}{
		{"uci commit dhcp", false, 1},
		{"uci commit dhcp", true, 1},
		{"/etc/init.d/dnsmasq reload", false, 2},
		{"uci set dhcp.ipv6ddns_" + openWrtSectionHash("nas.lan", newIP) + "=domain", true, 1},
	} {
		uci := &fakeUCI{t: t, sections: map[string]*uciSection{
			"cfg03domain": {"domain", map[string]string{"name": "nas.lan", "ip": obsoleteIP}},
		}, fail: map[string]int{tt.failing: 1}}
		dial := func() (commandRunner, error) { return uci, nil }
		service := &OpenWrt{Address: "router", Username: "root", Zone: "lan", dial: dial}

		if err := service.Update("nas", desired()); err == nil {
			t.Fatalf("%s: the update succeeded, want it to fail", tt.failing)
		}
		if uci.reloads != 0 {
			t.Fatalf("%s: dnsmasq was reloaded", tt.failing)
		}
		if tt.restarted {
			service = &OpenWrt{Address: "router", Username: "root", Zone: "lan", dial: dial}
		}
		if err := service.Update("nas", desired()); err != nil {
			t.Fatalf("%s: retry: %v", tt.failing, err)
		}
		if got, want := uci.domainIPs("nas.lan"), []string{newIPv4, wantedIP, newIP}; !slices.Equal(got, want) {
			t.Errorf("%s: nas.lan: got %v, want %v", tt.failing, got, want)
		}
		if uci.commits != tt.commits || uci.reloads != 1 || uci.staged != 0 {
			t.Errorf("%s: after the retry: %d commits, %d reloads and %d changes staged, want %d, 1 and 0", tt.failing, uci.commits, uci.reloads, uci.staged, tt.commits)
		}

		// And once applied, nothing more.
		changes := uci.changes
		if err := service.Update("nas", desired()); err != nil {
			t.Fatal(err)
		}
		if uci.changes != changes || uci.commits != tt.commits || uci.reloads != 1 {
			t.Errorf("%s: the update after the retry changed the config", tt.failing)
		}
	}
}

func openWrtSectionHash(fqdn, ip string) string {
	hash := sha256.Sum256([]byte(fqdn + ip))
	return hex.EncodeToString(hash[:])[:8]
}

// OpenWrt over a real SSH connection: the host key pinned, refused, or reported once.
func TestOpenWrtOverSSH(t *testing.T) {
	uci := &fakeUCI{t: t, sections: map[string]*uciSection{}}
	var mutex sync.Mutex
	server := sshtest.Start(t, "root", "secret", func(command string) ([]byte, error) {
		mutex.Lock()
		defer mutex.Unlock()
		return uci.Run(command)
	})

	service := &OpenWrt{Address: server.Address, Username: "root", Password: "secret", Zone: "lan"}
	for range 2 {
		if err := service.Update("nas", desired()); err != nil {
			t.Fatal(err)
		}
	}
	if got := uci.domainIPs("nas.lan"); len(got) != 3 {
		t.Errorf("got %v, want the three addresses", got)
	}
	if warnings := service.Warnings(); len(warnings) != 1 || !strings.Contains(warnings[0], server.HostKey) {
		t.Errorf("unpinned: got warnings %v, want one with %s", warnings, server.HostKey)
	}
	if warnings := service.Warnings(); len(warnings) != 0 {
		t.Errorf("warned again: %v", warnings)
	}

	pinned := &OpenWrt{Address: server.Address, Username: "root", Password: "secret", Zone: "lan", HostKey: server.HostKey}
	if err := pinned.Update("nas", desired()); err != nil || len(pinned.Warnings()) != 0 {
		t.Errorf("pinned: %v, %v", err, pinned.Warnings())
	}

	commands := len(server.Commands())
	other := &OpenWrt{Address: server.Address, Username: "root", Password: "secret", Zone: "lan", HostKey: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	if err := other.Update("nas", desired()); err == nil || !strings.Contains(err.Error(), "host key mismatch") {
		t.Errorf("pinned to another key: got %v", err)
	}
	if len(server.Commands()) != commands {
		t.Error("a command reached a host with another key")
	}
}

// An update ends once dnsmasq answers with its records: the reload is a signal, and returns
// before dnsmasq has read them.
func TestOpenWrtWaitsForDnsmasq(t *testing.T) {
	interval, timeout, reachable := openWrtServedInterval, openWrtServedTimeout, openWrtReachableTimeout
	t.Cleanup(func() {
		openWrtServedInterval, openWrtServedTimeout, openWrtReachableTimeout = interval, timeout, reachable
	})
	openWrtServedInterval = time.Millisecond

	uci := &fakeUCI{t: t, sections: map[string]*uciSection{}}
	service := &OpenWrt{Zone: "lan", dial: func() (commandRunner, error) { return uci, nil }}

	// It answers with what it had for three lookups more: the update asks until the fourth.
	uci.lag = 3
	if err := service.Update("nas", desired()); err != nil {
		t.Fatal(err)
	}
	if uci.lookups != 4 || uci.lag != 0 {
		t.Errorf("%d lookups, %d still to lag: want the update to end at the fourth", uci.lookups, uci.lag)
	}

	// The same for an address taken out, which it still answers with; the others of the name,
	// which stay, don't count.
	uci.lookups, uci.lag = 0, 2
	if err := service.Update("nas", collectionWith("2001:db8::1")); err != nil {
		t.Fatal(err)
	}
	if uci.lookups != 3 {
		t.Errorf("an address removed: %d lookups, want 3", uci.lookups)
	}

	// And for the last address taken out: dnsmasq then has no such name.
	uci.lookups, uci.lag = 0, 1
	if err := service.Update("nas", collectionWith()); err != nil {
		t.Fatal(err)
	}
	if uci.lookups != 2 {
		t.Errorf("every address removed: %d lookups, want 2", uci.lookups)
	}

	// A dnsmasq that never answers with them is an error, and the next update reloads it again,
	// with nothing to change.
	openWrtServedTimeout = 20 * time.Millisecond
	uci.lag = 1 << 30
	err := service.Update("nas", collectionWith("2001:db8::1"))
	if err == nil || !strings.Contains(err.Error(), "the records of nas.lan are written, but after 20ms dnsmasq answers at 127.0.0.1 with [], not with [2001:db8::1]") {
		t.Errorf("never served: %v", err)
	}
	uci.lag = 0
	reloads := uci.reloads
	if err := service.Update("nas", collectionWith("2001:db8::1")); err != nil || uci.reloads != reloads+1 {
		t.Errorf("after it: %v, %d reloads more, want 1", err, uci.reloads-reloads)
	}

	// Where nothing answers at 127.0.0.1 there is nothing to ask: the update ends as the reload
	// does, once that is sure.
	openWrtReachableTimeout = 5 * time.Millisecond
	uci.unreachable = true
	if err := service.Update("nas", collectionWith("2001:db8::2")); err != nil {
		t.Errorf("nothing answers: %v", err)
	}
	// And where dnsmasq is at another port, or is more than one, nothing is asked.
	uci.unreachable = false
	for _, sections := range []map[string]*uciSection{
		{"cfg01": {sectionType: "dnsmasq", options: map[string]string{"port": "5353"}}},
		{"cfg01": {sectionType: "dnsmasq", options: map[string]string{}}, "cfg02": {sectionType: "dnsmasq", options: map[string]string{}}},
	} {
		moved := &fakeUCI{t: t, sections: sections}
		other := &OpenWrt{Zone: "lan", dial: func() (commandRunner, error) { return moved, nil }}
		if err := other.Update("nas", desired()); err != nil || moved.lookups != 0 || moved.reloads != 1 {
			t.Errorf("dnsmasq moved: %v, %d lookups, %d reloads", err, moved.lookups, moved.reloads)
		}
	}
	one := &fakeUCI{t: t, sections: map[string]*uciSection{"cfg01": {sectionType: "dnsmasq", options: map[string]string{"port": "53"}}, "cfg02": {sectionType: "srvhost", options: map[string]string{"port": "5060"}}}}
	if err := (&OpenWrt{Zone: "lan", dial: func() (commandRunner, error) { return one, nil }}).Update("nas", desired()); err != nil || one.lookups == 0 {
		t.Errorf("one dnsmasq at 53: %v, %d lookups", err, one.lookups)
	}
}

// What BusyBox's nslookup writes on OpenWrt, read: the addresses of the name, not the server's.
func TestNslookupAddresses(t *testing.T) {
	for output, want := range map[string][]string{
		"Server:\t\t127.0.0.1\nAddress:\t127.0.0.1:53\n\nName:\tnas.lan\nAddress: 192.0.2.1\n\nName:\tnas.lan\nAddress: 2001:DB8::1\n\n": {"192.0.2.1", "2001:db8::1"},
		"Server:\t\t127.0.0.1\nAddress:\t127.0.0.1:53\n\n** server can't find nope.lan: REFUSED\n\n":                                     {},
	} {
		if reached, got := nslookupAddresses(output); !reached || !slices.Equal(got, want) && len(got)+len(want) > 0 {
			t.Errorf("%q: reached %t, %v, want %v", output, reached, got, want)
		}
	}
	for _, output := range []string{";; connection timed out; no servers could be reached\n\n", "nslookup: write to '127.0.0.1': Connection refused\n", "sh: nslookup: not found\n"} {
		if reached, got := nslookupAddresses(output); reached || len(got) != 0 {
			t.Errorf("%q: reached %t, %v", output, reached, got)
		}
	}
}
