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
