package ddns

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
)

type uciSection struct {
	sectionType string
	options     map[string]string
}

// fakeUCI runs the uci commands the provider sends on a dhcp config, and counts the changes.
type fakeUCI struct {
	t        *testing.T
	sections map[string]*uciSection
	changes  int
	commits  int
	reloads  int
}

func shellUnquote(s string) string {
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], `'\''`, "'")
	}
	return s
}

func (u *fakeUCI) Run(command string) ([]byte, error) {
	switch {
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
	case command == "uci commit dhcp":
		u.commits++
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
