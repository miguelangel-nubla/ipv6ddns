package ddns

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/miguelangel-nubla/ipv6ddns/internal/sshtest"
	"github.com/miguelangel-nubla/ipv6disc"
)

// fakePowerShell runs the DNS server commands the provider sends against fake.
type fakePowerShell struct {
	fake     *fakeDNS
	commands []string
}

var (
	psString      = `'((?:[^']|'')*)'`
	getCommand    = regexp.MustCompile(`Get-DnsServerResourceRecord -ZoneName ` + psString + ` -Name ` + psString + ` -RRType (A|AAAA) (-Node )?`)
	addCommand    = regexp.MustCompile(`^Add-DnsServerResourceRecord -ZoneName ` + psString + ` -Name ` + psString + ` -(A|Aaaa) -IPv(?:4|6)Address '([^']+)'(?: -TimeToLive '([^']+)')?$`)
	removeCommand = regexp.MustCompile(`^Remove-DnsServerResourceRecord -ZoneName ` + psString + ` -Name ` + psString + ` -RRType (A|AAAA) -RecordData '([^']+)' -Force$`)
)

func psUnquote(s string) string {
	return strings.ReplaceAll(s, "''", "'")
}

func (p *fakePowerShell) RunPS(script string) ([]byte, error) {
	p.fake.mutex.Lock()
	defer p.fake.mutex.Unlock()
	p.commands = append(p.commands, script)

	if matches := getCommand.FindAllStringSubmatch(script, -1); matches != nil {
		var ips []string
		for _, m := range matches {
			if psUnquote(m[1]) != "example.com" {
				return nil, errors.New("no such zone")
			}
			// As the DNS server: without -Node, the records of the names under the name too,
			// which for @ is the whole zone.
			name := psUnquote(m[2])
			for _, rec := range p.fake.records {
				under := m[4] == "" && (name == "@" || strings.HasSuffix(rec.name, "."+name))
				if (rec.name == name || under) && rec.rrType == m[3] {
					ips = append(ips, fmt.Sprintf("%s %d", rec.ip, rec.ttl))
				}
			}
		}
		// As ConvertTo-Json: one value alone, more in an array.
		switch len(ips) {
		case 0:
			return []byte("[]\r\n"), nil
		case 1:
			out, _ := json.Marshal(ips[0])
			return append(out, "\r\n"...), nil
		default:
			out, _ := json.Marshal(ips)
			return append(out, "\r\n"...), nil
		}
	}
	if m := addCommand.FindStringSubmatch(script); m != nil {
		ttl := 0
		if m[5] != "" {
			ttl = parseTimeSpan(m[5])
		}
		p.fake.add(psUnquote(m[2]), strings.ToUpper(m[3]), m[4], ttl)
		return nil, nil
	}
	if m := removeCommand.FindStringSubmatch(script); m != nil {
		p.fake.deleteWhere(func(rec record) bool {
			return rec.name == psUnquote(m[2]) && rec.rrType == m[3] && sameIP(rec.ip, m[4])
		})
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected command: %s", script)
}

func (p *fakePowerShell) Close() error { return nil }

// parseTimeSpan reads [d.]hh:mm:ss into seconds.
func parseTimeSpan(s string) int {
	var days, h, m, sec int
	if strings.Contains(s, ".") {
		fmt.Sscanf(s, "%d.%d:%d:%d", &days, &h, &m, &sec)
	} else {
		fmt.Sscanf(s, "%d:%d:%d", &h, &m, &sec)
	}
	return ((days*24+h)*60+m)*60 + sec
}

func TestWindowsUpdate(t *testing.T) {
	for hostname, name := range map[string]string{
		"nas": "nas", "": "@", "o'brien": "o'brien",
		// With its zone, the same names.
		"nas.example.com": "nas", "NAS.Example.COM.": "NAS", "example.com": "@",
	} {
		if got := windowsRecordName(hostname, "example.com"); got != name {
			t.Errorf("windowsRecordName(%q) = %q, want %q", hostname, got, name)
		}
		fake := newFakeDNS(t, name, "other")
		// The records of the names under it are not its own: one with an address it has no more,
		// and one with an address it is to have.
		fake.add("a."+name, "AAAA", obsoleteIP, 300)
		fake.add("*."+name, "AAAA", newIP, 300)
		fake.writes = 0
		ps := &fakePowerShell{fake: fake}
		service := &WindowsDNS{Zone: "example.com", newRunner: func() (WindowsRunner, error) { return ps, nil }}
		service.TTL.Duration = 26 * time.Hour

		fake.check(func(addrs *ipv6disc.AddrCollection) error { return service.Update(hostname, addrs) }, name, "other")
		for _, rec := range fake.of(name) {
			if rec.ttl != 26*3600 {
				t.Errorf("%q: record %s: ttl %d, want 26h: of the one it had too", hostname, rec.ip, rec.ttl)
			}
		}
		if len(fake.of("a."+name)) != 1 || len(fake.of("*."+name)) != 1 {
			t.Errorf("%q: the records of the names under it changed: %v", hostname, fake.records)
		}
	}
}

// Without a TTL, the records keep the one they have: the zone's.
func TestWindowsNoTTL(t *testing.T) {
	fake := newFakeDNS(t, "nas", "other")
	ps := &fakePowerShell{fake: fake}
	service := &WindowsDNS{Zone: "example.com", newRunner: func() (WindowsRunner, error) { return ps, nil }}
	fake.check(func(addrs *ipv6disc.AddrCollection) error { return service.Update("nas", addrs) }, "nas", "other")
	for _, rec := range fake.of("nas") {
		if ip, _ := canonicalIP(rec.ip); ip == wantedIP && rec.ttl != 300 {
			t.Errorf("the record kept was made again: ttl %d", rec.ttl)
		}
	}
}

func TestWindowsOneRecord(t *testing.T) {
	// ConvertTo-Json gives a lone string for one address.
	fake := &fakeDNS{t: t}
	fake.add("nas", "AAAA", wantedIP, 0)
	fake.writes = 0
	ps := &fakePowerShell{fake: fake}
	service := &WindowsDNS{Zone: "example.com", newRunner: func() (WindowsRunner, error) { return ps, nil }}
	if err := service.Update("nas", collectionWith(wantedIP)); err != nil {
		t.Fatal(err)
	}
	if fake.writes != 0 {
		t.Errorf("got %d changes, want none", fake.writes)
	}
}

func TestPreparePowerShellCommand(t *testing.T) {
	encoded, err := preparePowerShellCommand("Write-Output 'é'")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	if got := string(utf16.Decode(units)); !strings.HasSuffix(got, "Write-Output 'é'") || !strings.HasPrefix(got, "$ProgressPreference") {
		t.Errorf("decoded: %q", got)
	}
}

func secondsDuration(s int64) time.Duration {
	return time.Duration(s) * time.Second
}

func TestWindowsOverSSH(t *testing.T) {
	server := sshtest.Start(t, "admin", "secret", func(command string) ([]byte, error) {
		if !strings.HasPrefix(command, "powershell -NoProfile -NonInteractive -EncodedCommand ") {
			return nil, errors.New("not powershell")
		}
		return []byte("[]"), nil
	})
	service := &WindowsDNS{Zone: "example.com", Address: server.Address, Username: "admin", Password: "secret", HostKey: server.HostKey}
	if err := service.Update("nas", collectionWith()); err != nil {
		t.Fatal(err)
	}
	if got := server.Commands(); len(got) != 1 {
		t.Errorf("got %d commands, want the one listing the records", len(got))
	}
}
