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
)

// fakePowerShell runs the DNS server commands the provider sends against fake.
type fakePowerShell struct {
	fake     *fakeDNS
	commands []string
}

var (
	psString      = `'((?:[^']|'')*)'`
	getCommand    = regexp.MustCompile(`Get-DnsServerResourceRecord -ZoneName ` + psString + ` -Name ` + psString + ` -RRType (A|AAAA) `)
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
			for _, rec := range p.fake.of(psUnquote(m[2])) {
				if rec.rrType == m[3] {
					ips = append(ips, rec.ip)
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
	for _, hostname := range []string{"nas", "", "o'brien"} {
		name := windowsRecordName(hostname)
		fake := newFakeDNS(t, name, "other")
		ps := &fakePowerShell{fake: fake}
		service := &WindowsDNS{Zone: "example.com", newRunner: func() (WindowsRunner, error) { return ps, nil }}
		service.TTL.Duration = 26 * time.Hour

		fake.check(func() error { return service.Update(hostname, desired()) }, name, "other")
		for _, rec := range fake.of(name) {
			if ip, _ := canonicalIP(rec.ip); ip != wantedIP && rec.ttl != 26*3600 {
				t.Errorf("%q: record %s: ttl %d, want 26h", hostname, rec.ip, rec.ttl)
			}
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
