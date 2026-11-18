package ddns

import (
	"net"
	"strings"
	"testing"
)

func FuzzUCIDomains(f *testing.F) {
	f.Add("dhcp.cfg01=domain\ndhcp.cfg01.name='nas.lan'\ndhcp.cfg01.ip='2001:db8::1'\n")
	f.Add("dhcp.@host[0]=host\ndhcp.@host[0].name='x'\n=\n.\ndhcp..=\ndhcp.a.b.c='d'\n")
	f.Fuzz(func(t *testing.T, output string) {
		for id, domain := range uciDomains(output) {
			if !strings.Contains(output, "dhcp."+id+"=domain") && !strings.Contains(output, "dhcp."+id+"='domain'") {
				t.Errorf("section %s (%+v) is not a domain section of the output", id, domain)
			}
		}
	})
}

func FuzzCanonicalIP(f *testing.F) {
	for _, s := range []string{"2001:0db8::1", "::ffff:192.0.2.1", "fe80::1%eth0", " 192.0.2.1 ", "host", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		ip, ok := canonicalIP(s)
		if !ok {
			return
		}
		if again, ok := canonicalIP(ip); !ok || again != ip {
			t.Errorf("canonicalIP(%q) = %q, and again %q, %v", s, ip, again, ok)
		}
		if strings.Contains(ip, "%") {
			t.Errorf("canonicalIP(%q) = %q keeps a zone", s, ip)
		}
	})
}

func FuzzFQDN(f *testing.F) {
	f.Add("host", "example.com")
	f.Add("host.example.com.", ".example.com")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, hostname, zone string) {
		fqdn := FQDN(hostname, zone)
		zone = strings.Trim(zone, ".")
		if zone != "" && fqdn != zone && !strings.HasSuffix(fqdn, "."+zone) {
			t.Errorf("FQDN(%q, %q) = %q is not in the zone", hostname, zone, fqdn)
		}
		if host, domain := SplitFQDN(fqdn); domain != "" && host+"."+domain != fqdn {
			t.Errorf("SplitFQDN(%q) = %q, %q", fqdn, host, domain)
		}
	})
}

func FuzzWithDefaultPort(f *testing.F) {
	for _, s := range []string{"router", "router:22", "2001:db8::1", "[2001:db8::1]", "[2001:db8::1]:22", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, address string) {
		result := withDefaultPort(address, "22")
		if strings.ContainsAny(address, "[]:") {
			return // a malformed address can stay malformed
		}
		if host, port, err := net.SplitHostPort(result); err != nil || host != address || port != "22" {
			t.Errorf("withDefaultPort(%q) = %q", address, result)
		}
	})
}

func FuzzTimeSpan(f *testing.F) {
	f.Add(int64(300))
	f.Add(int64(90061))
	f.Fuzz(func(t *testing.T, seconds int64) {
		if seconds < 0 || seconds > 1<<40 {
			return
		}
		span := timeSpan(secondsDuration(seconds))
		if got := parseTimeSpan(span); int64(got) != seconds {
			t.Errorf("timeSpan of %ds = %s, read back as %ds", seconds, span, got)
		}
	})
}
