package ddns

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
)

// validSettings are settings each provider takes.
var validSettings = map[string]string{
	"adguardhome":             `{"address": "http://adguard:3000", "username": "admin", "password": "p", "zone": "lan.example.com"}`,
	"pihole":                  `{"address": "http://pihole", "password": "p", "zone": "lan.example.com"}`,
	"cloudflare":              `{"api_token": "t", "zone": "example.com", "ttl": "5m", "proxied": false}`,
	"duckdns":                 `{"api_token": "01234567-89ab-cdef-0123-456789abcdef"}`,
	"gravity":                 `{"server": "http://gravity", "api_key": "k", "zone": "example.com.", "ttl": "5m"}`,
	"mikrotik":                `{"address": "192.0.2.1", "username": "u", "password": "p", "zone": "lan", "ttl": "5m"}`,
	"openwrt":                 `{"address": "192.0.2.1", "username": "root", "password": "p", "zone": "lan", "ttl": "5m"}`,
	"rfc2136":                 `{"server": "192.0.2.53", "zone": "example.com", "ttl": "5m", "tsig_key": "ipv6ddns", "tsig_secret": "c2VjcmV0", "tsig_algorithm": "hmac-sha512"}`,
	"resolver":                `{"zone": "home.arpa", "records": ["printer A 192.168.1.20"], "ttl": "1m"}`,
	"route53":                 `{"access_key_id": "a", "secret_access_key": "s", "region": "eu-west-1", "hosted_zone_id": "Z1", "ttl": "5m"}`,
	"technitium":              `{"address": "https://dns", "token": "t", "zone": "example.com", "ttl": "5m"}`,
	"unifi":                   `{"address": "https://192.168.1.1", "api_key": "k", "zone": "lan.example.com", "ttl": "5m"}`,
	"windows":                 `{"zone": "example.com"}`,
	"opnsense_unbound":        `{"address": "https://fw", "key": "k", "secret": "s", "zone": "lan", "ttl": "5m"}`,
	"pfsense_restapi_unbound": `{"address": "https://fw", "key": "k", "zone": "lan", "ttl": "5m"}`,
}

func TestNewService(t *testing.T) {
	valid := validSettings
	for provider := range providers {
		settings, ok := valid[provider]
		if !ok {
			t.Errorf("%s: no test settings", provider)
			continue
		}
		if _, err := NewService(provider, json.RawMessage(settings)); err != nil {
			t.Errorf("%s: %v", provider, err)
		}
		if _, err := NewService(provider, json.RawMessage(`{"nope": 1}`)); err == nil {
			t.Errorf("%s: invalid settings: want an error", provider)
		}
	}
	if _, err := NewService("nope", json.RawMessage(`{}`)); err == nil {
		t.Error("unknown provider: want an error")
	}

	service, _ := NewService("cloudflare", json.RawMessage(valid["cloudflare"]))
	if ttl := service.(*Cloudflare).TTL.Duration; ttl != 5*time.Minute {
		t.Errorf("ttl: got %s", ttl)
	}
}

func TestDesiredRecords(t *testing.T) {
	c := ipv6disc.NewAddrCollection()
	for _, ip := range []string{"192.0.2.1", "2001:db8::1", "fe80::1%eth0"} {
		c.Add(ipv6disc.NewAddr(nil, netip.MustParseAddr(ip), "test", time.Hour, nil))
	}
	want := map[string]string{"192.0.2.1": "A", "2001:db8::1": "AAAA", "fe80::1": "AAAA"}
	if got := desiredRecords(c); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}

	for in, want := range map[string]string{"2001:0db8:0000::0001": "2001:db8::1", " 192.0.2.1 ": "192.0.2.1", "::ffff:192.0.2.1": "192.0.2.1"} {
		if got, ok := canonicalIP(in); !ok || got != want {
			t.Errorf("canonicalIP(%q) = %q, %v, want %q", in, got, ok, want)
		}
	}
	if _, ok := canonicalIP("host"); ok {
		t.Error("canonicalIP of a name: want none")
	}
}

func TestWithDefaultPort(t *testing.T) {
	for in, want := range map[string]string{
		"router":            "router:22",
		"router:2222":       "router:2222",
		"192.0.2.1":         "192.0.2.1:22",
		"2001:db8::1":       "[2001:db8::1]:22",
		"[2001:db8::1]":     "[2001:db8::1]:22",
		"[2001:db8::1]:222": "[2001:db8::1]:222",
	} {
		if got := withDefaultPort(in, "22"); got != want {
			t.Errorf("withDefaultPort(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTLSConfigs(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	hash := sha256.Sum256(server.Certificate().Raw)
	fingerprint := hex.EncodeToString(hash[:])
	other := strings.Repeat("0", 64)

	for _, tt := range []struct {
		name   string
		config *tls.Config
		ok     bool
	}{
		{"untrusted, no fingerprint", verifiedOrPinnedTLSConfig("127.0.0.1", ""), false},
		{"untrusted, its fingerprint", verifiedOrPinnedTLSConfig("127.0.0.1", fingerprint), true},
		{"untrusted, its fingerprint with colons in upper case", verifiedOrPinnedTLSConfig("127.0.0.1", colons(strings.ToUpper(fingerprint))), true},
		{"untrusted, another fingerprint", verifiedOrPinnedTLSConfig("127.0.0.1", other), false},
		{"trusted, for its address", trusting(verifiedOrPinnedTLSConfig("127.0.0.1", ""), server), true},
		{"pinned", pinnedTLSConfig(fingerprint), true},
		{"pinned to another", pinnedTLSConfig(other), false},
	} {
		response, err := newHTTPClient(tt.config).Get(server.URL)
		if err == nil {
			response.Body.Close()
		}
		if (err == nil) != tt.ok {
			t.Errorf("%s: got %v, want success %v", tt.name, err, tt.ok)
		}
	}
}

// trusting makes the config trust the test server's certificate, as the system would a real one.
func trusting(config *tls.Config, server *httptest.Server) *tls.Config {
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	verify := config.VerifyConnection
	config.VerifyConnection = func(cs tls.ConnectionState) error {
		systemRoots = roots
		defer func() { systemRoots = nil }()
		return verify(cs)
	}
	return config
}

// Without a server name, the host given is the one the certificate must be for.
func TestVerifiedTLSConfigWithoutServerName(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{server.Certificate()}}
	for host, ok := range map[string]bool{"127.0.0.1": true, "other.test": false, "": false} {
		err := trusting(verifiedOrPinnedTLSConfig(host, ""), server).VerifyConnection(cs)
		if (err == nil) != ok {
			t.Errorf("host %q: got %v, want success %v", host, err, ok)
		}
	}
}

func colons(s string) string {
	var parts []string
	for i := 0; i < len(s); i += 2 {
		parts = append(parts, s[i:i+2])
	}
	return strings.Join(parts, ":")
}

func TestUCIDomains(t *testing.T) {
	output := `dhcp.@dnsmasq[0]=dnsmasq
dhcp.@dnsmasq[0].domain='lan'
dhcp.@host[0]=host
dhcp.@host[0].name='nas.lan'
dhcp.@host[0].ip='192.168.1.10'
dhcp.@domain[0]=domain
dhcp.@domain[0].name='nas.lan'
dhcp.@domain[0].ip='2001:db8::10'
dhcp.ipv6ddns_0123abcd=domain
dhcp.ipv6ddns_0123abcd.name='nas.lan'
dhcp.ipv6ddns_0123abcd.ip='2001:db8::11'
`
	want := map[string]uciDomain{
		"@domain[0]":        {name: "nas.lan", ip: "2001:db8::10"},
		"ipv6ddns_0123abcd": {name: "nas.lan", ip: "2001:db8::11"},
	}
	if got := uciDomains(output); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if got := shellQuote("it's"); got != `'it'\''s'` {
		t.Errorf("shellQuote: got %s", got)
	}
}

func TestWindowsHelpers(t *testing.T) {
	for d, want := range map[time.Duration]string{
		5 * time.Minute:               "00:05:00",
		25*time.Hour + 61*time.Second: "1.01:01:01",
		48 * time.Hour:                "2.00:00:00",
	} {
		if got := timeSpan(d); got != want {
			t.Errorf("timeSpan(%s) = %s, want %s", d, got, want)
		}
	}
	if got := psQuote("o'brien"); got != "'o''brien'" {
		t.Errorf("psQuote: got %s", got)
	}
	if windowsRecordName("", "example.com") != "@" || windowsRecordName("host", "example.com") != "host" {
		t.Error("windowsRecordName")
	}
}

// A setting no provider has, as a typo, is an error rather than ignored.
func TestUnknownSettingsAreRefused(t *testing.T) {
	for provider, settings := range validSettings {
		var withTypo map[string]any
		if err := json.Unmarshal([]byte(settings), &withTypo); err != nil {
			t.Fatal(err)
		}
		withTypo["tll"] = "5m"
		raw, _ := json.Marshal(withTypo)
		if _, err := NewService(provider, raw); err == nil || !strings.Contains(err.Error(), "tll") {
			t.Errorf("%s: a setting with a typo: got %v, want an error naming it", provider, err)
		}
	}
}
