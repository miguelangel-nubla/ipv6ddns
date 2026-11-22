package ddns

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
)

// routerOSTime prints seconds as RouterOS does a time: 5m, 1d2h, 1w.
func routerOSTime(seconds int) string {
	if seconds == 0 {
		return "0s"
	}
	var out string
	for _, unit := range []struct {
		name    string
		seconds int
	}{{"w", 7 * 86400}, {"d", 86400}, {"h", 3600}, {"m", 60}, {"s", 1}} {
		if n := seconds / unit.seconds; n > 0 {
			out += fmt.Sprint(n) + unit.name
			seconds %= unit.seconds
		}
	}
	return out
}

func TestRouterOSDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"5m":         5 * time.Minute,
		"1d":         24 * time.Hour,
		"1w2d":       9 * 24 * time.Hour,
		"1w2d3h4m5s": 9*24*time.Hour + 3*time.Hour + 4*time.Minute + 5*time.Second,
		"0s":         0,
		"500ms":      500 * time.Millisecond,
		"00:05:00":   5 * time.Minute,
		"1d00:05:00": 24*time.Hour + 5*time.Minute,
		// As Go prints one, which the provider sends.
		"24h0m0s": 24 * time.Hour,
	} {
		if got, ok := routerOSDuration(in); !ok || got != want {
			t.Errorf("routerOSDuration(%q) = %s, %v, want %s", in, got, ok, want)
		}
	}
	for _, in := range []string{"x", "5", "5x", "1d00:05", "m"} {
		if got, ok := routerOSDuration(in); ok {
			t.Errorf("routerOSDuration(%q) = %s, want none", in, got)
		}
	}
}

// mikrotikFake serves /ip/dns/static from fake: RouterOS leaves out the type of an A record, and
// prints a TTL its way.
func mikrotikFake(fake *fakeDNS) func(string, map[string]string, map[string]string) ([]map[string]string, error) {
	return func(command string, args, queries map[string]string) ([]map[string]string, error) {
		fake.mutex.Lock()
		defer fake.mutex.Unlock()
		switch command {
		case "/ip/dns/static/print":
			var rows []map[string]string
			for _, rec := range fake.of(queries["name"]) {
				row := map[string]string{".id": "*" + rec.id, "name": rec.name, "address": rec.ip, "ttl": routerOSTime(rec.ttl), "disabled": strconv.FormatBool(rec.disabled)}
				if rec.rrType != "A" {
					row["type"] = rec.rrType
				}
				rows = append(rows, row)
			}
			return rows, nil
		case "/ip/dns/static/add":
			ttl, err := time.ParseDuration(args["ttl"])
			if err != nil {
				return nil, errors.New("invalid ttl")
			}
			fake.add(args["name"], args["type"], args["address"], int(ttl.Seconds()))
		case "/ip/dns/static/remove":
			fake.deleteWhere(func(rec record) bool { return "*"+rec.id == args[".id"] })
		case "/ip/dns/static/set":
			for i := range fake.records {
				if "*"+fake.records[i].id == args[".id"] {
					ttl, _ := time.ParseDuration(args["ttl"])
					fake.records[i].ttl = int(ttl.Seconds())
				}
			}
			fake.writes++
		default:
			return nil, errors.New("no such command")
		}
		return nil, nil
	}
}

func TestMikrotikUpdate(t *testing.T) {
	fake := newFakeDNS(t, "nas.lan", "other.lan")
	// A duplicate, of an address wanted: the address has one record, as each other.
	fake.add("nas.lan", "AAAA", wantedIP, 26*3600)
	fake.writes = 0
	router := newFakeRouterOS(t, nil, mikrotikFake(fake))

	// A TTL that RouterOS prints with days, 1d2h: it is not set again when it is the one set.
	service := &Mikrotik{Address: router.address(), Username: "admin", Zone: "lan"}
	service.TTL.Duration = 26 * time.Hour
	fake.check(func(addrs *ipv6disc.AddrCollection) error { return service.Update("nas", addrs) }, "nas.lan", "other.lan")
	for _, rec := range fake.of("nas.lan") {
		if rec.ttl != 26*3600 {
			t.Errorf("record %s: ttl %d, want 26h: of the one it had too", rec.ip, rec.ttl)
		}
	}
	fake.checkDisabled(func(addrs *ipv6disc.AddrCollection) error { return service.Update("nas", addrs) }, "nas.lan")
}

// A fingerprint without TLS would be a password in the clear with nothing checked.
func TestMikrotikFingerprintNeedsTLS(t *testing.T) {
	fingerprint := strings.Repeat("ab", 32)
	for settings, ok := range map[string]bool{
		`"tls_fingerprint": "` + fingerprint + `"`:                   false,
		`"tls_fingerprint": "` + fingerprint + `", "use_tls": false`: false,
		`"tls_fingerprint": "` + fingerprint + `", "use_tls": true`:  true,
		// As the documentation says to run it first, to be told the fingerprint.
		`"tls_fingerprint": "", "use_tls": true`: true,
		`"tls_fingerprint": ""`:                  true,
		`"use_tls": false`:                       true,
	} {
		_, err := NewService("mikrotik", json.RawMessage(`{"address": "192.0.2.1", "username": "u", "password": "p", "zone": "lan", "ttl": "5m", `+settings+`}`))
		if (err == nil) != ok {
			t.Errorf("%s: got %v, want success %v", settings, err, ok)
		}
		if err != nil && !strings.Contains(err.Error(), "use_tls") {
			t.Errorf("%s: the error doesn't tell of use_tls: %v", settings, err)
		}
	}
}

func TestMikrotikTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Close()
	certificate := server.TLS.Certificates[0]
	hash := sha256.Sum256(certificate.Certificate[0])
	fingerprint := hex.EncodeToString(hash[:])

	fake := newFakeDNS(t, "nas.lan", "other.lan")
	router := newFakeRouterOS(t, &tls.Config{Certificates: []tls.Certificate{certificate}}, mikrotikFake(fake))

	for _, tt := range []struct {
		name        string
		fingerprint string
		wantErr     string
	}{
		{"pinned", fingerprint, ""},
		{"pinned to another", strings.Repeat("0", 64), "fingerprint mismatch"},
		// Untrusted, and the error tells the fingerprint to configure.
		{"no fingerprint", "", fingerprint},
	} {
		service := &Mikrotik{Address: router.address(), UseTLS: true, TLSFingerprint: tt.fingerprint, Username: "admin", Zone: "lan"}
		service.TTL.Duration = 5 * time.Minute
		err := service.Update("nas", desired())
		if tt.wantErr == "" && err != nil {
			t.Errorf("%s: %v", tt.name, err)
		}
		if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
			t.Errorf("%s: got %v, want an error with %q", tt.name, err, tt.wantErr)
		}
	}
}
