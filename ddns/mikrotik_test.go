package ddns

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mikrotikFake serves /ip/dns/static from fake: RouterOS leaves out the type of an A record.
func mikrotikFake(fake *fakeDNS) func(string, map[string]string, map[string]string) ([]map[string]string, error) {
	return func(command string, args, queries map[string]string) ([]map[string]string, error) {
		fake.mutex.Lock()
		defer fake.mutex.Unlock()
		switch command {
		case "/ip/dns/static/print":
			var rows []map[string]string
			for _, rec := range fake.of(queries["name"]) {
				row := map[string]string{".id": "*" + rec.id, "name": rec.name, "address": rec.ip, "ttl": (time.Duration(rec.ttl) * time.Second).String()}
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
	router := newFakeRouterOS(t, nil, mikrotikFake(fake))

	service := &Mikrotik{Address: router.address(), Username: "admin", Zone: "lan"}
	service.TTL.Duration = 5 * time.Minute
	fake.check(func() error { return service.Update("nas", desired()) }, "nas.lan", "other.lan")
	for _, rec := range fake.of("nas.lan") {
		if rec.ttl != 300 {
			t.Errorf("record %s: ttl %d, want 300", rec.ip, rec.ttl)
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
