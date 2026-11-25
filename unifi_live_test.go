//go:build live

package ipv6ddns

// The program with a UniFi Network as both its discovery and its names: the unifi plugin reads
// the clients, and the unifi provider keeps a name, as the configuration has them. Of a
// self-hosted Network Application, IPV6DDNS_LIVE_UNIFI, which tools/live-providers.sh runs; and of
// UniFi OS Server, with its API key and with its admin, IPV6DDNS_LIVE_UNIFI_OS and
// IPV6DDNS_LIVE_UNIFI_OS_USER, which tools/unifi-os-server.sh sets up. Each is skipped without.
// The plugin's type is registered by its import, as the command's are all.

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/ddns"
	"github.com/miguelangel-nubla/ipv6disc"
	_ "github.com/miguelangel-nubla/ipv6disc/pkg/plugins/unifi"
	"github.com/miguelangel-nubla/ipv6disc/pkg/unifi"
	"go.uber.org/zap/zaptest"
)

func TestLiveUniFiProgram(t *testing.T) {
	for _, variable := range []string{"IPV6DDNS_LIVE_UNIFI", "IPV6DDNS_LIVE_UNIFI_OS", "IPV6DDNS_LIVE_UNIFI_OS_USER"} {
		t.Run(variable, func(t *testing.T) {
			raw := os.Getenv(variable)
			if raw == "" {
				t.Skipf("%s is not set: see tools/live-providers.sh and tools/unifi-os-server.sh", variable)
			}
			var settings map[string]string
			if err := json.Unmarshal([]byte(raw), &settings); err != nil {
				t.Fatal(err)
			}
			// The same server, logged in alike, for the plugin and the provider.
			var login strings.Builder
			for _, key := range []string{"address", "api_key", "username", "password", "tls_fingerprint"} {
				if settings[key] != "" {
					fmt.Fprintf(&login, "      %s: %q\n", key, settings[key])
				}
			}
			run := func(addresses ...string) {
				t.Helper()
				var listed strings.Builder
				for _, a := range addresses {
					fmt.Fprintf(&listed, "      - %q\n", a)
				}
				cfg := loadConfig(t, `
discovery:
  ipv6:
    enabled: false
  plugins:
    gateway:
      type: unifi
      interval: 1m
`+login.String()+`
sources:
  fixed:
    type: static
    addresses:
`+listed.String()+`
credentials:
  gateway:
    provider: unifi
    debounce: 1ms
    settings:
`+login.String()+`      zone: `+settings["zone"]+`
      ttl: 5m
tasks:
  program:
    sources:
      - fixed
    endpoints:
      gateway:
        - live-program
`)
				w, err := NewWorker(zaptest.NewLogger(t).Sugar(), cfg)
				if err != nil {
					t.Fatal(err)
				}
				// The plugins, made and registered as the command does.
				plugins, err := cfg.Discovery.NewPlugins()
				if err != nil {
					t.Fatal(err)
				}
				for _, p := range plugins {
					w.RegisterPlugin(p)
				}
				ctx, cancel := context.WithCancel(context.Background())
				if err := w.Start(ctx); err != nil {
					cancel()
					t.Fatal(err)
				}
				defer func() {
					cancel()
					w.Shutdown(context.Background())
				}()
				// Updated, and a poll of the plugin done without an error. UniFi OS limits how often a
				// user logs in, and the test logs in often: a login it refuses is tried again at the
				// next poll, and update, a minute later.
				for deadline := time.Now().Add(3 * time.Minute); ; time.Sleep(200 * time.Millisecond) {
					page := w.Page("", false).String()
					polled := strings.Contains(page, "gateway: discovery_count=") && strings.Contains(page, "last_error= ")
					updated := strings.Contains(page, "live-program."+settings["zone"]+": (last update:")
					if polled && updated {
						break
					}
					if time.Now().After(deadline) {
						t.Fatalf("no update, or no poll without an error, after 3 minutes:\n%s", page)
					}
				}
			}

			// What the server has, read by a client of the test's own, of its certificate alone.
			fingerprint := settings["tls_fingerprint"]
			client, err := unifi.New(unifi.Config{
				Address: settings["address"], APIKey: settings["api_key"], Username: settings["username"], Password: settings["password"],
			}, &tls.Config{InsecureSkipVerify: true, VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
				if sum := sha256.Sum256(raw[0]); hex.EncodeToString(sum[:]) != fingerprint {
					return errors.New("not the server's certificate")
				}
				return nil
			}}, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			fqdn := "live-program." + settings["zone"]
			records := func() []string {
				t.Helper()
				var listed []struct {
					Key        string `json:"key"`
					RecordType string `json:"record_type"`
					Value      string `json:"value"`
					TTL        int    `json:"ttl"`
				}
				// A login refused for coming too often is tried again, as the program does.
				for deadline := time.Now().Add(3 * time.Minute); ; time.Sleep(10 * time.Second) {
					err := client.Call(context.Background(), http.MethodGet, "/static-dns", nil, &listed)
					if err == nil {
						break
					}
					if !strings.Contains(err.Error(), "HTTP 429") || time.Now().After(deadline) {
						t.Fatal(err)
					}
				}
				var got []string
				for _, r := range listed {
					if r.Key == fqdn {
						got = append(got, fmt.Sprintf("%s %s %d", r.RecordType, r.Value, r.TTL))
					}
				}
				slices.Sort(got)
				return got
			}
			// The name leaves no record behind.
			t.Cleanup(func() {
				if provider, err := ddns.NewService("unifi", json.RawMessage(raw)); err == nil {
					provider.Update("live-program", ipv6disc.NewAddrCollection())
				}
			})

			run("2001:db8::77", "192.0.2.77")
			if got := records(); !slices.Equal(got, []string{"A 192.0.2.77 300", "AAAA 2001:db8::77 300"}) {
				t.Errorf("the records: %v", got)
			}
			run("2001:db8::77")
			if got := records(); !slices.Equal(got, []string{"AAAA 2001:db8::77 300"}) {
				t.Errorf("without the IPv4 address: %v", got)
			}
		})
	}
}
