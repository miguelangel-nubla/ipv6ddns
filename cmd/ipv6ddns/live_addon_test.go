//go:build linux && integration

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/internal/livetest"
)

// The add-on of Home Assistant, as its start runs it: the command as it is built, with the
// starting configuration as its file and no other flag. On a machine that has, as Home
// Assistant's has, a bridge called hassio with the Supervisor's address, 172.30.32.1, where the
// Supervisor asks an add-on of the host's network for its page.
//
// The report is served there, at the port the add-on says is its ingress, and to the network
// outside nowhere: nothing but the file says so now. And the discovery runs, with ipv6disc's
// protocols, and finds a host of the network.
func TestLiveAddonStartingConfiguration(t *testing.T) {
	starter, err := os.ReadFile(filepath.Join("..", "..", "homeassistant", "starter.config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	lan := livetest.NewLAN(t, 21)
	router := lan.Router
	ha, peer := lan.Machine(t, "ha", 10), lan.Machine(t, "peer", 20)
	const supervisor = "172.30.32.1"
	ha.IP(t, "link", "add", "hassio", "type", "bridge")
	ha.IP(t, "addr", "add", supervisor+"/23", "dev", "hassio")
	ha.IP(t, "link", "set", "hassio", "up")

	// Asked as the Supervisor asks: from the machine itself, at its address on the bridge.
	addon := configure(t, ha, ha, "addon", 8053, string(starter))
	addon.web = supervisor + ":8053"
	addon.start().serving()

	if !refused(t, router, ha, 8053) {
		t.Errorf("the report is served to the network, at %s:8053", ha.IPv4)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if conn, err := ha.Dial(ctx, "tcp6", "[::1]:8053"); err == nil {
		conn.Close()
		t.Error("the report is served at the machine's loopback too")
	} else if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("the loopback's port 8053: %v", err)
	}

	if got, want := addon.status().Protocols, []string{"ndp", "ping", "ssdp", "wsd", "mdns", "dhcp", "lldp", "llmnr"}; !slices.Equal(got, want) {
		t.Errorf("the add-on says it runs %v, want %v", got, want)
	}
	waitFor(t, 30*time.Second, "peer's address at the add-on", func() bool { return addon.knows(peer.MAC, peer.IPv6) }, addon.tells)
	if page := addon.page("/"); !strings.Contains(page, peer.MAC) {
		t.Errorf("the add-on's page has no %s:\n%s", peer.MAC, page)
	}
	for _, level := range []string{"warn", "error"} {
		if entries := addon.logged(level); len(entries) > 0 {
			t.Errorf("the add-on logged at %s: %v", level, entries)
		}
	}
	addon.terminate()
}
