//go:build linux && integration

package ipv6ddns

// What only a real network tells of the Home Assistant device: that what it announces by mDNS is
// where it can be connected to, for Home Assistant's own libraries at the other end of a link,
// between two network namespaces. It needs root, iproute2, and a Python with aioesphomeapi:
//
//	go test -tags integration -exec sudo -run '^TestLive' .

import (
	"bufio"
	"context"
	"encoding/json"
	"slices"
	"strconv"
	"sync"
	"testing"

	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/internal/livetest"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/esphome"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/listen"
)

// The device listens where homeassistant.listen says, on a port that isn't homeassistant.port's:
// Home Assistant finds it by mDNS, at that port and at the address of the link only, and connects
// to what it found, with the key.
func TestLiveHomeAssistantFindsThePort(t *testing.T) {
	py := livetest.Python(t)
	link := livetest.NewLink(t, 2)
	port := link.FreePort(t)
	key := esphome.GenerateKey()
	h, err := newHomeAssistant(config.HomeAssistant{Name: "ipv6ddns-live-port", FriendlyName: "live test", Port: 6053, Key: key,
		Entries: []listen.Entry{{Host: link.Address, Port: strconv.Itoa(port)}}}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var running sync.WaitGroup
	defer running.Wait()
	defer cancel()
	if err := h.serve(ctx, &running, nil, nil, t.Errorf); err != nil {
		t.Fatal(err)
	}

	cmd := link.Command(py, "pkg/esphome/testdata/find.py", "ipv6ddns-live-port", link.PeerAddress, key, "30")
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Wait()
	defer cmd.Process.Kill()
	var found struct {
		Port       int
		Addresses  []string
		Encryption string
	}
	var connected struct {
		Name     string
		MAC      string
		Entities int
	}
	for lines := bufio.NewScanner(stdout); lines.Scan(); {
		event := struct {
			Found, Connected any
			Error            string
		}{&found, &connected, ""}
		if err := json.Unmarshal(lines.Bytes(), &event); err != nil {
			t.Fatalf("%s: %v", lines.Text(), err)
		}
		if event.Error != "" {
			t.Errorf("Home Assistant: %s", event.Error)
		}
	}
	if found.Port != port {
		t.Errorf("announced the port %d, listening on %d", found.Port, port)
	}
	if !slices.Equal(found.Addresses, []string{link.Address}) {
		t.Errorf("announced the addresses %v, want that of the link, %s", found.Addresses, link.Address)
	}
	if found.Encryption == "" {
		t.Error("the announcement doesn't say the device needs its key")
	}
	if connected.Name != "ipv6ddns-live-port" || connected.MAC == "" {
		t.Errorf("Home Assistant didn't connect to what it found: %+v", connected)
	}
}
