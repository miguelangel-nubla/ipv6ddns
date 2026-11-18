package ipv6ddns

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/esphome"
	"go.uber.org/zap"
)

func freePort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// Home Assistant, by its ESPHome integration's library, sees a name's entities, and the state it
// sends for a homeassistant source reaches the DNS provider, and the name's addresses entity.
func TestHomeAssistantIntegration(t *testing.T) {
	py := os.Getenv("ESPHOME_PYTHON")
	if py == "" {
		py = "python3"
	}
	if err := exec.Command(py, "-c", "import aioesphomeapi").Run(); err != nil {
		if os.Getenv("ESPHOME_COMPAT_REQUIRED") != "" {
			t.Fatalf("%s has no aioesphomeapi", py)
		}
		t.Skipf("%s has no aioesphomeapi; ESPHOME_PYTHON names one that has", py)
	}

	key := esphome.GenerateKey()
	port := freePort(t)
	wan := config.Source{Type: config.SourceHomeAssistant, Entity: "sensor.wan_ip"}
	wan.Interval.Duration, wan.Lifetime.Duration = time.Hour, 3*time.Hour
	cfg := config.Config{
		Tasks:         map[string]config.Task{"web": {Name: "web", Sources: []string{"wan"}, Endpoints: map[string][]string{"dns": {"web"}}}},
		Credentials:   map[string]config.Credential{"dns": fakeCredential("homeassistant", time.Millisecond, time.Hour)},
		Sources:       map[string]config.Source{"wan": wan},
		HomeAssistant: &config.HomeAssistant{Key: key, Name: "ipv6ddns-test", FriendlyName: "ipv6ddns test", Port: port},
	}
	w, err := NewWorker(zap.NewNop().Sugar(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	fakeServicesMutex.Lock()
	service := fakeServices["homeassistant"]
	fakeServicesMutex.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := w.homeAssistant.serve(ctx, t.Logf); err != nil {
		t.Fatal(err)
	}
	go w.homeAssistant.follow(ctx, func() Status { return w.Status(false) })
	w.sources["wan"].Start(ctx, zap.NewNop().Sugar(), w.askRematch)
	go func() {
		for ctx.Err() == nil {
			w.lookForChanges()
			select {
			case <-ctx.Done():
			case <-w.rematch:
			case <-time.After(100 * time.Millisecond):
			}
		}
	}()

	cmd := exec.Command(py, "testdata/ha_client.py", strconv.Itoa(port), key)
	cmd.Stderr = os.Stderr
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	timer := time.AfterFunc(60*time.Second, func() { cmd.Process.Kill() })
	defer timer.Stop()
	entities := map[string]string{}
	done := false
	lines := bufio.NewScanner(stdout)
	for lines.Scan() {
		var event struct {
			Entity *struct {
				ObjectID string `json:"object_id"`
				Name     string `json:"name"`
			} `json:"entity"`
			Done *bool `json:"done"`
		}
		if err := json.Unmarshal(lines.Bytes(), &event); err != nil {
			t.Fatalf("%s: %v", lines.Text(), err)
		}
		if event.Entity != nil {
			entities[event.Entity.ObjectID] = event.Entity.Name
		}
		if event.Done != nil {
			done = *event.Done
		}
	}
	cmd.Wait()

	service.waitFor(t, "web", "203.0.113.50")
	for id, name := range map[string]string{
		"dns_web_addresses":   "web.fake addresses",
		"dns_web_last_update": "web.fake last update",
		"dns_web_problem":     "web.fake update",
		"discovered_hosts":    "Discovered hosts",
		"update_now":          "Update now",
	} {
		if entities[id] != name {
			t.Errorf("entity %s: %q, want %q (all: %v)", id, entities[id], name, entities)
		}
	}
	if !done {
		t.Error("the addresses entity never showed the state Home Assistant sent")
	}
}
