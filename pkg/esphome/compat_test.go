package esphome

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
)

// python is the interpreter with aioesphomeapi: $ESPHOME_PYTHON, or python3.
func python(t *testing.T) string {
	p := os.Getenv("ESPHOME_PYTHON")
	if p == "" {
		p = "python3"
	}
	if err := exec.Command(p, "-c", "import aioesphomeapi").Run(); err != nil {
		if os.Getenv("ESPHOME_COMPAT_REQUIRED") != "" {
			t.Fatalf("%s has no aioesphomeapi: %v", p, err)
		}
		t.Skipf("%s has no aioesphomeapi; ESPHOME_PYTHON names one that has", p)
	}
	return p
}

// Home Assistant's ESPHome library, aioesphomeapi, connects to the device as to any ESPHome one:
// it is refused without the key and with another, then reads the device and its entities, follows
// their states, presses its button, and gives it the state of an entity it asks for.
func TestHomeAssistantConnects(t *testing.T) {
	py := python(t)
	key := GenerateKey()
	rawKey, _ := ParseKey(key)
	mac, _ := net.ParseMAC("02:00:5e:10:00:01")
	d := &Device{
		Name: "ipv6ddns-test", FriendlyName: "ipv6ddns test", MAC: mac, Key: rawKey,
		Manufacturer: "ipv6ddns", Model: "DDNS updater", Project: "miguelangel-nubla.ipv6ddns", ProjectVersion: "1.2.3",
	}
	addresses := d.AddTextSensor(Entity{ID: "addresses", Name: "Addresses", Icon: "mdi:ip-network"})
	hosts := d.AddSensor(Entity{ID: "hosts", Name: "Hosts", Unit: "hosts", Category: CategoryDiagnostic})
	pressed := d.AddBinarySensor(Entity{ID: "pressed", Name: "Pressed", DeviceClass: "problem"})
	echo := d.AddTextSensor(Entity{ID: "echo", Name: "Echo"})
	d.AddButton(Entity{ID: "update", Name: "Update"}, func() { pressed.Set(true) })
	d.SubscribeHomeAssistant("sensor.wan_ip", "", func(state string) { echo.Set("got:" + state) })
	addresses.Set("2001:db8::1")
	hosts.Set(3)
	pressed.Set(false)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- d.Serve(ctx, ln) }()
	defer func() {
		cancel()
		if err := <-served; err != nil {
			t.Error(err)
		}
	}()

	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	cmd := exec.Command(py, "testdata/client.py", port, key)
	cmd.Stderr = os.Stderr
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	timer := time.AfterFunc(60*time.Second, func() { cmd.Process.Kill() })
	defer timer.Stop()

	events := map[string][]map[string]any{}
	lines := bufio.NewScanner(stdout)
	for lines.Scan() {
		var event map[string]any
		if err := json.Unmarshal(lines.Bytes(), &event); err != nil {
			t.Fatalf("%s: %v", lines.Text(), err)
		}
		for k := range event {
			events[k] = append(events[k], event)
		}
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("the client: %v", err)
	}

	if got := events["no_key"]; len(got) != 1 || got[0]["no_key"] != "RequiresEncryptionAPIError" {
		t.Errorf("without the key: %v", got)
	}
	if got := events["wrong_key"]; len(got) != 1 || got[0]["wrong_key"] != "InvalidEncryptionKeyAPIError" {
		t.Errorf("with another key: %v", got)
	}
	if got := events["info"]; len(got) != 1 {
		t.Errorf("device info: %v", got)
	} else {
		info := got[0]["info"].(map[string]any)
		for k, want := range map[string]string{
			"name": "ipv6ddns-test", "friendly_name": "ipv6ddns test", "mac": "02:00:5E:10:00:01",
			"project_name": "miguelangel-nubla.ipv6ddns", "project_version": "1.2.3", "manufacturer": "ipv6ddns",
			"api_version": "APIVersion(major=1, minor=20)",
		} {
			if info[k] != want {
				t.Errorf("device info %s: %v, want %v", k, info[k], want)
			}
		}
	}
	if got := events["entity"]; len(got) != 5 {
		t.Errorf("entities: %v", got)
	}
	if got := events["asked"]; len(got) != 1 || got[0]["asked"].(map[string]any)["entity_id"] != "sensor.wan_ip" {
		t.Errorf("the state the device asks: %v", got)
	}
	if got := events["done"]; len(got) != 1 || got[0]["done"] != true {
		t.Errorf("the button, and the echo of Home Assistant's state: %v", got)
	}
	initial := map[string]any{}
	for _, e := range events["state"] {
		s := e["state"].(map[string]any)
		if _, seen := initial[s["entity"].(string)]; !seen {
			initial[s["entity"].(string)] = s["value"]
		}
	}
	if initial["addresses"] != "2001:db8::1" || initial["hosts"] != 3.0 {
		t.Errorf("the first states: %v", initial)
	}
}
