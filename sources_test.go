package ipv6ddns

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6disc"
	"go.uber.org/zap"
)

// fakePlugin is a discovery plugin of the stats a poller tells.
type fakePlugin struct {
	name  string
	stats map[string]any
}

func (p fakePlugin) Name() string { return p.name }
func (p fakePlugin) Start(ctx context.Context, _ *ipv6disc.State, _ func(error)) error {
	<-ctx.Done()
	return nil
}
func (p fakePlugin) Stats() map[string]any { return p.stats }

// The sources, the discovery plugins and Home Assistant's device, in the status and the report
// alike: each source's addresses, runs and error; each plugin's last run, error and count, which
// the discovery's page has; the device's connection, the states the sources read, and why it isn't announced.
func TestSourcesStatus(t *testing.T) {
	const secret = "SECRET-91c2"
	wan := config.Source{Type: config.SourceStatic, Addresses: []string{"203.0.113.7"}}
	wan.Interval.Duration, wan.Lifetime.Duration = time.Hour, time.Hour
	ha := config.Source{Type: config.SourceHomeAssistant, Entity: "sensor.wan_ip", Attribute: "ipv6"}
	ha.Interval.Duration, ha.Lifetime.Duration = time.Hour, time.Hour
	cfg := config.Config{
		Sources:       map[string]config.Source{"wan": wan, "ha": ha},
		HomeAssistant: &config.HomeAssistant{Key: "8vnmHn62XcKmD3ePKcHl8NFhZQU1E7nVSYxU8vQ9PGA=", Name: "ipv6ddns-test", Port: 6053, Announce: new(bool)},
	}
	w, err := NewWorker(zap.NewNop().Sugar(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.discWorker.State.Close)
	ran := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	w.RegisterPlugin(fakePlugin{"router", map[string]any{"discovery_count": 3, "last_run": ran, "last_error": "denied for " + secret}})

	// Before anything: no runs, Home Assistant not connected, no state sent.
	st := w.Status(false)
	if len(st.Sources) != 2 || st.HomeAssistant == nil || st.HomeAssistant.Connected || len(st.HomeAssistant.States) != 1 || st.HomeAssistant.States[0].Received {
		t.Fatalf("the status before: %+v %+v", st.Sources, st.HomeAssistant)
	}
	page := w.Page("", false).String()
	for _, has := range []string{
		"Sources: 2, 0 failing\n    ha (homeassistant)\n        Addresses: none\n        Runs: 0, failures 0, last run never, last success never\n",
		"Home Assistant: ipv6ddns-test, not connected\n    sensor.wan_ip (ipv6): not sent yet\n",
	} {
		if !strings.Contains(page, has) {
			t.Errorf("the report before has no %q:\n%s", has, page)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.sources["wan"].Start(ctx, zap.NewNop().Sugar(), w.askRematch)
	deadline := time.Now().Add(5 * time.Second)
	for w.sources["wan"].Status(false).Runs == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the static source never ran")
		}
		time.Sleep(5 * time.Millisecond)
	}
	since := time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC)
	w.homeAssistant.connectedSince = func() (time.Time, bool) { return since, true }
	w.homeAssistant.states[stateKey("sensor.wan_ip", "ipv6")] = "2001:db8::1"
	w.homeAssistant.announceError = errors.New("no address to announce").Error()

	st = w.Status(false)
	src := st.Sources[1]
	if src.Name != "wan" || len(src.Addresses) != 1 || src.Runs != 1 || src.LastRun == nil || src.LastSuccess == nil {
		t.Errorf("the source wan: %+v", src)
	}
	if p := st.Plugins; len(p) != 1 || p[0].Name != "router" || p[0].DiscoveryCount != 3 || p[0].LastRun == nil || !p[0].LastRun.Equal(ran) || !strings.Contains(p[0].LastError, secret) {
		t.Errorf("the plugins: %+v", p)
	}
	h := st.HomeAssistant
	if !h.Connected || !h.ConnectedSince.Equal(since) || h.States[0].State != "2001:db8::1" || !h.States[0].Received || h.AnnounceError != "no address to announce" {
		t.Errorf("Home Assistant: %+v", h)
	}
	data, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"plugins":[{"name":"router","last_run":"2026-11-26T10:00:00Z"`, `"discovery_count":3`,
		`"homeassistant":{"name":"ipv6ddns-test","connected":true,"connected_since":"2026-11-26T09:00:00Z"`,
		`"states":[{"entity":"sensor.wan_ip","attribute":"ipv6","state":"2001:db8::1","received":true}]`, `"announce_error":"no address to announce"`} {
		if !strings.Contains(string(data), key) {
			t.Errorf("the status's JSON has no %s: %s", key, data)
		}
	}
	if strings.Contains(string(data), cfg.HomeAssistant.Key) {
		t.Errorf("the status's JSON has the key: %s", data)
	}

	page = w.Page("", false).String()
	for _, has := range []string{
		"    wan (static)\n        Addresses: 203.0.113.7\n        Runs: 1, failures 0, last run " + src.LastRun.Format(time.RFC3339) + ", last success " + src.LastSuccess.Format(time.RFC3339) + "\n",
		// The plugins' runs are the discovery's, as the status has them.
		"Plugins:\n    router: discovery_count=3 last_error=denied for " + secret + " last_run=10:00:00\n",
		"Home Assistant: ipv6ddns-test, connected since 2026-11-26T09:00:00Z\n    sensor.wan_ip (ipv6): \"2001:db8::1\"\n    (not announced: no address to announce)\n",
	} {
		if !strings.Contains(page, has) {
			t.Errorf("the report has no %q:\n%s", has, page)
		}
	}
	if hidden := w.Page("", true).String(); strings.Contains(hidden, cfg.HomeAssistant.Key) {
		t.Errorf("the hidden report has the key:\n%s", hidden)
	}
	if hidden, _ := json.Marshal(w.Status(true)); strings.Contains(string(hidden), secret) {
		t.Errorf("the hidden status has a secret: %s", hidden)
	}
}

// The configuration's warnings are in the status and the report's Config section alike, and the
// program's goroutines and heap in a line of the report, as the status's process.
func TestWarningsAndProcessInTheReport(t *testing.T) {
	cfg := config.Config{Warnings: []string{"discovery.ipv4 has settings but is off"}}
	w, err := NewWorker(zap.NewNop().Sugar(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.discWorker.State.Close)
	st := w.Status(true)
	data, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"warnings":["discovery.ipv4 has settings but is off"]`) || st.Process.Goroutines == 0 {
		t.Errorf("the status: %s", data)
	}
	page := w.Page("", true).String()
	for _, has := range []string{
		"    Warnings:\n        - discovery.ipv4 has settings but is off\n",
		"Process: ",
		" goroutines, heap ",
	} {
		if !strings.Contains(page, has) {
			t.Errorf("no %q in:\n%s", has, page)
		}
	}
}
