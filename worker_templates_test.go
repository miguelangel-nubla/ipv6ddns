package ipv6ddns

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/ddns"
	"github.com/miguelangel-nubla/ipv6disc"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// A task's host name that is a template is a name for each host its filters match, by what the
// host is called: {hostname} of all those of a name, {n}.{hostname} of each, in the MACs' order
// among those there now, {mac} of each by its MAC. A name written as it is stays that one's, and
// a host that leaves, or is renamed, has its names emptied.
func TestTemplates(t *testing.T) {
	cfg := loadConfig(t, `
credentials:
  fake:
    provider: fake
    debounce: 1ms
    settings:
      id: templates
tasks:
  lan:
    filter:
      - ip:
          prefix: 2001:db8::/64
    endpoints:
      fake:
        - "{hostname}"
        - "{n}.{hostname}"
        - "{mac}.hosts"
  written:
    filter:
      - mac:
          address: "00:00:00:00:00:0c"
    endpoints:
      fake:
        - nas
`)
	core, logs := observer.New(zap.WarnLevel)
	w, err := NewWorker(zap.New(core).Sugar(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.discWorker.State.Close)
	fake := fakeServices["templates"]
	const macC = "00:00:00:00:00:0c"
	name := func(mac, name string) {
		hw, _ := net.ParseMAC(mac)
		w.discWorker.RegisterName(hw, name, "test", time.Hour)
	}

	// wait waits until the last update of a name is of these addresses, in any order.
	wait := func(hostname string, want ...string) {
		t.Helper()
		slices.Sort(want)
		deadline := time.Now().Add(3 * time.Second)
		for {
			updates := fake.updatesOf(hostname)
			var last []string
			if len(updates) > 0 {
				last = slices.Sorted(slices.Values(updates[len(updates)-1]))
			}
			if len(updates) > 0 && slices.Equal(last, want) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: got updates %v, want the last to be %v", hostname, updates, want)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	// b before a, to tell the MACs' order from the order they came in.
	register(t, w, macB, "2001:db8::b", time.Hour)
	// a's addresses are to go, for it to leave.
	const short = 1500 * time.Millisecond
	register(t, w, macA, "2001:db8::a", short)
	register(t, w, macA, "2001:db8::a2", short)
	// Outside the task's filter: no name of the template's has it.
	register(t, w, macA, "2001:db8:1::a", short)
	register(t, w, macC, "2001:db8::c", time.Hour)
	name(macA, "printer")
	name(macB, "printer")
	name(macB, "laser")
	name(macC, "nas")
	w.lookForChanges()

	wait("printer", "2001:db8::a", "2001:db8::a2", "2001:db8::b")
	wait("1.printer", "2001:db8::a", "2001:db8::a2")
	wait("2.printer", "2001:db8::b")
	wait("laser", "2001:db8::b")
	wait("1.laser", "2001:db8::b")
	wait("00000000000a.hosts", "2001:db8::a", "2001:db8::a2")
	wait("00000000000b.hosts", "2001:db8::b")
	wait("00000000000c.hosts", "2001:db8::c")
	// The name written is its task's, with that task's addresses: the template's host of that name
	// isn't added to it, and is told once. Its numbered name is no name written: it is there.
	wait("nas", "2001:db8::c")
	wait("1.nas", "2001:db8::c")
	w.lookForChanges()
	warned := logs.FilterMessageSnippet("is written in the configuration, so it keeps").All()
	if len(warned) != 1 || !strings.Contains(warned[0].Message, `endpoint fake: nas.fake is written in the configuration, so it keeps its own addresses: hosts with that name, from the template "{hostname}" of task lan, are left out of it`) {
		t.Errorf("the name written, told: %v", warned)
	}
	if updates := fake.updatesOf("nas"); len(updates) != 1 {
		t.Errorf("the name written was updated %d times: %v", len(updates), updates)
	}

	// The status has them, as any name.
	var listed []string
	for _, h := range w.Status(true).Hostnames {
		listed = append(listed, h.Hostname)
	}
	if want := []string{"00000000000a.hosts", "00000000000b.hosts", "00000000000c.hosts", "1.laser", "1.nas", "1.printer", "2.printer", "laser", "nas", "printer"}; !slices.Equal(listed, want) {
		t.Errorf("the names of the status: %v, want %v", listed, want)
	}

	// a leaves: b is the first of its name now, and the second is no more.
	deadline := time.Now().Add(5 * time.Second)
	for w.discWorker.GetAll()[macA] != nil {
		if time.Now().After(deadline) {
			t.Fatal("a's addresses didn't expire")
		}
		time.Sleep(20 * time.Millisecond)
	}
	w.lookForChanges()
	wait("printer", "2001:db8::b")
	wait("1.printer", "2001:db8::b")
	wait("2.printer")
	wait("00000000000a.hosts")

	// Emptied at its provider, a name of a template is forgotten: the status has it no more.
	deadline = time.Now().Add(3 * time.Second)
	for {
		w.lookForChanges()
		listed = listed[:0]
		for _, h := range w.Status(true).Hostnames {
			listed = append(listed, h.Hostname)
		}
		if !slices.Contains(listed, "2.printer") && !slices.Contains(listed, "00000000000a.hosts") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the names emptied are still in the status: %v", listed)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !slices.Contains(listed, "1.printer") || !slices.Contains(listed, "nas") {
		t.Errorf("the names that stay: %v", listed)
	}

	// And back: its names are made again.
	register(t, w, macA, "2001:db8::a", time.Hour)
	name(macA, "printer")
	w.lookForChanges()
	wait("1.printer", "2001:db8::a")
	wait("2.printer", "2001:db8::b")

	for _, target := range w.targets {
		target.hostname.Stop()
	}
	w.dynamicMutex.Lock()
	for _, h := range w.dynamic {
		h.Stop()
	}
	w.dynamicMutex.Unlock()
}

// rateLimited is a provider that refuses the first updates of every name, as one that limits its
// requests does when many come at once, and takes those after.
type rateLimited struct {
	mutex   sync.Mutex
	refuse  int
	refused map[string]int
	records map[string][]string
	updates int
}

func (r *rateLimited) Update(hostname string, addresses *ipv6disc.AddrCollection) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.updates++
	if r.refused[hostname] < r.refuse {
		r.refused[hostname]++
		return errors.New("429 Too Many Requests")
	}
	r.records[hostname] = slices.Sorted(slices.Values(addresses.Strings()))
	return nil
}

func (r *rateLimited) Domain(hostname string) string { return hostname + ".limited" }

// Many hosts at once, each with its names of the templates, at a provider that refuses the first
// updates of each: every name has its addresses in the end, none is left out or mixed with
// another's, and none is asked without a pause.
func TestTemplatesAtAProviderThatLimits(t *testing.T) {
	limited := &rateLimited{refuse: 2, refused: map[string]int{}, records: map[string][]string{}}
	ddns.RegisterProvider("limited", func(json.RawMessage) (ddns.Service, error) { return limited, nil })
	cfg := loadConfig(t, `
credentials:
  limited:
    provider: limited
    debounce: 1ms
    retry: 1s
    settings: {}
tasks:
  lan:
    filter:
      - ip:
          prefix: 2001:db8::/64
    endpoints:
      limited:
        - "{hostname}"
        - "{n}.{hostname}"
`)
	w, err := NewWorker(zap.NewNop().Sugar(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.discWorker.State.Close)

	// Fifty hosts: forty of a name each, and ten that share one.
	const hosts = 50
	want := map[string][]string{}
	for i := range hosts {
		mac := fmt.Sprintf("00:00:00:00:01:%02x", i)
		ip := fmt.Sprintf("2001:db8::1:%x", i)
		register(t, w, mac, ip, time.Hour)
		name := fmt.Sprintf("host%02d", i)
		if i >= 40 {
			name = "shared"
			want[fmt.Sprintf("%d.shared", i-39)] = []string{ip}
		} else {
			want["1."+name] = []string{ip}
		}
		want[name] = append(want[name], ip)
		hw, _ := net.ParseMAC(mac)
		w.discWorker.RegisterName(hw, name, "test", time.Hour)
	}
	for _, addrs := range want {
		slices.Sort(addrs)
	}
	began := time.Now()
	w.lookForChanges()

	deadline := time.Now().Add(15 * time.Second)
	for {
		limited.mutex.Lock()
		done := len(limited.records) == len(want)
		limited.mutex.Unlock()
		if done {
			break
		}
		if time.Now().After(deadline) {
			limited.mutex.Lock()
			t.Fatalf("%d of %d names updated after 15s", len(limited.records), len(want))
		}
		time.Sleep(20 * time.Millisecond)
	}
	limited.mutex.Lock()
	defer limited.mutex.Unlock()
	for name, addrs := range want {
		if !slices.Equal(limited.records[name], addrs) {
			t.Errorf("%s has %v, want %v", name, limited.records[name], addrs)
		}
	}
	// Each name: refused twice, taken the third time, and no more; with the retry's pause
	// between, so not all at once.
	if got, most := limited.updates, len(want)*(limited.refuse+1); got != most {
		t.Errorf("%d updates for %d names refused %d times each: want %d", got, len(want), limited.refuse, most)
	}
	if took := time.Since(began); took < 2*time.Second {
		t.Errorf("all taken in %s: the refused ones were asked again without the retry's pause of 1s, twice", took)
	}

	for _, target := range w.targets {
		target.hostname.Stop()
	}
	w.dynamicMutex.Lock()
	for _, h := range w.dynamic {
		h.Stop()
	}
	w.dynamicMutex.Unlock()
}

// zoned is a provider of a zone, made by its settings: {"id": "...", "zone": "...", "learns":
// true}. With learns its Domain is as Route 53's: the name as written until the first update, a
// name of the zone after.
type zoned struct {
	mutex   sync.Mutex
	zone    string
	known   bool
	records map[string][]string
	// Each update, as "name [addresses]", in order.
	log []string
}

var (
	zonedMutex    sync.Mutex
	zonedServices = map[string]*zoned{}
)

func init() {
	ddns.RegisterProvider("zoned", func(settings json.RawMessage) (ddns.Service, error) {
		var s struct {
			ID, Zone string
			Learns   bool
		}
		if err := json.Unmarshal(settings, &s); err != nil || s.ID == "" {
			return nil, errors.New("zoned: no id")
		}
		service := &zoned{zone: s.Zone, known: !s.Learns, records: map[string][]string{}}
		zonedMutex.Lock()
		zonedServices[s.ID] = service
		zonedMutex.Unlock()
		return service, nil
	})
}

func (z *zoned) Update(hostname string, addresses *ipv6disc.AddrCollection) error {
	z.mutex.Lock()
	defer z.mutex.Unlock()
	z.known = true
	name := ddns.FQDN(hostname, z.zone)
	z.log = append(z.log, fmt.Sprintf("%s %v", name, addresses.Strings()))
	if len(addresses.Get()) == 0 {
		delete(z.records, name)
	} else {
		z.records[name] = addresses.Strings()
	}
	return nil
}

func (z *zoned) Domain(hostname string) string {
	z.mutex.Lock()
	defer z.mutex.Unlock()
	if !z.known {
		return ddns.FQDN(hostname, "")
	}
	return ddns.FQDN(hostname, z.zone)
}

// recordsOf are the records of a name, and every update so far.
func (z *zoned) recordsOf(name string) (records, log []string) {
	z.mutex.Lock()
	defer z.mutex.Unlock()
	return slices.Clone(z.records[name]), slices.Clone(z.log)
}

// zonedWorker is a worker of that configuration, and its provider of that id. Its names stop
// with the test.
func zonedWorker(t *testing.T, logger *zap.SugaredLogger, id, content string) (*Worker, *zoned) {
	t.Helper()
	w, err := NewWorker(logger, loadConfig(t, content))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, target := range w.targets {
			target.hostname.Stop()
		}
		w.dynamicMutex.Lock()
		for _, h := range w.dynamic {
			h.Stop()
		}
		w.dynamicMutex.Unlock()
		w.discWorker.State.Close()
	})
	zonedMutex.Lock()
	defer zonedMutex.Unlock()
	return w, zonedServices[id]
}

// named gives a host a name, as discovery learns it.
func named(w *Worker, mac, name string) {
	hw, _ := net.ParseMAC(mac)
	w.discWorker.RegisterName(hw, name, "test", time.Hour)
}

// rematched matches until the name has an address at the provider, and then twenty times more, as
// every ten seconds: the hosts are still there, each with its address.
func rematched(t *testing.T, w *Worker, z *zoned, name string) {
	t.Helper()
	w.lookForChanges()
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if got, _ := z.recordsOf(name); len(got) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no first update of %s", name)
		}
	}
	for range 20 {
		w.lookForChanges()
		time.Sleep(10 * time.Millisecond)
	}
	// Whatever the last matching scheduled is sent.
	time.Sleep(100 * time.Millisecond)
}

// At a provider that learns its zone at the first update, as Route 53, the name of a template's
// records changes then, from printer to printer.zone.test. It stays the one name it was: a second
// one, made for the new name, would have the first emptied, and its records removed while the host
// is there.
func TestTemplateAtAProviderThatLearnsItsZone(t *testing.T) {
	w, learns := zonedWorker(t, zap.NewNop().Sugar(), "learns", `
credentials:
  aws:
    provider: zoned
    debounce: 1ms
    settings:
      id: learns
      zone: zone.test
      learns: true
tasks:
  lan:
    filter:
      - ip:
          prefix: 2001:db8::/64
    endpoints:
      aws:
        - "{hostname}"
`)
	register(t, w, macA, "2001:db8::a", time.Hour)
	named(w, macA, "printer")
	rematched(t, w, learns, "printer.zone.test")

	got, log := learns.recordsOf("printer.zone.test")
	if !slices.Equal(got, []string{"2001:db8::a"}) {
		t.Errorf("the host is there, and its name has %v at the provider, want its address; the updates: %q", got, log)
	}
	if !slices.Equal(log, []string{"printer.zone.test [2001:db8::a]"}) {
		t.Errorf("the host never left nor changed, and its name was updated again: the updates: %q", log)
	}
	var listed []string
	for _, h := range w.Status(true).Hostnames {
		listed = append(listed, h.Hostname+" "+h.Domain)
	}
	if !slices.Equal(listed, []string{"printer printer.zone.test"}) {
		t.Errorf("the names of the status: %q, want the one", listed)
	}

	// And once the host leaves, the name's records are removed, and it is forgotten.
	w.expandTemplates(nil, nil)
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		w.expandTemplates(nil, nil)
		if got, _ := learns.recordsOf("printer.zone.test"); len(got) == 0 && len(w.Status(true).Hostnames) == 0 {
			break
		}
		if time.Now().After(deadline) {
			_, log := learns.recordsOf("printer.zone.test")
			t.Fatalf("the host left, and its name is still there: the updates: %q; the status: %+v", log, w.Status(true).Hostnames)
		}
	}
}

// A name written wins there too, before the zone is learned and after: a host that calls itself
// as a name written is left out of it, though the name written is nas.zone.test by then.
func TestWrittenNameWinsAtAProviderThatLearnsItsZone(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	w, learns := zonedWorker(t, zap.New(core).Sugar(), "learnswritten", `
credentials:
  aws:
    provider: zoned
    debounce: 1ms
    settings:
      id: learnswritten
      zone: zone.test
      learns: true
tasks:
  lan:
    filter:
      - ip:
          prefix: 2001:db8::/64
    endpoints:
      aws:
        - "{hostname}"
  written:
    filter:
      - mac:
          address: "00:00:00:00:00:0c"
    endpoints:
      aws:
        - nas
`)
	register(t, w, macC, "2001:db8::c", time.Hour)
	// Another host says it is nas too.
	register(t, w, macB, "2001:db8::b", time.Hour)
	named(w, macB, "nas")
	rematched(t, w, learns, "nas.zone.test")

	got, log := learns.recordsOf("nas.zone.test")
	if !slices.Equal(got, []string{"2001:db8::c"}) {
		t.Errorf("the name written has %v at the provider, want its own task's address alone; the updates: %q", got, log)
	}
	if !slices.Equal(log, []string{"nas.zone.test [2001:db8::c]"}) {
		t.Errorf("the updates: %q, want the one of the name written", log)
	}
	if n := len(w.Status(true).Hostnames); n != 1 {
		t.Errorf("%d names in the status, want the one written", n)
	}
	// Told as the name is then: once before the zone is learned, once after.
	if warned := logs.FilterMessageSnippet("is written in the configuration, so it keeps").All(); len(warned) != 2 ||
		!strings.Contains(warned[0].Message, "endpoint aws: nas is written") || !strings.Contains(warned[1].Message, "endpoint aws: nas.zone.test is written") {
		t.Errorf("the name written, told: %v", warned)
	}
}

// Two templates that make two names until the zone is learned, printer and printer.zone.test,
// and one after: they become one name, with nothing removed, and its records are the host's.
func TestTemplatesThatAreOneNameOnceTheZoneIsLearned(t *testing.T) {
	w, learns := zonedWorker(t, zap.NewNop().Sugar(), "learnsone", `
credentials:
  aws:
    provider: zoned
    debounce: 1ms
    settings:
      id: learnsone
      zone: zone.test
      learns: true
tasks:
  lan:
    filter:
      - ip:
          prefix: 2001:db8::/64
    endpoints:
      aws:
        - "{hostname}"
        - "{hostname}.zone.test"
`)
	register(t, w, macA, "2001:db8::a", time.Hour)
	named(w, macA, "printer")
	rematched(t, w, learns, "printer.zone.test")

	got, log := learns.recordsOf("printer.zone.test")
	if !slices.Equal(got, []string{"2001:db8::a"}) {
		t.Errorf("the host is there, and its name has %v at the provider, want its address; the updates: %q", got, log)
	}
	if slices.Contains(log, "printer.zone.test []") {
		t.Errorf("the host never left, and its name's records were removed: the updates: %q", log)
	}
	if n := len(w.Status(true).Hostnames); n != 1 {
		t.Errorf("%d names in the status, want one: %+v", n, w.Status(true).Hostnames)
	}
	w.dynamicMutex.Lock()
	defer w.dynamicMutex.Unlock()
	if len(w.dynamic) != 1 {
		t.Errorf("%d names of the templates kept, want one", len(w.dynamic))
	}
}

// A template never names the zone itself. Where a name written in full is itself, as lan of the
// zone lan, a host that calls itself lan would have its addresses in the zone's own records: it is
// left out, and told once. The zone written in a task as it is has its own task's addresses.
func TestTemplateNeverNamesTheZone(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	w, lan := zonedWorker(t, zap.New(core).Sugar(), "lan", `
credentials:
  router:
    provider: zoned
    debounce: 1ms
    settings:
      id: lan
      zone: lan
tasks:
  lan:
    filter:
      - ip:
          prefix: 2001:db8::/64
    endpoints:
      router:
        - "{hostname}"
  written:
    filter:
      - mac:
          address: "00:00:00:00:00:0c"
    endpoints:
      router:
        - lan
`)
	register(t, w, macA, "2001:db8::a", time.Hour)
	named(w, macA, "printer")
	// A host that says it is called as the zone.
	register(t, w, macB, "2001:db8::b", time.Hour)
	named(w, macB, "lan")
	register(t, w, macC, "2001:db8::c", time.Hour)
	rematched(t, w, lan, "printer.lan")

	_, log := lan.recordsOf("lan")
	slices.Sort(log)
	if want := []string{"lan [2001:db8::c]", "printer.lan [2001:db8::a]"}; !slices.Equal(log, want) {
		t.Errorf("the updates: %q, want %q: the zone's own records are its task's, and no host's", log, want)
	}
	warned := logs.FilterMessageSnippet("which is the zone itself").All()
	if want := `endpoint router: the template "{hostname}" of task lan gives a host the name lan, which is the zone itself: the host is left out of it, and the zone's own records stay as they are. Only a name written in a task as it is, not a template's, can be the zone`; len(warned) != 1 || warned[0].Message != want {
		t.Errorf("the host called as the zone, told: %v, want once %q", warned, want)
	}
}
