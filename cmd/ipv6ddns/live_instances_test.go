//go:build linux && integration

package main

// Several instances at once, as the command: two on one machine, each with its configuration, and
// two on two machines of one link. Each must do what it would alone.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/internal/livetest"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/esphome"
)

// Two instances on one machine, of different configurations: the first of IPv6 alone, with a key
// of its own for Home Assistant, the second of both families, with the key Home Assistant gives.
// Each updates its own DNS server with what it discovers, serves its own state at its own port,
// and is its own device to Home Assistant, which finds the two by mDNS. One stops and starts
// again, and the other goes on as it was.
func TestLiveTwoInstancesOneMachine(t *testing.T) {
	lan := livetest.NewLAN(t, 11)
	router := lan.Router
	machine := lan.Machine(t, "machine", 10)
	peer := lan.Machine(t, "peer", 20)
	hass := lan.Machine(t, "hass", 30)

	dnsOne := startProvider(t, router, 5381, "token-one", "one.example")
	dnsTwo := startProvider(t, router, 5382, "token-two", "two.example")
	keyOne := esphome.GenerateKey()

	one := configure(t, machine, router, "one", 8053, fmt.Sprintf(`
webserver:
  listen:
    - "%s:8053"
homeassistant:
  name: ipv6ddns-one
  friendly_name: The first
  key: %s
  listen: 6053
discovery:
  lifetime: 9s
  rediscover: 3s
tasks:
  peer:
    filter:
      - mac:
          address: "%s"
        ip:
          prefix: "%s"
    endpoints:
      first:
        - peer
  machine:
    filter:
      - self: true
        ip:
          prefix: "%s"
    endpoints:
      first:
        - machine
credentials:
%s`, machine.IPv4, keyOne, peer.MAC, lan.Prefix(), lan.Prefix(), dnsOne.credential("first", "1s")))

	two := configure(t, machine, router, "two", 8054, fmt.Sprintf(`
webserver:
  listen:
    - 8054
homeassistant:
  name: ipv6ddns-two
  friendly_name: The second
  key_provisioning: true
  key_provisioning_state_file: two.state
  listen: "%s:6054"
discovery:
  lifetime: 12s
  rediscover: 4s
  ipv4:
    enabled: true
    lifetime: 2m
tasks:
  peer:
    filter:
      - mac:
          address: "%s"
        ip:
          prefix: "%s"
      - mac:
          address: "%s"
        ip:
          family:
            - 4
    endpoints:
      second:
        - other
credentials:
%s`, machine.IPv4, peer.MAC, lan.Prefix(), peer.MAC, dnsTwo.credential("second", "2s")))

	ha := startHomeAssistant(t, hass)
	one.start()
	two.start()
	one.serving()
	two.serving()

	// Each updates its own server with what its own tasks take, of what it discovers itself: the
	// peer's IPv4 address is the second's only, which reads the system's table the first doesn't.
	waitFor(t, 60*time.Second, "peer's address at the first's server", func() bool { return dnsOne.has("peer.one.example", peer.IPv6) }, dnsOne.tells, one.tells)
	waitFor(t, 60*time.Second, "machine's address at the first's server", func() bool { return dnsOne.has("machine.one.example", machine.IPv6) }, dnsOne.tells, one.tells)
	waitFor(t, 60*time.Second, "peer's addresses at the second's server", func() bool { return dnsTwo.has("other.two.example", peer.IPv4, peer.IPv6) }, dnsTwo.tells, two.tells)
	for _, addresses := range one.status().Discovered {
		for _, a := range addresses.Addresses {
			if !strings.Contains(a.Address, ":") {
				t.Errorf("the first, of IPv6 alone, has %s at %s", a.Address, addresses.MAC)
			}
		}
	}
	for _, i := range []*instance{one, two} {
		if addresses, self := i.discovered(machine.MAC); !self || !slices.Contains(addresses, machine.IPv6) {
			t.Errorf("%s has, as its own machine's: %v, %v", i.name, addresses, self)
		}
		if _, self := i.discovered(peer.MAC); self {
			t.Errorf("%s has the peer as its own machine", i.name)
		}
	}

	// Each serves its own state at its own port: its names, at its endpoint, and none of the
	// other's.
	for _, of := range []struct {
		i                   *instance
		endpoint, name, not string
	}{
		{one, "first", "peer.one.example", "other.two.example"},
		{two, "second", "other.two.example", "peer.one.example"},
	} {
		for _, h := range of.i.status().Hostnames {
			if h.Endpoint != of.endpoint || h.Provider != "technitium" || h.LastError != "" || h.Updates == 0 {
				t.Errorf("%s: /status.json has the name %+v", of.i.name, h)
			}
		}
		for _, page := range []string{"/", "/metrics", "/status.json"} {
			body := of.i.page(page)
			if !strings.Contains(body, of.name) || strings.Contains(body, of.not) {
				t.Errorf("%s: %s isn't its own state, with %s and without %s:\n%s", of.i.name, page, of.name, of.not, body)
			}
		}
		if metrics := of.i.page("/metrics"); !strings.Contains(metrics, `ipv6ddns_hostname_last_update_failed{provider="technitium",endpoint="`+of.endpoint+`",hostname="`+of.name+`"} 0`) {
			t.Errorf("%s: /metrics:\n%s", of.i.name, metrics)
		}
	}
	if requests, refused := dnsOne.asked(); refused != 0 {
		t.Errorf("the first's server refused %d of %d requests: the second's credential came to it", refused, requests)
	}
	if requests, refused := dnsTwo.asked(); refused != 0 {
		t.Errorf("the second's server refused %d of %d requests: the first's credential came to it", refused, requests)
	}

	// Home Assistant finds two devices, each at its port, at the machine's address: the first
	// with its key, the second waiting for one.
	isOne := func(s haService) bool { return s.Port == 6053 && s.Encryption }
	foundOne := ha.found("ipv6ddns-one", 30*time.Second, "at 6053, with a key", isOne)
	foundTwo := ha.found("ipv6ddns-two", 30*time.Second, "at 6054, without a key", func(s haService) bool { return s.Port == 6054 && !s.Encryption })
	for _, s := range []haService{foundOne, foundTwo} {
		if !slices.Equal(s.Addresses, []string{machine.IPv4.String()}) || s.Host != s.Name+".local." || s.MAC == "" {
			t.Errorf("announced: %+v, want at %s, as %s.local.", s, machine.IPv4, s.Name)
		}
	}
	if foundOne.MAC == foundTwo.MAC {
		t.Errorf("the two devices are one to Home Assistant: both announce the MAC %s", foundOne.MAC)
	}
	if foundOne.FriendlyName != "The first" || foundTwo.FriendlyName != "The second" {
		t.Errorf("announced as %q and %q", foundOne.FriendlyName, foundTwo.FriendlyName)
	}

	// It gives the second its key, as when adding it: the second announces itself again, with
	// it, and the first's announcement stays.
	keyTwo := esphome.GenerateKey()
	before := ha.now()
	ha.giveKey(foundTwo, keyTwo)
	foundTwo = ha.found("ipv6ddns-two", 30*time.Second, "with the key given", func(s haService) bool { return s.Port == 6054 && s.Encryption })
	if ha.removed(before, "ipv6ddns-one") {
		t.Errorf("the second announced itself again, and the first's announcement went\n%s", ha.tells())
	}
	if _, err := os.Stat(filepath.Join(two.folder, "two.state")); err != nil {
		t.Errorf("the second's state file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(one.folder, "homeassistant.state")); err == nil {
		t.Error("the first, with a key of its own, made a state file")
	}

	// Each device takes its own key only, and has its own instance's entities and states.
	var deviceOne, deviceTwo haDevice
	waitFor(t, 30*time.Second, "peer's address as the state of the first's entity", func() bool {
		deviceOne = ha.connected(foundOne, keyOne)
		return deviceOne.States["first_peer_addresses"] == peer.IPv6.String()
	}, ha.tells)
	waitFor(t, 30*time.Second, "peer's addresses as the state of the second's entity", func() bool {
		deviceTwo = ha.connected(foundTwo, keyTwo)
		return deviceTwo.States["second_other_addresses"] == peer.IPv4.String()+", "+peer.IPv6.String()
	}, ha.tells)
	if deviceOne.Name != "ipv6ddns-one" || deviceOne.FriendlyName != "The first" || !sameMAC(deviceOne.MAC, foundOne.MAC) ||
		!slices.Contains(deviceOne.Entities, "first_machine_addresses") || slices.ContainsFunc(deviceOne.Entities, func(id string) bool { return strings.HasPrefix(id, "second_") }) {
		t.Errorf("the first device, announced with the MAC %s: %+v", foundOne.MAC, deviceOne)
	}
	if deviceTwo.Name != "ipv6ddns-two" || deviceTwo.FriendlyName != "The second" || !sameMAC(deviceTwo.MAC, foundTwo.MAC) ||
		slices.ContainsFunc(deviceTwo.Entities, func(id string) bool { return strings.HasPrefix(id, "first_") }) {
		t.Errorf("the second device, announced with the MAC %s: %+v", foundTwo.MAC, deviceTwo)
	}
	if device, _ := ha.connect(foundOne, keyTwo); device != nil {
		t.Errorf("the first took the second's key: %+v", device)
	}
	if device, _ := ha.connect(foundTwo, keyOne); device != nil {
		t.Errorf("the second took the first's key: %+v", device)
	}

	// The peer leaves: both take its address off their records, each after its own lifetime,
	// and keep the rest. Its IPv4 address stays for its own lifetime, which is longer.
	peer.Leave(t)
	left := time.Now()
	waitFor(t, 40*time.Second, "peer's address off the first's server", func() bool { return dnsOne.has("peer.one.example") }, dnsOne.tells, one.tells)
	t.Logf("off the first's server %s after the peer left, with a lifetime of 9s", time.Since(left).Round(100*time.Millisecond))
	waitFor(t, 40*time.Second, "peer's address off the second's server", func() bool { return dnsTwo.has("other.two.example", peer.IPv4) }, dnsTwo.tells, two.tells)
	t.Logf("off the second's server %s after the peer left, with a lifetime of 12s", time.Since(left).Round(100*time.Millisecond))
	if one.knows(peer.MAC, peer.IPv6) || two.knows(peer.MAC, peer.IPv6) {
		t.Error("an instance still has the address of the peer that left")
	}
	if !dnsOne.has("machine.one.example", machine.IPv6) {
		t.Errorf("the machine's own record went with the peer's\n%s", dnsOne.tells())
	}
	peer.Return(t)
	waitFor(t, 60*time.Second, "peer's address back at the first's server", func() bool { return dnsOne.has("peer.one.example", peer.IPv6) }, dnsOne.tells, one.tells)
	waitFor(t, 60*time.Second, "peer's address back at the second's server", func() bool { return dnsTwo.has("other.two.example", peer.IPv4, peer.IPv6) }, dnsTwo.tells, two.tells)

	// A third instance at a port another has doesn't start, and says which: the web server's,
	// then the device's. It updates nothing, and Home Assistant never sees it.
	dnsThree := startProvider(t, router, 5383, "token-three", "three.example")
	third := func(webPort, devicePort int) string {
		return fmt.Sprintf(`
webserver:
  listen:
    - %d
homeassistant:
  name: ipv6ddns-three
  listen:
    - %d
  key_provisioning: true
discovery:
  lifetime: 9s
  rediscover: 3s
tasks:
  peer:
    filter:
      - mac:
          address: "%s"
    endpoints:
      third:
        - peer
credentials:
%s`, webPort, devicePort, peer.MAC, dnsThree.credential("third", "0s"))
	}
	for _, taken := range []struct {
		what                string
		webPort, devicePort int
		names               string
	}{
		{"the second's web server's port", 8054, 6055, ":8054"},
		{"the first's web server's port, at its address", 8053, 6055, ":8053"},
		{"the first's device's port", 8055, 6053, ":6053"},
		{"the second's device's port, at its address", 8055, 6054, ":6054"},
	} {
		wrote := configure(t, machine, router, "three", taken.webPort, third(taken.webPort, taken.devicePort)).start().fails()
		if !strings.Contains(wrote, "address already in use") || !strings.Contains(wrote, taken.names) {
			t.Errorf("at %s, the third ended without saying the address is taken, %s:\n%s", taken.what, taken.names, wrote)
		}
	}
	time.Sleep(3 * time.Second)
	if requests, _ := dnsThree.asked(); requests != 0 {
		t.Errorf("the third, which didn't start, asked its server %d times\n%s", requests, dnsThree.tells())
	}
	if slices.ContainsFunc(ha.since(0), func(e haEvent) bool { return e.Service != nil && e.Service.Name == "ipv6ddns-three" }) {
		t.Errorf("the third, which didn't start, was announced\n%s", ha.tells())
	}
	for _, i := range []*instance{one, two} {
		i.serving()
	}
	if s := ha.query("ipv6ddns-one"); s == nil || !isOne(*s) {
		t.Errorf("the first's device isn't announced as it was, after a third tried its ports: %+v", s)
	}

	// The first stops: its announcement is taken back, and its ports are free. The second's
	// stays, for a Home Assistant that starts now too, and it goes on discovering and updating.
	before = ha.now()
	writesOne := len(dnsOne.changes())
	one.terminate()
	ha.await(before, 20*time.Second, "the first's announcement taken back", func(e haEvent) bool { return e.Removed == "ipv6ddns-one" })
	for _, port := range []int{8053, 6053} {
		if !refused(t, router, machine, port) {
			t.Errorf("the first stopped, and its port %d still listens", port)
		}
	}
	peer.Leave(t)
	waitFor(t, 40*time.Second, "peer's address off the second's server, the first stopped", func() bool { return dnsTwo.has("other.two.example", peer.IPv4) }, dnsTwo.tells, two.tells)
	if ha.removed(before, "ipv6ddns-two") {
		t.Errorf("the first stopped, and the second's announcement went\n%s", ha.tells())
	}
	if s := ha.query("ipv6ddns-two"); s == nil || s.Port != 6054 || !s.Encryption || !slices.Equal(s.Addresses, []string{machine.IPv4.String()}) {
		t.Errorf("the first stopped, and a query for the second finds %+v", s)
	}
	if s := ha.query("ipv6ddns-one"); s != nil {
		t.Errorf("the first stopped, and a query for it finds %+v", s)
	}
	if device := ha.connected(foundTwo, keyTwo); device.Name != "ipv6ddns-two" {
		t.Errorf("the first stopped, and the second's device is %+v", device)
	}
	if strings.Contains(two.page("/"), "one.example") || two.hostname("other.two.example").LastError != "" {
		t.Errorf("the first stopped, and the second serves:\n%s", two.page("/"))
	}
	if writes := dnsOne.changes(); len(writes) != writesOne {
		t.Errorf("the first stopped, and its server was written to: %v", writes[writesOne:])
	}

	// The first starts again: the same device, at the same port, and it updates its server with
	// what is there now.
	before = ha.now()
	one.start().serving()
	peer.Return(t)
	ha.await(before, 30*time.Second, "the first's announcement again", func(e haEvent) bool {
		return e.Service != nil && e.Service.Name == "ipv6ddns-one" && isOne(*e.Service) && e.Service.MAC == foundOne.MAC
	})
	waitFor(t, 60*time.Second, "peer's address at the first's server, started again", func() bool { return dnsOne.has("peer.one.example", peer.IPv6) }, dnsOne.tells, one.tells)
	waitFor(t, 60*time.Second, "peer's address at the second's server, the first started again", func() bool { return dnsTwo.has("other.two.example", peer.IPv4, peer.IPv6) }, dnsTwo.tells, two.tells)
	if device := ha.connected(foundOne, keyOne); device.Name != "ipv6ddns-one" || !sameMAC(device.MAC, foundOne.MAC) {
		t.Errorf("the first, started again, is the device %+v", device)
	}
	if ha.removed(before, "ipv6ddns-two") {
		t.Errorf("the first started again, and the second's announcement went\n%s", ha.tells())
	}

	one.terminate()
	two.terminate()
	for _, i := range []*instance{one, two} {
		if errors := i.logged("error"); len(errors) != 0 {
			t.Errorf("%s logged errors:\n%s", i.name, strings.Join(errors, "\n"))
		}
	}
	for _, w := range slices.Concat(dnsOne.changes(), dnsTwo.changes(), dnsThree.changes()) {
		if w.from != machine.IPv4 {
			t.Errorf("a write that isn't the machine's: %s", w)
		}
	}
}

// A second instance that would be the first's device over again, to Home Assistant, isn't: left
// with the first's state file, as two configurations in one folder that name none, it doesn't
// start; left with its name, on the same machine or on another, or with a copy of its identity,
// it runs and updates, and doesn't announce itself, which it says. The first's device stays as it
// was all along, and the second is found once it has a name of its own.
func TestLiveInstancesOfOneDevice(t *testing.T) {
	lan := livetest.NewLAN(t, 12)
	router := lan.Router
	machine := lan.Machine(t, "machine", 10)
	other := lan.Machine(t, "other", 11)
	hass := lan.Machine(t, "hass", 30)
	dns := startProvider(t, router, 5381, "token", "one.example")

	config := func(name string, webPort, devicePort int, device string) string {
		return fmt.Sprintf(`
webserver:
  listen:
    - %d
homeassistant:
  listen:
    - %d
  key_provisioning: true
%s
tasks:
  machine:
    filter:
      - self: true
        ip:
          prefix: "%s"
    endpoints:
      dns:
        - %s
credentials:
%s`, webPort, devicePort, device, lan.Prefix(), name, dns.credential("dns", "1s"))
	}

	ha := startHomeAssistant(t, hass)
	folder := t.TempDir()
	first := configureIn(t, machine, router, "the first", folder, "first.yaml", 8053, config("first", 8053, 6053, "")).start().serving()
	isFirst := func(s haService) bool {
		return s.Port == 6053 && slices.Equal(s.Addresses, []string{machine.IPv4.String()})
	}
	found := ha.found("ipv6ddns", 30*time.Second, "at 6053", isFirst)
	waitFor(t, 30*time.Second, "machine's address at the server, by the first", func() bool { return dns.has("first.one.example", machine.IPv6) }, dns.tells, first.tells)
	unchanged := func(after string) {
		t.Helper()
		if s := ha.query("ipv6ddns"); s == nil || !isFirst(*s) || s.MAC != found.MAC {
			t.Errorf("%s, a query for the first's device, %+v, finds %+v", after, found, s)
		}
		for _, e := range ha.since(0) {
			if s := e.Service; e.Removed == "ipv6ddns" || s != nil && (s.MAC == found.MAC || s.Name == "ipv6ddns") && (*s).Port != 6053 {
				t.Errorf("%s, the first's device isn't what Home Assistant saw all along\n%s", after, ha.tells())
				break
			}
		}
	}

	// In the first's folder, with another port and no more: the same state file.
	wrote := configureIn(t, machine, router, "the second, of the first's state file", folder, "second.yaml", 8054, config("second", 8054, 6054, "")).start().fails()
	if !strings.Contains(wrote, filepath.Join(folder, "homeassistant.state")) || !strings.Contains(wrote, "another ipv6ddns") {
		t.Errorf("with the first's state file, the second ended without saying so:\n%s", wrote)
	}
	time.Sleep(3 * time.Second)
	if requests, _ := dns.asked(); dns.has("second.one.example", machine.IPv6) {
		t.Errorf("the second, which didn't start, updated its name, in %d requests\n%s", requests, dns.tells())
	}
	unchanged("after a second with its state file")

	// With a state file of its own, and the first's name: on the same machine, and on another.
	for _, at := range []struct {
		what string
		m    *livetest.Machine
	}{{"on its machine", machine}, {"on another machine", other}} {
		second := configure(t, at.m, router, "the second, of the first's name, "+at.what, 8054, config("second", 8054, 6054, "")).start().serving()
		waitFor(t, 30*time.Second, "address at the server, by the second, of the first's name, "+at.what, func() bool { return dns.has("second.one.example", at.m.IPv6) }, dns.tells, second.tells)
		// It has a device all the same, for who adds it by its address.
		if device := ha.connected(haService{Name: "ipv6ddns", Addresses: []string{at.m.IPv4.String()}, Port: 6054}, ""); sameMAC(device.MAC, found.MAC) {
			t.Errorf("the second, of the first's name, %s, has its MAC too: %+v", at.what, device)
		}
		time.Sleep(3 * time.Second)
		unchanged("with a second of its name, " + at.what)
		if !slices.ContainsFunc(second.logged("error"), func(line string) bool {
			return strings.Contains(line, "another device is announced with the name ipv6ddns") && strings.Contains(line, machine.IPv4.String())
		}) {
			t.Errorf("the second, of the first's name, %s, didn't say so:\n%s", at.what, second.output.String())
		}
		second.terminate()
		time.Sleep(2 * time.Second)
		unchanged("after a second of its name, " + at.what)
	}

	// With a name of its own, and a copy of the first's state file: its MAC, on another machine.
	state, err := os.ReadFile(filepath.Join(folder, "homeassistant.state"))
	if err != nil {
		t.Fatal(err)
	}
	copied := configure(t, other, router, "the second, of the first's identity", 8054, config("second", 8054, 6054, "  name: ipv6ddns-second"))
	if err := os.WriteFile(filepath.Join(copied.folder, "homeassistant.state"), state, 0o600); err != nil {
		t.Fatal(err)
	}
	copied.start().serving()
	waitFor(t, 30*time.Second, "address at the server, by the second, of the first's identity", func() bool { return dns.has("second.one.example", other.IPv6) }, dns.tells, copied.tells)
	time.Sleep(3 * time.Second)
	if s := ha.service("ipv6ddns-second"); s != nil {
		t.Errorf("the second, of the first's identity, was announced, a second name of one device to Home Assistant: %+v", s)
	}
	if !slices.ContainsFunc(copied.logged("error"), func(line string) bool {
		return strings.Contains(line, "another device is announced with the MAC of ipv6ddns-second, as ipv6ddns")
	}) {
		t.Errorf("the second, of the first's identity, didn't say so:\n%s", copied.output.String())
	}
	copied.terminate()
	unchanged("after a second of its identity")

	// With a name and a state file of its own, it is a device of its own, found as the first.
	second := configure(t, machine, router, "the second, of its own name", 8054, config("second", 8054, 6054, "  name: ipv6ddns-second")).start().serving()
	if s := ha.found("ipv6ddns-second", 30*time.Second, "at 6054", func(s haService) bool { return s.Port == 6054 }); s.MAC == found.MAC {
		t.Errorf("the second, of its own name and state file, has the first's MAC: %+v", s)
	}
	if errors := second.logged("error"); len(errors) != 0 {
		t.Errorf("the second, of its own name, logged errors:\n%s", strings.Join(errors, "\n"))
	}
	second.terminate()
	unchanged("after a second with its own name")

	// The first stopped, its state file is free: the second takes it, and is that device.
	first.terminate()
	if errors := first.logged("error"); len(errors) != 0 {
		t.Errorf("the first logged errors:\n%s", strings.Join(errors, "\n"))
	}
	before := ha.now()
	heir := configureIn(t, machine, router, "the second, once the first stopped", folder, "second.yaml", 8054, config("second", 8054, 6054, "")).start().serving()
	ha.await(before, 30*time.Second, "announcement of the first's device by the second, once the first stopped", func(e haEvent) bool {
		return e.Service != nil && e.Service.Name == "ipv6ddns" && e.Service.Port == 6054 && e.Service.MAC == found.MAC
	})
	heir.terminate()

	// What answers with the first's name, its MAC, its port and its address is the first itself,
	// as it was announced before: a reflector of mDNS, on another machine, still answers so when
	// the first starts again. It is no other device: the first announces itself, and says nothing.
	reflector := other.Command(livetest.Python(t), "testdata/reflector.py", other.IPv4.String(), "ipv6ddns", found.MAC, "6053", machine.IPv4.String())
	input, err := reflector.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := reflector.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := reflector.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		input.Close()
		reflector.Process.Kill()
		reflector.Wait()
	})
	if line, err := bufio.NewReader(output).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("the reflector: %q, %v", line, err)
	}
	waitFor(t, 20*time.Second, "answer of the reflector for the first's device", func() bool {
		s := ha.query("ipv6ddns")
		return s != nil && isFirst(*s) && s.MAC == found.MAC && s.FriendlyName == "reflected"
	}, ha.tells)
	before = ha.now()
	first.start().serving()
	ha.await(before, 30*time.Second, "announcement of the first's device by itself, with a reflector answering for it", func(e haEvent) bool {
		return e.Service != nil && e.Service.Name == "ipv6ddns" && isFirst(*e.Service) && e.Service.MAC == found.MAC && e.Service.FriendlyName == found.FriendlyName
	})
	first.terminate()
	if errors := first.logged("error"); len(errors) != 0 {
		t.Errorf("the first, started again with a reflector answering for it, logged errors:\n%s", strings.Join(errors, "\n"))
	}
}

// Two instances on two machines of one link, a and b, with a plain host, the peer, and the router:
// each hears what the other sends. Each discovers the peer and the other's machine as it would
// alone, with their real addresses at their real MACs, and only its own machine as its own; what
// a alone asks for, the addresses of a MAC nobody has, and the peer's IPv4 address, gives b
// nothing; a sends on the link what it sent before b started; a name both keep at one server has
// the addresses both found, written once; and the peer that leaves goes from each after its own
// lifetime.
func TestLiveTwoInstancesTwoMachines(t *testing.T) {
	lan := livetest.NewLAN(t, 13)
	router := lan.Router
	a := lan.Machine(t, "a", 10)
	b := lan.Machine(t, "b", 11)
	peer := lan.Machine(t, "peer", 20)
	// The peer's stable address, which it never sends from: deprecated. Only who asks for it,
	// with a solicitation, finds it.
	stable := livetest.EUI64(lan.Prefix(), peer.MAC)
	peer.IP(t, "addr", "add", stable.String()+"/64", "dev", peer.Interface, "nodad", "preferred_lft", "0")
	// A MAC no machine has, and the address it would make: of the solicited-node group of b's
	// link-local address, which ends as it, so b's machine takes every solicitation for it, and
	// b's instance hears what a asks.
	ghostMAC := "02:00:01" + b.MAC[8:]
	ghost := livetest.EUI64(lan.Prefix(), ghostMAC)
	if group := func(ip netip.Addr) [3]byte { return [3]byte(ip.AsSlice()[13:]) }; group(ghost) != group(b.LinkLocal()) {
		t.Fatalf("%s isn't of the solicited-node group of %s", ghost, b.LinkLocal())
	}

	dnsA := startProvider(t, router, 5381, "token-a", "a.example")
	dnsB := startProvider(t, router, 5382, "token-b", "b.example")
	dnsPair := startProvider(t, router, 5383, "token-pair", "pair.example")
	keyA, keyB := esphome.GenerateKey(), esphome.GenerateKey()

	// What both have: the peer's addresses, its stable one asked for; their own machine's; the
	// other's machine's; and the peer's again at the server they share, under one name.
	config := func(name, key, lifetime, rediscover, discovery string, own *provider, mate *livetest.Machine, more string) string {
		return fmt.Sprintf(`
webserver:
  listen:
    - 8053
homeassistant:
  name: ipv6ddns-%[2]s
  key: %[3]s
  listen: 6053
discovery:
  lifetime: %[1]s
  rediscover: %[4]s
%[5]s
tasks:
  peer:
    filter:
      - mac:
          address: "%[6]s"
        ip:
          prefix: "%[7]s"
      - mac:
          address: "%[6]s"
        ip:
          prefix: "%[7]s"
          type:
            - eui64
    endpoints:
      own:
        - peer
      pair:
        - ha
  me:
    filter:
      - self: true
        ip:
          prefix: "%[7]s"
    endpoints:
      own:
        - me
  mate:
    filter:
      - mac:
          address: "%[8]s"
        ip:
          prefix: "%[7]s"
    endpoints:
      own:
        - mate
%[9]s
credentials:
%[10]s%[11]s`, lifetime, name, key, rediscover, discovery, peer.MAC, lan.Prefix(), mate.MAC, more, own.credential("own", "1s"), dnsPair.credential("pair", "1s"))
	}
	// a alone asks: for the peer's IPv4 address, and for the addresses of the MAC nobody has.
	instanceA := configure(t, a, router, "a", 8053, config("a", keyA, "9s", "3s", `  ipv4:
    enabled: true
    active: false
    lifetime: 2m
  solicit:
    ipv6: true
    ipv4: true`, dnsA, b, fmt.Sprintf(`  peer4:
    filter:
      - mac:
          address: "%s"
        ip:
          family:
            - 4
    endpoints:
      own:
        - peer4
  ghost:
    filter:
      - mac:
          address: "%s"
        ip:
          type:
            - eui64
      - mac:
          address: "%s"
        ip:
          family:
            - 4
    endpoints:
      own:
        - ghost`, peer.MAC, ghostMAC, ghostMAC)))
	// b takes every IPv4 address it comes to know, whoever has it.
	instanceB := configure(t, b, router, "b", 8053, config("b", keyB, "12s", "4s", `  ipv4:
    enabled: true
    active: false
    lifetime: 2m
  solicit:
    ipv6: true`, dnsB, a, `  ipv4:
    filter:
      - ip:
          family:
            - 4
          prefix: "198.18.13.0/24"
    endpoints:
      own:
        - ipv4`))

	// What is true of the link: the addresses each MAC has.
	truth := map[string][]netip.Addr{peer.MAC: {stable}}
	for _, m := range []*livetest.Machine{router, a, b, peer} {
		truth[m.MAC] = append(truth[m.MAC], m.IPv4, m.IPv6, m.LinkLocal())
	}

	ha := startHomeAssistant(t, router)
	// What goes out on the link all along, and in a while, sent.
	all, sent := lan.Capture(t), lan.Capture(t)
	// What a sends in a while, of each kind, and the addresses it solicits, once it has found
	// everything.
	const while = 15 * time.Second
	counted := func() (map[string]int, map[netip.Addr]int) {
		time.Sleep(3 * time.Second)
		sent.Reset()
		time.Sleep(while)
		return sent.From(a.MAC), sent.Solicited(a.MAC)
	}

	// a alone, the other machine there without an instance.
	instanceA.start().serving()
	waitFor(t, 60*time.Second, "peer's addresses at a's server", func() bool { return dnsA.has("peer.a.example", peer.IPv6, stable) }, dnsA.tells, instanceA.tells)
	waitFor(t, 60*time.Second, "peer's IPv4 address at a's server", func() bool { return dnsA.has("peer4.a.example", peer.IPv4) }, dnsA.tells, instanceA.tells)
	waitFor(t, 60*time.Second, "b's machine's addresses at a's server", func() bool { return dnsA.has("mate.a.example", b.IPv6) }, dnsA.tells, instanceA.tells)
	waitFor(t, 60*time.Second, "peer's addresses at the server of both, by a", func() bool { return dnsPair.has("ha.pair.example", peer.IPv6, stable) }, dnsPair.tells, instanceA.tells)
	alone, aloneAsked := counted()
	if silent := sent.From(b.MAC); silent["multicast ping"] != 0 || silent["ssdp"] != 0 || silent["wsd"] != 0 {
		t.Fatalf("b's machine, without an instance, probes: %v", silent)
	}

	// Both.
	instanceB.start().serving()
	waitFor(t, 60*time.Second, "peer's addresses at b's server", func() bool { return dnsB.has("peer.b.example", peer.IPv6, stable) }, dnsB.tells, instanceB.tells)
	waitFor(t, 60*time.Second, "a's machine's addresses at b's server", func() bool { return dnsB.has("mate.b.example", a.IPv6) }, dnsB.tells, instanceB.tells)
	waitFor(t, 60*time.Second, "b's own address at its server", func() bool { return dnsB.has("me.b.example", b.IPv6) }, dnsB.tells, instanceB.tells)
	waitFor(t, 60*time.Second, "a's own address at its server", func() bool { return dnsA.has("me.a.example", a.IPv6) }, dnsA.tells, instanceA.tells)
	waitFor(t, 30*time.Second, "peer's addresses as the name of both, to b", func() bool {
		h := instanceB.hostname("ha.pair.example")
		return h.Updates > 0 && h.LastError == "" && len(h.Addresses) == 2
	}, dnsPair.tells, instanceB.tells)
	writes := len(dnsPair.changes())
	requests, _ := dnsPair.asked()
	together, togetherAsked := counted()

	// a sends what it sent alone: nothing it hears of b makes it probe, or ask.
	t.Logf("a sent in %s, alone: %v; with b: %v; b: %v", while, alone, together, sent.From(b.MAC))
	t.Logf("a solicited in %s, alone: %v; with b: %v; b: %v", while, aloneAsked, togetherAsked, sent.Solicited(b.MAC))
	for _, kind := range []string{"multicast ping", "ssdp", "wsd", "arp"} {
		if together[kind] > alone[kind]+1 {
			t.Errorf("a sent %d %s in %s with b, and %d alone", together[kind], kind, while, alone[kind])
		}
	}
	if alone["multicast ping"] < 3 {
		t.Errorf("a sent %d multicast pings in %s alone, with a round every 3s", alone["multicast ping"], while)
	}
	// Of what goes by the addresses it has, a few more, for those it has of b now: the three
	// pings to each before it would expire, and the solicitation that follows each answer.
	for kind, slack := range map[string]int{"solicitation": 12, "ping": 12, "mdns": 6} {
		if together[kind] > alone[kind]*3/2+slack {
			t.Errorf("a sent %d %s in %s with b, and %d alone", together[kind], kind, while, alone[kind])
		}
	}
	// And by the address asked for, which tells what the totals hide: a solicits b's machine once
	// for each answer to its own multicast ping, as when b's machine had no instance, and not once
	// more for each ping and solicitation of b's it hears; and b solicits a's once a round of its
	// own. The link-local addresses are asked for now and then, before they would expire.
	bSent, bAsked := sent.From(b.MAC), sent.Solicited(b.MAC)
	for address, slack := range map[netip.Addr]int{b.IPv6: 2, b.LinkLocal(): 4} {
		if togetherAsked[address] > aloneAsked[address]+slack {
			t.Errorf("a solicited %s, of b's machine, %d times in %s with b's instance there, and %d times without", address, togetherAsked[address], while, aloneAsked[address])
		}
	}
	if aloneAsked[b.IPv6] < 3 {
		t.Errorf("a solicited %s, of b's machine, %d times in %s alone, with a round every 3s", b.IPv6, aloneAsked[b.IPv6], while)
	}
	for address, slack := range map[netip.Addr]int{a.IPv6: 2, a.LinkLocal(): 4} {
		if bAsked[address] > bSent["multicast ping"]+slack {
			t.Errorf("b solicited %s, of a's machine, %d times in %s, in %d rounds of its own", address, bAsked[address], while, bSent["multicast ping"])
		}
	}
	if of := sent.From(b.MAC); of["multicast ping"] > together["multicast ping"]+1 || of["solicitation"] > together["solicitation"]*3/2+6 {
		t.Errorf("b, with a round every 4s, sent in %s %v, and a, with one every 3s, %v", while, of, together)
	}

	// The name of both has what both found, and is left alone: no request more, with nothing new
	// to say. An instance that starts makes the records what it has found so far, as it does
	// alone: b took off the stable address a had found, until it found it too, and no more.
	if !dnsPair.has("ha.pair.example", peer.IPv6, stable) {
		t.Errorf("the name of both hasn't the peer's addresses\n%s", dnsPair.tells())
	}
	if changes := dnsPair.changes(); len(changes) > 4 || len(changes) != writes {
		t.Errorf("the name of both, of two addresses, was written %d times, %d of them while nothing changed\n%s", len(changes), len(changes)-writes, dnsPair.tells())
	}
	if after, _ := dnsPair.asked(); after != requests {
		t.Errorf("the server of both was asked %d times while nothing changed\n%s", after-requests, dnsPair.tells())
	}
	for _, i := range []*instance{instanceA, instanceB} {
		if h := i.hostname("ha.pair.example"); h.LastError != "" || !slices.Equal(h.Addresses, []string{peer.IPv6.String(), stable.String()}) {
			t.Errorf("%s has the name of both as %+v", i.name, h)
		}
	}

	// What a alone asked for: found by a, and nothing of it to b; nothing of the MAC nobody
	// has, to either. It went out on the link all the while, to a group b's machine is of.
	if asked, byB := all.Solicited(a.MAC)[ghost], all.Solicited(b.MAC)[ghost]; asked == 0 || byB != 0 {
		t.Errorf("a solicited the address of the MAC nobody has %d times, and b %d times: a alone asks for it", asked, byB)
	}
	if !dnsA.has("ghost.a.example") || instanceA.hostname("ghost.a.example").Updates > 1 {
		t.Errorf("a has addresses of a MAC nobody has\n%s", dnsA.tells())
	}
	if !dnsB.has("ipv4.b.example", router.IPv4, b.IPv4) && !dnsB.has("ipv4.b.example", router.IPv4, a.IPv4, b.IPv4) {
		t.Errorf("b has IPv4 addresses it never came to know, of what a asked\n%s", dnsB.tells())
	}

	// Each has every machine at its own MAC, with addresses that are its own, and only its own
	// machine as such.
	for _, of := range []struct {
		i    *instance
		own  *livetest.Machine
		mate *livetest.Machine
	}{{instanceA, a, b}, {instanceB, b, a}} {
		for _, host := range of.i.status().Discovered {
			for _, address := range host.Addresses {
				if !slices.Contains(truth[host.MAC], netip.MustParseAddr(address.Address)) {
					t.Errorf("%s has %s at %s, which hasn't it", of.i.name, address.Address, host.MAC)
				}
				if address.Self != (host.MAC == of.own.MAC) {
					t.Errorf("%s has %s at %s as its own machine's: %v", of.i.name, address.Address, host.MAC, address.Self)
				}
			}
		}
		for _, m := range []*livetest.Machine{router, of.own, of.mate, peer} {
			if !of.i.knows(m.MAC, m.IPv6) {
				t.Errorf("%s hasn't %s at %s, of %s", of.i.name, m.IPv6, m.MAC, m.Name)
			}
		}
		if !of.i.knows(peer.MAC, stable) {
			t.Errorf("%s hasn't the peer's stable address, %s", of.i.name, stable)
		}
	}

	// Home Assistant finds the two devices, each at its machine's address, and connects to each
	// with its key.
	for _, of := range []struct {
		name, key string
		m         *livetest.Machine
	}{{"ipv6ddns-a", keyA, a}, {"ipv6ddns-b", keyB, b}} {
		found := ha.found(of.name, 30*time.Second, "at its machine's address", func(s haService) bool {
			return s.Port == 6053 && slices.Equal(s.Addresses, []string{of.m.IPv4.String()})
		})
		if device := ha.connected(found, of.key); device.Name != of.name || !slices.Contains(device.Entities, "pair_ha_addresses") {
			t.Errorf("the device %s is %+v", of.name, device)
		}
	}

	// The peer leaves: it goes from each after its own lifetime, and from the name of both when
	// the first of them lets it go, once.
	writes = len(dnsPair.changes())
	peer.Leave(t)
	left := time.Now()
	for _, of := range []struct {
		i                    *instance
		dns                  *provider
		name                 string
		lifetime, rediscover time.Duration
	}{{instanceA, dnsA, "peer.a.example", 9 * time.Second, 3 * time.Second}, {instanceB, dnsB, "peer.b.example", 12 * time.Second, 4 * time.Second}} {
		waitFor(t, 40*time.Second, "peer off the server of "+of.i.name, func() bool { return of.dns.has(of.name) }, of.dns.tells, of.i.tells)
		took := time.Since(left)
		t.Logf("off %s's server %s after the peer left, with a lifetime of %s", of.i.name, took.Round(100*time.Millisecond), of.lifetime)
		if took < of.lifetime-of.rediscover-time.Second || took > of.lifetime+6*time.Second {
			t.Errorf("the peer went from %s %s after it left, with a lifetime of %s", of.i.name, took.Round(100*time.Millisecond), of.lifetime)
		}
	}
	if !dnsPair.has("ha.pair.example") {
		t.Errorf("the peer left, and the name of both has addresses\n%s", dnsPair.tells())
	}
	time.Sleep(3 * time.Second)
	if changes := dnsPair.changes()[writes:]; len(changes) != 2 || changes[0].action != "delete" || changes[1].action != "delete" {
		t.Errorf("the peer left, and the name of both was written otherwise than its two addresses taken off once\n%s", dnsPair.tells())
	}
	if !dnsA.has("mate.a.example", b.IPv6) || !dnsB.has("mate.b.example", a.IPv6) || !dnsA.has("me.a.example", a.IPv6) || !dnsB.has("me.b.example", b.IPv6) {
		t.Errorf("the peer left, and other names changed\n%s\n%s", dnsA.tells(), dnsB.tells())
	}

	// It comes back: both find it again, and its stable address once they ask again, within a
	// minute; the name of both ends with what both have. This time they read the name at the same
	// moment, empty, and so add the same address: the server refuses the second, which logs it,
	// tries again after its retry, and finds the record there.
	writes = len(dnsPair.changes())
	dnsPair.meet("ha.pair.example", 2)
	peer.Return(t)
	waitFor(t, 100*time.Second, "peer's addresses back at a's server", func() bool { return dnsA.has("peer.a.example", peer.IPv6, stable) }, dnsA.tells, instanceA.tells)
	waitFor(t, 100*time.Second, "peer's addresses back at b's server", func() bool { return dnsB.has("peer.b.example", peer.IPv6, stable) }, dnsB.tells, instanceB.tells)
	waitFor(t, 30*time.Second, "peer's addresses back as the name of both", func() bool {
		return dnsPair.has("ha.pair.example", peer.IPv6, stable) &&
			len(instanceA.hostname("ha.pair.example").Addresses) == 2 && len(instanceB.hostname("ha.pair.example").Addresses) == 2
	}, dnsPair.tells)
	time.Sleep(5 * time.Second)
	if changes := dnsPair.changes()[writes:]; len(changes) > 6 || !dnsPair.has("ha.pair.example", peer.IPv6, stable) {
		t.Errorf("the peer came back, and the name of both was written %d times, for two addresses\n%s", len(changes), dnsPair.tells())
	}
	collided := dnsPair.collisions()
	if len(collided) == 0 {
		t.Errorf("both read the name of both at the same moment, and neither was refused the address the other added\n%s", dnsPair.tells())
	}
	for _, refusal := range collided {
		i := map[netip.Addr]*instance{a.IPv4: instanceA, b.IPv4: instanceB}[refusal.from]
		if i == nil || !slices.ContainsFunc(i.logged("error"), func(line string) bool {
			return strings.Contains(line, "endpoint pair error updating ha") && strings.Contains(line, refusal.address)
		}) {
			t.Errorf("refused at the server of both, and not logged by its instance: %s", refusal)
		}
	}
	for _, i := range []*instance{instanceA, instanceB} {
		if h := i.hostname("ha.pair.example"); h.LastError != "" || !slices.Equal(h.Addresses, []string{peer.IPv6.String(), stable.String()}) {
			t.Errorf("after both updated the name of both at once, %s has it as %+v", i.name, h)
		}
	}
	t.Logf("the name of both, all along:\n%s", dnsPair.tells())

	instanceA.terminate()
	instanceB.terminate()

	// All along, by what each logged: no address at a MAC that hasn't it, none of the MAC
	// nobody has, and no error.
	for _, i := range []*instance{instanceA, instanceB} {
		identified := 0
		for _, line := range strings.Split(i.output.String(), "\n") {
			var entry struct {
				Level, Msg, IP, MAC string
			}
			if json.Unmarshal([]byte(line), &entry) != nil {
				continue
			}
			if entry.Msg == "host identified" {
				identified++
				if ip, err := netip.ParseAddr(entry.IP); err != nil || !slices.Contains(truth[entry.MAC], ip.WithZone("")) {
					t.Errorf("%s identified %s at %s, which hasn't it", i.name, entry.IP, entry.MAC)
				}
			}
			if strings.Contains(line, ghost.String()) && entry.Msg == "host identified" || entry.MAC == ghostMAC {
				t.Errorf("%s has something of the MAC nobody has: %s", i.name, line)
			}
			// But what the server of both refused of two updates at once.
			if entry.Level == "error" && !(strings.Contains(entry.Msg, "endpoint pair") && (strings.Contains(entry.Msg, "already exists") || strings.Contains(entry.Msg, "no such record exists"))) {
				t.Errorf("%s logged the error: %s", i.name, line)
			}
		}
		if identified < 4 {
			t.Errorf("%s logged %d hosts identified: is that still what its log says?", i.name, identified)
		}
	}
	for _, w := range slices.Concat(dnsA.changes(), dnsB.changes()) {
		if w.from != map[bool]netip.Addr{true: a.IPv4, false: b.IPv4}[strings.HasSuffix(w.domain, ".a.example")] {
			t.Errorf("a write that isn't its instance's: %s", w)
		}
	}
}

// Two instances with -live on one machine, each at its own terminal: each shows its own state
// there, serves it at its port, and ends by its own key.
func TestLiveTwoInstancesLive(t *testing.T) {
	lan := livetest.NewLAN(t, 14)
	router := lan.Router
	machine := lan.Machine(t, "machine", 10)
	dnsOne := startProvider(t, router, 5381, "token-one", "one.example")
	dnsTwo := startProvider(t, router, 5382, "token-two", "two.example")
	config := func(webPort int, dns *provider) string {
		return fmt.Sprintf(`
webserver:
  listen:
    - %d
discovery:
  rediscover: 3s
tasks:
  machine:
    filter:
      - self: true
        ip:
          prefix: "%s"
    endpoints:
      dns:
        - machine
credentials:
%s`, webPort, lan.Prefix(), dns.credential("dns", "1s"))
	}
	one := configure(t, machine, router, "one", 8053, config(8053, dnsOne)).live().start().serving()
	two := configure(t, machine, router, "two", 8054, config(8054, dnsTwo)).live().start().serving()
	waitFor(t, 30*time.Second, "machine's address at the first's server", func() bool { return dnsOne.has("machine.one.example", machine.IPv6) }, dnsOne.tells, one.tells)
	waitFor(t, 30*time.Second, "machine's address at the second's server", func() bool { return dnsTwo.has("machine.two.example", machine.IPv6) }, dnsTwo.tells, two.tells)
	shows := func(i *instance, own, other string) {
		t.Helper()
		waitFor(t, 15*time.Second, own+" on the terminal of "+i.name, func() bool { return strings.Contains(i.output.String(), own) }, i.tells)
		if strings.Contains(i.output.String(), other) || !strings.Contains(i.page("/"), own) || strings.Contains(i.page("/"), other) {
			t.Errorf("%s shows %s, of the other, at its terminal or its port:\n%q", i.name, other, i.output.String())
		}
	}
	shows(one, "machine.one.example", "machine.two.example")
	shows(two, "machine.two.example", "machine.one.example")

	// q at the first's terminal ends the first, and the second goes on.
	quits := func(i *instance) {
		t.Helper()
		if _, err := i.keys.Write([]byte("q")); err != nil {
			t.Fatal(err)
		}
		select {
		case <-i.exited:
		case <-time.After(20 * time.Second):
			t.Fatalf("%s did not end at q:\n%q", i.name, i.output.String())
		}
		if i.err != nil {
			t.Errorf("%s ended at q with %v:\n%q", i.name, i.err, i.output.String())
		}
	}
	quits(one)
	shown := len(two.output.String())
	time.Sleep(3 * time.Second)
	two.serving()
	if len(two.output.String()) == shown && !strings.Contains(two.page("/"), "machine.two.example") {
		t.Errorf("the first ended, and the second shows nothing more")
	}
	if !refused(t, router, machine, 8053) {
		t.Error("the first ended, and its port still listens")
	}
	quits(two)
}

// sameMAC tells whether two MACs are one, however each is written.
func sameMAC(a, b string) bool {
	plain := func(mac string) string { return strings.ToLower(strings.ReplaceAll(mac, ":", "")) }
	return a != "" && plain(a) == plain(b)
}
