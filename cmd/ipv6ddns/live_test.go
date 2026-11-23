//go:build linux && integration

package main

// What the live tests of several instances share: the command running on a machine of a link, a
// DNS server for it to update, and Home Assistant on another machine. They need root, iproute2, a
// Python with aioesphomeapi, and the command, built:
//
//	go build -o /tmp/ipv6ddns ./cmd/ipv6ddns
//	go test -tags integration -exec "sudo env ESPHOME_PYTHON=$(which python3) IPV6DDNS_COMMAND=/tmp/ipv6ddns" -run '^TestLive' ./cmd/ipv6ddns

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns"
	"github.com/miguelangel-nubla/ipv6ddns/internal/livetest"
)

// waitFor waits until the condition holds, and fails the test with what tells of it otherwise.
func waitFor(t *testing.T, timeout time.Duration, what string, condition func() bool, tells ...func() string) {
	t.Helper()
	for deadline := time.Now().Add(timeout); !condition(); time.Sleep(100 * time.Millisecond) {
		if time.Now().After(deadline) {
			var told []string
			for _, tell := range tells {
				told = append(told, tell())
			}
			t.Fatalf("no %s in %s\n%s", what, timeout, strings.Join(told, "\n"))
		}
	}
}

// provider is a DNS server with the API of Technitium's, of one zone, for one token, on a machine
// of the link: it keeps the records, and every change of them with who made it. It refuses what
// the server refuses, seen of the 15.6.2 that tools/live-providers.sh runs: a record added that is
// there, and one deleted that isn't.
type provider struct {
	// The address for a credential's settings, with the token and the zone.
	address, token, zone string

	mutex   sync.Mutex
	records map[string]map[string]string // the type of each address, by name
	writes  []write
	// The changes it refused: a record added that was there, one deleted that wasn't.
	refusals []write
	// The requests in all, and those with another token or zone.
	requests, refused int
	// The readers of a name's records that wait for each other, if any: see meet.
	meeting *meeting
	// A name whose writes are held, if any, until released: see stall. Held, a write is then
	// dropped, as one whose client is gone.
	stalled     string
	stalledSeen chan struct{}
	release     chan struct{}
}

// stall holds the writes of a name from now on, and returns a channel closed when the first
// comes, and a function that lets them go, unapplied.
func (p *provider) stall(domain string) (seen <-chan struct{}, release func()) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.stalled, p.stalledSeen, p.release = domain, make(chan struct{}), make(chan struct{})
	r := p.release
	return p.stalledSeen, func() {
		p.mutex.Lock()
		p.stalled = ""
		p.mutex.Unlock()
		close(r)
	}
}

// meeting is of the machines that read a name's records, until there are as many as it takes:
// each is then answered with the records as they were at that moment.
type meeting struct {
	domain  string
	readers int
	waiting map[netip.Addr]bool
	met     chan struct{}
	records map[string]string
}

// meet makes the next reads of the name's records wait for each other, once: when as many
// machines as readers have asked, each is told the same records, those of that moment, as two
// instances that update a name at the same time are. One that waited 20 seconds alone is answered
// alone.
func (p *provider) meet(domain string, readers int) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.meeting = &meeting{domain: domain, readers: readers, waiting: make(map[netip.Addr]bool), met: make(chan struct{})}
}

// write is a change of the records: add or delete, of an address of a name, and the machine that
// asked.
type write struct {
	at             time.Time
	from           netip.Addr
	action, domain string
	address        string
}

func (w write) String() string {
	return fmt.Sprintf("%s %s %s %s by %s", w.at.Format("15:04:05.000"), w.action, w.domain, w.address, w.from)
}

func startProvider(t *testing.T, m *livetest.Machine, port int, token, zone string) *provider {
	t.Helper()
	p := &provider{
		address: "http://" + net.JoinHostPort(m.IPv4.String(), strconv.Itoa(port)), token: token, zone: zone,
		records: make(map[string]map[string]string),
	}
	listener, err := m.Listen("tcp4", net.JoinHostPort(m.IPv4.String(), strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: p}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	return p
}

func (p *provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	answer := func(v map[string]any) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(v)
	}
	failed := func(message string) { answer(map[string]any{"status": "error", "errorMessage": message}) }
	q := r.URL.Query()
	p.requests++
	if q.Get("token") != p.token || q.Get("zone") != p.zone {
		p.refused++
		failed("Invalid token or session expired.")
		return
	}
	domain, ip := q.Get("domain"), q.Get("ipAddress")
	action := strings.TrimPrefix(r.URL.Path, "/api/zones/records/")
	from := netip.MustParseAddrPort(r.RemoteAddr).Addr()
	if action != "get" && p.stalled != "" && domain == p.stalled {
		select {
		case <-p.stalledSeen:
		default:
			close(p.stalledSeen)
		}
		release := p.release
		p.mutex.Unlock()
		<-release
		p.mutex.Lock()
		return
	}
	switch action {
	case "get":
		current := p.records[domain]
		if m := p.meeting; m != nil && m.domain == domain {
			if m.waiting[from] = true; len(m.waiting) == m.readers {
				m.records, p.meeting = maps.Clone(current), nil
				close(m.met)
			}
			p.mutex.Unlock()
			select {
			case <-m.met:
				current = m.records
			case <-time.After(20 * time.Second):
			}
			p.mutex.Lock()
		}
		records := []map[string]any{}
		for ip, rrType := range current {
			records = append(records, map[string]any{"type": rrType, "ttl": 300, "rData": map[string]string{"ipAddress": ip}})
		}
		answer(map[string]any{"status": "ok", "response": map[string]any{"records": records}})
		return
	case "add":
		// As the server: a record that is there isn't added again.
		if _, ok := p.records[domain][ip]; ok {
			p.refusals = append(p.refusals, write{time.Now(), from, action, domain, ip})
			failed("Cannot add record: record already exists.")
			return
		}
		if p.records[domain] == nil {
			p.records[domain] = make(map[string]string)
		}
		p.records[domain][ip] = q.Get("type")
	case "delete":
		// Nor is one that isn't there deleted.
		if _, ok := p.records[domain][ip]; !ok {
			p.refusals = append(p.refusals, write{time.Now(), from, action, domain, ip})
			failed("Cannot delete record: no such record exists.")
			return
		}
		delete(p.records[domain], ip)
	case "update":
	default:
		http.NotFound(w, r)
		return
	}
	p.writes = append(p.writes, write{time.Now(), from, action, domain, ip})
	answer(map[string]any{"status": "ok"})
}

// addresses are those of a name's records, sorted.
func (p *provider) addresses(domain string) []string {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	addresses := []string{}
	for ip := range p.records[domain] {
		addresses = append(addresses, ip)
	}
	slices.Sort(addresses)
	return addresses
}

// has tells whether the records of a name are these addresses, and no other.
func (p *provider) has(domain string, addresses ...netip.Addr) bool {
	want := []string{}
	for _, a := range addresses {
		want = append(want, a.String())
	}
	slices.Sort(want)
	return slices.Equal(p.addresses(domain), want)
}

// changes are the writes so far.
func (p *provider) changes() []write {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return slices.Clone(p.writes)
}

// collisions are the changes it refused so far.
func (p *provider) collisions() []write {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return slices.Clone(p.refusals)
}

// asked is how many requests came, and how many of them were refused.
func (p *provider) asked() (requests, refused int) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.requests, p.refused
}

// tells is what the provider has, for a test that fails.
func (p *provider) tells() string {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	var b strings.Builder
	fmt.Fprintf(&b, "the zone %s has %v, after:\n", p.zone, p.records)
	for _, w := range p.writes {
		fmt.Fprintln(&b, "\t", w)
	}
	for _, w := range p.refusals {
		fmt.Fprintln(&b, "\trefused:", w)
	}
	return b.String()
}

// credential is the provider as a credential of a configuration, indented under credentials.
func (p *provider) credential(name, debounce string) string {
	return fmt.Sprintf(`  %s:
    provider: technitium
    debounce: %s
    retry: 2s
    settings:
      address: %s
      token: %s
      zone: %s
      ttl: 5m
`, name, debounce, p.address, p.token, p.zone)
}

// instance is the ipv6ddns command running on a machine, with the configuration in its folder.
type instance struct {
	t       *testing.T
	name    string
	machine *livetest.Machine
	folder  string
	// Where its web server is asked: an address of the machine's, and its port.
	web string
	// Who asks it: another machine of the link.
	client *http.Client

	cmd    *exec.Cmd
	exited chan struct{}
	err    error
	output lockedBuffer
	// With --live: what is typed at its terminal.
	keys io.Writer
	// More of the command's environment, as NAME=value.
	env []string
}

// lockedBuffer is what the command wrote, read while it runs.
type lockedBuffer struct {
	mutex  sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.buffer.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.buffer.String()
}

// configure writes the configuration of an instance in a folder of its own, and returns it, to
// start: the web server at the port, and the rest as given.
func configure(t *testing.T, m *livetest.Machine, asks *livetest.Machine, name string, webPort int, config string) *instance {
	t.Helper()
	folder := filepath.Join(t.TempDir(), name)
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	return configureIn(t, m, asks, name, folder, "config.yaml", webPort, config)
}

// configureIn is configure in a folder that is there, which instances can share.
func configureIn(t *testing.T, m *livetest.Machine, asks *livetest.Machine, name, folder, file string, webPort int, config string) *instance {
	t.Helper()
	if err := os.WriteFile(filepath.Join(folder, file), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	i := &instance{t: t, name: name, machine: m, folder: folder, web: net.JoinHostPort(m.IPv4.String(), strconv.Itoa(webPort)), client: asks.HTTPClient()}
	i.cmd = m.Command(livetest.Command(t), "--config="+filepath.Join(folder, file))
	return i
}

// live makes the instance one with --live, at a terminal of its own, testdata/terminal.py: its
// screen is the instance's output, and it ends as its command does.
func (i *instance) live() *instance {
	i.t.Helper()
	command := i.cmd.Args[slices.Index(i.cmd.Args, livetest.Command(i.t)):]
	i.cmd = i.machine.Command(livetest.Python(i.t), append([]string{"testdata/terminal.py"}, append(command, "--live")...)...)
	return i
}

// start runs the command. It returns at once: serving tells that it started.
func (i *instance) start() *instance {
	i.t.Helper()
	// Again, for one that ran and ended.
	i.cmd = exec.Command(i.cmd.Args[0], i.cmd.Args[1:]...)
	i.cmd.Stdout, i.cmd.Stderr = &i.output, &i.output
	i.cmd.Env = append(append(os.Environ(), "TERM=xterm"), i.env...)
	keys, err := i.cmd.StdinPipe()
	if err != nil {
		i.t.Fatal(err)
	}
	i.keys = keys
	i.exited, i.err = make(chan struct{}), nil
	if err := i.cmd.Start(); err != nil {
		i.t.Fatal(err)
	}
	exited, cmd := i.exited, i.cmd
	go func() {
		i.err = cmd.Wait()
		close(exited)
	}()
	i.t.Cleanup(func() {
		cmd.Process.Kill()
		<-exited
		if i.t.Failed() {
			i.t.Logf("%s wrote:\n%s", i.name, i.output.String())
		}
	})
	return i
}

// tells is what the command wrote, for a test that fails.
func (i *instance) tells() string { return i.name + " wrote:\n" + i.output.String() }

// get asks the instance's web server for a page.
func (i *instance) get(page string) (string, error) {
	resp, err := i.client.Get("http://" + i.web + page)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err == nil && resp.StatusCode != http.StatusOK {
		err = errors.New(resp.Status)
	}
	return string(body), err
}

// page is get, of an instance that serves.
func (i *instance) page(page string) string {
	i.t.Helper()
	body, err := i.get(page)
	if err != nil {
		i.t.Fatalf("%s: %s: %v", i.name, page, err)
	}
	return body
}

// serving waits for the web server to answer: the instance started.
func (i *instance) serving() *instance {
	i.t.Helper()
	waitFor(i.t, 20*time.Second, i.name+" serving", func() bool {
		select {
		case <-i.exited:
			i.t.Fatalf("%s ended: %v\n%s", i.name, i.err, i.output.String())
		default:
		}
		body, err := i.get("/healthz")
		return err == nil && body == "ok\n"
	}, i.tells)
	return i
}

// status is the instance's state, as /status.json has it.
func (i *instance) status() ipv6ddns.Status {
	i.t.Helper()
	var status ipv6ddns.Status
	if err := json.Unmarshal([]byte(i.page("/status.json")), &status); err != nil {
		i.t.Fatalf("%s: /status.json: %v", i.name, err)
	}
	return status
}

// discovered are the addresses the instance has at a MAC, and whether as its own machine's.
func (i *instance) discovered(mac string) (addresses []netip.Addr, self bool) {
	i.t.Helper()
	for _, host := range i.status().Discovered {
		if host.MAC != mac {
			continue
		}
		for _, a := range host.Addresses {
			addresses = append(addresses, netip.MustParseAddr(a.Address))
			self = self || a.Self
		}
	}
	return addresses, self
}

// knows tells whether the instance has the address at the MAC.
func (i *instance) knows(mac string, address netip.Addr) bool {
	i.t.Helper()
	addresses, _ := i.discovered(mac)
	return slices.Contains(addresses, address)
}

// name is a name's state, by its domain.
func (i *instance) hostname(domain string) ipv6ddns.HostnameStatus {
	i.t.Helper()
	status := i.status()
	for _, h := range status.Hostnames {
		if h.Domain == domain {
			return h
		}
	}
	i.t.Fatalf("%s has no name %s: %+v", i.name, domain, status.Hostnames)
	return ipv6ddns.HostnameStatus{}
}

// logged are the entries of the instance's log at a level, as "error".
func (i *instance) logged(level string) []string {
	var lines []string
	for _, line := range strings.Split(i.output.String(), "\n") {
		var entry struct{ Level string }
		if json.Unmarshal([]byte(line), &entry) == nil && entry.Level == level {
			lines = append(lines, line)
		}
	}
	return lines
}

// terminate ends the command as a signal does, as docker stop and systemd: it stops by itself,
// with no error.
func (i *instance) terminate() {
	i.t.Helper()
	i.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-i.exited:
	case <-time.After(20 * time.Second):
		i.t.Fatalf("%s did not stop:\n%s", i.name, i.output.String())
	}
	if i.err != nil {
		i.t.Errorf("%s ended with %v:\n%s", i.name, i.err, i.output.String())
	}
}

// fails waits for a command that must not start to end, with an error: it returns what it wrote.
func (i *instance) fails() string {
	i.t.Helper()
	select {
	case <-i.exited:
	case <-time.After(20 * time.Second):
		i.t.Fatalf("%s runs, and should not have started:\n%s", i.name, i.output.String())
	}
	if i.err == nil {
		i.t.Errorf("%s ended with no error:\n%s", i.name, i.output.String())
	}
	return i.output.String()
}

// refused tells whether nothing listens at a port of the machine, asked from another.
func refused(t *testing.T, from, m *livetest.Machine, port int) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := from.Dial(ctx, "tcp4", net.JoinHostPort(m.IPv4.String(), strconv.Itoa(port)))
	if err == nil {
		conn.Close()
		return false
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("port %d of %s: %v", port, m.Name, err)
	}
	return true
}

// homeAssistant is Home Assistant's side, testdata/home_assistant.py, on a machine of the link:
// it browses for the devices all along, and connects to those it is told.
type homeAssistant struct {
	t     *testing.T
	input io.Writer

	mutex  sync.Mutex
	events []haEvent
	ended  bool
}

// haEvent is a line of the script's: one of these.
type haEvent struct {
	Ready     bool
	Service   *haService
	Removed   string
	Connected *haDevice
	Failed    *haFailure
	Given     *struct {
		Port  int
		OK    bool `json:"ok"`
		Error string
	}
	Queried *struct {
		Name    string
		Service *haService
	}
}

// haService is a device as its announcement tells it.
type haService struct {
	Name, Host   string
	Port         int
	Addresses    []string
	MAC          string `json:"mac"`
	FriendlyName string `json:"friendly_name"`
	Encryption   bool
}

// haDevice is a device as it tells of itself to who connects, with its entities and their states.
type haDevice struct {
	Address      string
	Port         int
	Name         string
	FriendlyName string `json:"friendly_name"`
	MAC          string `json:"mac"`
	Entities     []string
	States       map[string]any
}

type haFailure struct {
	Address string
	Port    int
	Error   string
}

func startHomeAssistant(t *testing.T, m *livetest.Machine) *homeAssistant {
	t.Helper()
	cmd := m.Command(livetest.Python(t), "testdata/home_assistant.py", m.IPv4.String())
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	h := &homeAssistant{t: t, input: input}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for lines := bufio.NewScanner(output); lines.Scan(); {
			var event haEvent
			err := json.Unmarshal(lines.Bytes(), &event)
			h.mutex.Lock()
			if err != nil {
				t.Errorf("Home Assistant: %s: %v", lines.Text(), err)
			}
			h.events = append(h.events, event)
			h.mutex.Unlock()
		}
		h.mutex.Lock()
		h.ended = true
		h.mutex.Unlock()
	}()
	t.Cleanup(func() {
		cmd.Process.Kill()
		<-done
		cmd.Wait()
	})
	h.await(0, 30*time.Second, "Home Assistant browsing", func(e haEvent) bool { return e.Ready })
	return h
}

// now is where the events are at: await and since take it, for those after.
func (h *homeAssistant) now() int {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	return len(h.events)
}

// since are the events after a point.
func (h *homeAssistant) since(from int) []haEvent {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	return slices.Clone(h.events[from:])
}

// tells is every event so far, for a test that fails.
func (h *homeAssistant) tells() string {
	var b strings.Builder
	fmt.Fprintln(&b, "Home Assistant saw:")
	for _, e := range h.since(0) {
		line, _ := json.Marshal(e)
		fmt.Fprintln(&b, "\t", string(line))
	}
	return b.String()
}

// await is the first event after a point that matches.
func (h *homeAssistant) await(from int, timeout time.Duration, what string, matches func(haEvent) bool) haEvent {
	h.t.Helper()
	var found haEvent
	waitFor(h.t, timeout, what, func() bool {
		h.mutex.Lock()
		ended := h.ended
		h.mutex.Unlock()
		for _, e := range h.since(from) {
			if matches(e) {
				found = e
				return true
			}
		}
		if ended {
			h.t.Fatalf("waiting for %s: Home Assistant ended\n%s", what, h.tells())
		}
		return false
	}, h.tells)
	return found
}

func (h *homeAssistant) tell(command map[string]any) {
	h.t.Helper()
	line, err := json.Marshal(command)
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err := h.input.Write(append(line, '\n')); err != nil {
		h.t.Fatal(err)
	}
}

// service is the device as last announced, or nil: never, or its announcement taken back since.
func (h *homeAssistant) service(name string) *haService {
	var service *haService
	for _, e := range h.since(0) {
		switch {
		case e.Service != nil && e.Service.Name == name:
			service = e.Service
		case e.Removed == name:
			service = nil
		}
	}
	return service
}

// found waits for the device to be announced so that matches holds, and returns it.
func (h *homeAssistant) found(name string, timeout time.Duration, what string, matches func(haService) bool) haService {
	h.t.Helper()
	waitFor(h.t, timeout, "announcement of "+name+" "+what, func() bool {
		s := h.service(name)
		return s != nil && matches(*s)
	}, h.tells)
	return *h.service(name)
}

// removed tells whether the device took its announcement back after a point.
func (h *homeAssistant) removed(from int, name string) bool {
	return slices.ContainsFunc(h.since(from), func(e haEvent) bool { return e.Removed == name })
}

// connect connects to where a device was announced, with a key or none: the device, or the error.
func (h *homeAssistant) connect(s haService, key string) (*haDevice, *haFailure) {
	h.t.Helper()
	from := h.now()
	target := map[string]any{"address": s.Addresses[0], "port": s.Port, "key": nil}
	if key != "" {
		target["key"] = key
	}
	h.tell(map[string]any{"connect": target})
	e := h.await(from, 30*time.Second, "connection to "+s.Name, func(e haEvent) bool {
		return e.Connected != nil && e.Connected.Port == s.Port || e.Failed != nil && e.Failed.Port == s.Port
	})
	return e.Connected, e.Failed
}

// connected is connect, to a device that takes the key.
func (h *homeAssistant) connected(s haService, key string) haDevice {
	h.t.Helper()
	device, failure := h.connect(s, key)
	if device == nil {
		h.t.Fatalf("Home Assistant didn't connect to %s at %s:%d: %s", s.Name, s.Addresses[0], s.Port, failure.Error)
	}
	return *device
}

// giveKey gives the device a key, as Home Assistant does when it adds one that has none.
func (h *homeAssistant) giveKey(s haService, key string) {
	h.t.Helper()
	from := h.now()
	h.tell(map[string]any{"give_key": map[string]any{"address": s.Addresses[0], "port": s.Port, "key": key}})
	e := h.await(from, 30*time.Second, "a key given to "+s.Name, func(e haEvent) bool { return e.Given != nil && e.Given.Port == s.Port })
	if !e.Given.OK {
		h.t.Fatalf("%s didn't take the key Home Assistant gave: %s", s.Name, e.Given.Error)
	}
}

// query asks for a device as a Home Assistant that just started: what answers now, or nil.
func (h *homeAssistant) query(name string) *haService {
	h.t.Helper()
	from := h.now()
	h.tell(map[string]any{"query": name})
	return h.await(from, 30*time.Second, "answer to a query for "+name, func(e haEvent) bool {
		return e.Queried != nil && e.Queried.Name == name
	}).Queried.Service
}
