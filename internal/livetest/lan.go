//go:build linux && integration

package livetest

import (
	"context"
	"encoding/binary"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Command is the ipv6ddns command, built: $IPV6DDNS_COMMAND. The live tests of several instances
// run it, as it is installed, and don't skip without it.
func Command(t testing.TB) string {
	t.Helper()
	command := os.Getenv("IPV6DDNS_COMMAND")
	if _, err := os.Stat(command); err != nil {
		t.Fatalf("IPV6DDNS_COMMAND names the command, built, as go build -o /tmp/ipv6ddns ./cmd/ipv6ddns: %q: %v", command, err)
	}
	return command
}

// LAN is a link of several machines: a bridge, in a network namespace of its own, the router's,
// and a namespace for each machine, with one interface, lan, on the bridge. The test's own
// namespace isn't on it: nothing of the system's network, nor of the other tests, is heard there.
type LAN struct {
	// Router is the machine the bridge is in, a host of the link as the others: its address is
	// the bridge's.
	Router *Machine

	number   int
	machines []*Machine
}

// Machine is a host of a LAN.
type Machine struct {
	Name      string
	Namespace string
	// Interface is its interface on the link, with MAC, IPv4 and IPv6: one address of each family
	// besides the link-local one.
	Interface string
	MAC       string
	IPv4      netip.Addr
	IPv6      netip.Addr

	// The bridge's port to it, in the router's namespace.
	port   string
	router *Machine
}

// NewLAN makes a link with its router, which the end of the test removes, with what still runs on
// its machines. Each test gives another number, as NewLink: the names and the networks come from
// it, 198.18.<number>.0/24 and fd00:c612:<number>::/64.
func NewLAN(t testing.TB, number int) *LAN {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("the live tests make network namespaces: they need root")
	}
	l := &LAN{number: number}
	remove := func() {
		prefix := fmt.Sprintf("ipv6ddns-lan%d-", number)
		list, _ := exec.Command("ip", "netns", "list").Output()
		for _, line := range strings.Split(string(list), "\n") {
			name, _, _ := strings.Cut(line, " ")
			if !strings.HasPrefix(name, prefix) {
				continue
			}
			pids, _ := exec.Command("ip", "netns", "pids", name).Output()
			for _, pid := range strings.Fields(string(pids)) {
				if pid != strconv.Itoa(os.Getpid()) {
					_ = exec.Command("kill", "-9", pid).Run()
				}
			}
			_ = exec.Command("ip", "netns", "del", name).Run()
		}
	}
	remove() // what a test that was killed left
	t.Cleanup(remove)

	l.Router = l.machine(t, "router", 1)
	l.Router.Interface = "br0"
	IP(t, "netns", "add", l.Router.Namespace)
	l.Router.IP(t, "link", "set", "lo", "up")
	// Every frame goes to every port a group's could be at: the most that machines hear of each
	// other. No wait before a port forwards.
	l.Router.IP(t, "link", "add", "br0", "address", l.Router.MAC, "type", "bridge", "mcast_snooping", "0", "stp_state", "0", "forward_delay", "0")
	l.Router.addresses(t)
	l.Router.IP(t, "link", "set", "br0", "up")
	return l
}

func (l *LAN) machine(t testing.TB, name string, host int) *Machine {
	t.Helper()
	if host < 1 || host > 99 {
		t.Fatalf("machine %s: host %d, not from 1 to 99", name, host)
	}
	m := &Machine{
		Name:      name,
		Namespace: fmt.Sprintf("ipv6ddns-lan%d-%s", l.number, name),
		Interface: "lan",
		MAC:       fmt.Sprintf("02:00:00:00:%02x:%02x", l.number, host),
		// Of the networks for benchmarks, RFC 2544, and a unique local one: on no real link.
		IPv4:   netip.MustParseAddr(fmt.Sprintf("198.18.%d.%d", l.number, host)),
		IPv6:   netip.MustParseAddr(fmt.Sprintf("fd00:c612:%d::%d", l.number, host)),
		port:   fmt.Sprintf("port%d", host),
		router: l.Router,
	}
	l.machines = append(l.machines, m)
	return m
}

// Machine adds a machine to the link, the host'th of its networks, from 2 to 99: the router is
// the first.
func (l *LAN) Machine(t testing.TB, name string, host int) *Machine {
	t.Helper()
	m := l.machine(t, name, host)
	IP(t, "netns", "add", m.Namespace)
	m.IP(t, "link", "set", "lo", "up")
	IP(t, "link", "add", m.Interface, "netns", m.Namespace, "address", m.MAC, "type", "veth", "peer", "name", m.port, "netns", l.Router.Namespace)
	m.addresses(t)
	m.IP(t, "link", "set", m.Interface, "up")
	// The port is no host: without an address of its own, it sends nothing of its own.
	l.Router.IP(t, "link", "set", m.port, "addrgenmode", "none")
	l.Router.IP(t, "link", "set", m.port, "master", "br0", "up")
	return m
}

// EUI64 is the address a MAC makes for itself on the link's IPv6 network, or with fe80:: the
// link-local one every interface has.
func EUI64(prefix netip.Prefix, mac string) netip.Addr {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		panic("not a MAC: " + mac)
	}
	a := prefix.Masked().Addr().As16()
	copy(a[8:], []byte{hw[0] ^ 2, hw[1], hw[2], 0xff, 0xfe, hw[3], hw[4], hw[5]})
	return netip.AddrFrom16(a)
}

// LinkLocal is the machine's link-local address.
func (m *Machine) LinkLocal() netip.Addr {
	return EUI64(netip.MustParsePrefix("fe80::/64"), m.MAC)
}

// Prefix is the link's IPv6 network.
func (l *LAN) Prefix() netip.Prefix {
	return netip.PrefixFrom(l.Router.IPv6, 64).Masked()
}

// addresses gives the interface its addresses. The IPv6 one at once, without the detection of
// duplicates: there are none.
func (m *Machine) addresses(t testing.TB) {
	t.Helper()
	m.IP(t, "addr", "add", m.IPv4.String()+"/24", "dev", m.Interface)
	m.IP(t, "addr", "add", m.IPv6.String()+"/64", "dev", m.Interface, "nodad")
}

// IP runs ip, of iproute2, in the machine.
func (m *Machine) IP(t testing.TB, args ...string) {
	t.Helper()
	IP(t, append([]string{"-n", m.Namespace}, args...)...)
}

// Command is a command that runs on the machine. A signal to it is to the command itself: ip
// becomes it.
func (m *Machine) Command(name string, args ...string) *exec.Cmd {
	cmd := exec.Command("ip", append([]string{"netns", "exec", m.Namespace, name}, args...)...)
	cmd.Stderr = os.Stderr
	return cmd
}

// Leave takes the machine off the link, as one that loses power: nothing of it arrives any more.
// Return puts it back, with the addresses it had.
func (m *Machine) Leave(t testing.TB) {
	t.Helper()
	m.router.IP(t, "link", "set", m.port, "down")
}

func (m *Machine) Return(t testing.TB) {
	t.Helper()
	m.router.IP(t, "link", "set", m.port, "up")
}

// Do runs f on the machine: on a thread of the test that is in its network namespace meanwhile,
// so the sockets f makes are the machine's, and stay so wherever they are used after.
func (m *Machine) Do(f func() error) error {
	done := make(chan error, 1)
	go func() {
		// Unlocked only once the thread is back in the test's namespace: Go ends, with its
		// goroutine, one that is left locked, so none of the test's is ever in another's.
		runtime.LockOSThread()
		number, ok := setns[runtime.GOARCH]
		if !ok {
			done <- fmt.Errorf("no setns known for %s", runtime.GOARCH)
			return
		}
		enter := func(path string) (int, error) {
			fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
			if err != nil {
				return -1, err
			}
			return fd, nil
		}
		back, err := enter(fmt.Sprintf("/proc/self/task/%d/ns/net", syscall.Gettid()))
		if err != nil {
			done <- err
			return
		}
		defer syscall.Close(back)
		fd, err := enter("/run/netns/" + m.Namespace)
		if err != nil {
			done <- fmt.Errorf("namespace %s: %w", m.Namespace, err)
			return
		}
		defer syscall.Close(fd)
		if _, _, errno := syscall.RawSyscall(number, uintptr(fd), syscall.CLONE_NEWNET, 0); errno != 0 {
			done <- fmt.Errorf("namespace %s: setns: %w", m.Namespace, errno)
			runtime.UnlockOSThread()
			return
		}
		err = f()
		if _, _, errno := syscall.RawSyscall(number, uintptr(back), syscall.CLONE_NEWNET, 0); errno == 0 {
			runtime.UnlockOSThread()
		}
		done <- err
	}()
	return <-done
}

// setns is the system call's number, which syscall has for some architectures only.
var setns = map[string]uintptr{"amd64": 308, "arm64": 268, "386": 346, "arm": 375}

// Listen listens on the machine, as net.Listen: a server of the test's, at an address of the link.
func (m *Machine) Listen(network, address string) (net.Listener, error) {
	var l net.Listener
	err := m.Do(func() (err error) {
		l, err = net.Listen(network, address)
		return err
	})
	return l, err
}

// Dial connects from the machine, as net.Dialer's DialContext, to an address given as an IP.
func (m *Machine) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	var c net.Conn
	err := m.Do(func() (err error) {
		c, err = (&net.Dialer{}).DialContext(ctx, network, address)
		return err
	})
	return c, err
}

// HTTPClient is a client whose requests leave from the machine, each on a connection of its own.
func (m *Machine) HTTPClient() *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: m.Dial, DisableKeepAlives: true}}
}

// Capture counts what each MAC sends on the link, of what discovery and mDNS send: the frames
// that come in to the bridge's ports, and those the router sends itself.
type Capture struct {
	mutex  sync.Mutex
	counts map[string]map[string]int
	// The solicitations of each MAC, by the address asked for.
	solicited map[string]map[netip.Addr]int
}

// Reset forgets the counts.
func (c *Capture) Reset() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.counts = make(map[string]map[string]int)
	c.solicited = make(map[string]map[netip.Addr]int)
}

// From returns how many frames of each kind the MAC sent since Reset: "arp", a broadcast ARP
// request; "multicast ping" and "ping", an ICMPv6 echo request to a group and to a host;
// "solicitation", a neighbor solicitation to a group, as discovery's are; "ssdp" and "wsd", their
// searches; "mdns", any mDNS message.
func (c *Capture) From(mac string) map[string]int {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	counts := maps.Clone(c.counts[mac])
	if counts == nil {
		counts = map[string]int{}
	}
	return counts
}

// Solicited returns how many of the solicitations the MAC sent since Reset were for each address.
func (c *Capture) Solicited(mac string) map[netip.Addr]int {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	solicited := maps.Clone(c.solicited[mac])
	if solicited == nil {
		solicited = map[netip.Addr]int{}
	}
	return solicited
}

// Capture starts counting, until the end of the test.
func (l *LAN) Capture(t testing.TB) *Capture {
	t.Helper()
	c := &Capture{counts: make(map[string]map[string]int), solicited: make(map[string]map[netip.Addr]int)}
	var fd int
	ports := make(map[int]bool)
	bridge := 0
	err := l.Router.Do(func() (err error) {
		for _, m := range l.machines {
			if m == l.Router {
				continue
			}
			iface, err := net.InterfaceByName(m.port)
			if err != nil {
				return err
			}
			ports[iface.Index] = true
		}
		iface, err := net.InterfaceByName("br0")
		if err != nil {
			return err
		}
		bridge = iface.Index
		var protocol [2]byte
		binary.BigEndian.PutUint16(protocol[:], syscall.ETH_P_ALL)
		fd, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, int(binary.NativeEndian.Uint16(protocol[:])))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	// A bigger buffer, so that a burst of frames isn't lost; the frames still come without it.
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, 8<<20); err != nil {
		t.Logf("the capture's buffer stays as it was: %v", err)
	}
	// Reads wake up to see whether to stop.
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Usec: 100_000}); err != nil {
		t.Fatal(err)
	}
	stop, done := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { close(stop); <-done; syscall.Close(fd) })
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			select {
			case <-stop:
				return
			default:
			}
			n, from, err := syscall.Recvfrom(fd, buf, 0)
			if err != nil {
				continue
			}
			// As a frame comes in to a port, not as the bridge sends it on to the others; and
			// as the router sends its own.
			ll, ok := from.(*syscall.SockaddrLinklayer)
			if !ok {
				continue
			}
			intoPort := ports[ll.Ifindex] && ll.Pkttype != syscall.PACKET_OUTGOING
			fromRouter := ll.Ifindex == bridge && ll.Pkttype == syscall.PACKET_OUTGOING
			if !intoPort && !fromRouter {
				continue
			}
			if mac, kind := frameKind(buf[:n]); kind != "" {
				c.mutex.Lock()
				if c.counts[mac] == nil {
					c.counts[mac] = make(map[string]int)
				}
				c.counts[mac][kind]++
				if kind == "solicitation" && n >= 78 {
					if c.solicited[mac] == nil {
						c.solicited[mac] = make(map[netip.Addr]int)
					}
					// The target follows the message's type, code, checksum and reserved word.
					c.solicited[mac][netip.AddrFrom16([16]byte(buf[62:78]))]++
				}
				c.mutex.Unlock()
			}
		}
	}()
	return c
}

// frameKind tells the MAC an Ethernet frame is from, and its kind, of Capture's, if any.
func frameKind(frame []byte) (mac, kind string) {
	if len(frame) < 14 {
		return "", ""
	}
	const mdnsPort = 5353
	mac = net.HardwareAddr(frame[6:12]).String()
	switch binary.BigEndian.Uint16(frame[12:14]) {
	case syscall.ETH_P_ARP:
		if len(frame) >= 22 && binary.BigEndian.Uint16(frame[20:22]) == 1 && frame[0]&1 == 1 {
			return mac, "arp"
		}
	case syscall.ETH_P_IP:
		if len(frame) < 34 || frame[23] != syscall.IPPROTO_UDP {
			return "", ""
		}
		udp := frame[14+int(frame[14]&0x0f)*4:]
		if len(udp) >= 4 && binary.BigEndian.Uint16(udp[2:4]) == mdnsPort {
			return mac, "mdns"
		}
	case syscall.ETH_P_IPV6:
		if len(frame) < 58 {
			return "", ""
		}
		multicast, payload := frame[38] == 0xff, frame[54:]
		switch frame[20] {
		case syscall.IPPROTO_ICMPV6:
			switch {
			case payload[0] == 128 && multicast:
				return mac, "multicast ping"
			case payload[0] == 128:
				return mac, "ping"
			case payload[0] == 135 && multicast:
				return mac, "solicitation"
			}
		case syscall.IPPROTO_UDP:
			switch binary.BigEndian.Uint16(payload[2:4]) {
			case 1900:
				return mac, "ssdp"
			case 3702:
				return mac, "wsd"
			case mdnsPort:
				return mac, "mdns"
			}
		}
	}
	return "", ""
}
