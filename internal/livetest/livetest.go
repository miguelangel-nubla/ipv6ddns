//go:build linux && integration

package livetest

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// IP runs ip, of iproute2.
func IP(t testing.TB, args ...string) {
	t.Helper()
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		t.Fatalf("ip %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// Python is the interpreter with aioesphomeapi, Home Assistant's library for ESPHome devices:
// $ESPHOME_PYTHON, or python3. A live test doesn't skip without it.
func Python(t testing.TB) string {
	t.Helper()
	p := os.Getenv("ESPHOME_PYTHON")
	if p == "" {
		p = "python3"
	}
	if out, err := exec.Command(p, "-c", "import aioesphomeapi").CombinedOutput(); err != nil {
		t.Fatalf("%s has no aioesphomeapi; ESPHOME_PYTHON names one that has: %v\n%s", p, err, out)
	}
	return p
}

// Link is a link to another machine, as far as the network tells: a veth pair from the network
// namespace the test runs in to one of its own, the peer's.
type Link struct {
	// Interface is this end's, with Address; PeerAddress is the other end's, in Namespace.
	Interface   string
	Address     string
	PeerAddress string
	Namespace   string

	peerInterface string
}

// NewLink makes a link, which the end of the test removes. Each package gives another number,
// since the packages' tests run at once: the names and the network come from it.
func NewLink(t testing.TB, number int) *Link {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("the live tests make network namespaces: they need root")
	}
	l := &Link{
		Interface:     fmt.Sprintf("ipv6ddns-lt%d", number),
		peerInterface: fmt.Sprintf("ipv6ddns-lp%d", number),
		Namespace:     fmt.Sprintf("ipv6ddns-live-%d", number),
		// Of the networks for benchmarks, RFC 2544: on no real link.
		Address:     fmt.Sprintf("198.18.%d.1", number),
		PeerAddress: fmt.Sprintf("198.18.%d.2", number),
	}
	remove := func() {
		exec.Command("ip", "link", "del", l.Interface).Run()
		exec.Command("ip", "netns", "del", l.Namespace).Run()
	}
	remove() // what a test that was killed left
	t.Cleanup(remove)
	IP(t, "netns", "add", l.Namespace)
	IP(t, "link", "add", l.Interface, "type", "veth", "peer", "name", l.peerInterface, "netns", l.Namespace)
	IP(t, "addr", "add", l.Address+"/30", "dev", l.Interface)
	IP(t, "-n", l.Namespace, "addr", "add", l.PeerAddress+"/30", "dev", l.peerInterface)
	IP(t, "link", "set", l.Interface, "up")
	IP(t, "-n", l.Namespace, "link", "set", "lo", "up")
	IP(t, "-n", l.Namespace, "link", "set", l.peerInterface, "up")
	return l
}

// Command is a command that runs at the other end of the link: in the peer's namespace.
func (l *Link) Command(name string, args ...string) *exec.Cmd {
	cmd := exec.Command("ip", append([]string{"netns", "exec", l.Namespace, name}, args...)...)
	cmd.Stderr = os.Stderr
	return cmd
}

// Vanish takes the peer off the link, as a machine that loses power: nothing of it arrives any
// more, not the end of its connections either.
func (l *Link) Vanish(t testing.TB) {
	t.Helper()
	IP(t, "-n", l.Namespace, "addr", "del", l.PeerAddress+"/30", "dev", l.peerInterface)
}

// FreePort is a port of this end's address nothing listens on.
func (l *Link) FreePort(t testing.TB) int {
	t.Helper()
	ln, err := net.Listen("tcp4", net.JoinHostPort(l.Address, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
