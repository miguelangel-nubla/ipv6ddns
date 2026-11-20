//go:build linux && integration

package listen

// Which family an entry listens on is the system's to say, and Linux is where it matters: there
// Go's 0.0.0.0 and [::] are both the two. This checks it at addresses of an interface, not of
// loopback's only, and doesn't skip without IPv6. It needs root and iproute2:
//
//	go test -tags integration -exec sudo -run '^TestLive' ./pkg/listen

import (
	"os/exec"
	"testing"

	"github.com/miguelangel-nubla/ipv6ddns/internal/livetest"
)

func TestLiveListenFamilies(t *testing.T) {
	t.Run("loopback", func(t *testing.T) { listenFamilies(t, "127.0.0.1", "::1") })
	t.Run("an interface", func(t *testing.T) {
		const iface = "ipv6ddns-ll0"
		remove := func() { exec.Command("ip", "link", "del", iface).Run() }
		remove()
		t.Cleanup(remove)
		livetest.IP(t, "link", "add", iface, "type", "dummy")
		// Of the networks for documentation: on no real link.
		livetest.IP(t, "addr", "add", "192.0.2.53/32", "dev", iface)
		livetest.IP(t, "addr", "add", "2001:db8:53::1/128", "dev", iface, "nodad")
		livetest.IP(t, "link", "set", iface, "up")
		listenFamilies(t, "192.0.2.53", "2001:db8:53::1")
	})
}
