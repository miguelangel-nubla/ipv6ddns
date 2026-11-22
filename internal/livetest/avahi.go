//go:build linux && integration

package livetest

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// output is what a process writes while the test reads it.
type output struct {
	mutex  sync.Mutex
	buffer bytes.Buffer
}

func (o *output) Write(p []byte) (int, error) {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	return o.buffer.Write(p)
}

func (o *output) String() string {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	return o.buffer.String()
}

// Avahi runs avahi-daemon on the machine, a real mDNS responder, which says the machine is
// hostName.local, and has a service, so that it answers the query for the services of the link:
// as ipv6disc's own live tests run it. It needs no D-Bus, but a directory for its PID file and
// one for its services, which each has in a mount namespace of its own. It returns once avahi
// has announced its name, and the end of the test stops it. Without avahi-daemon the test fails:
// tools/live-test.sh and CI install it.
func (m *Machine) Avahi(t testing.TB, hostName string) {
	t.Helper()
	if _, err := exec.LookPath("avahi-daemon"); err != nil {
		t.Fatalf("the test runs avahi-daemon, a real mDNS responder: install it, as tools/live-test.sh does: %v", err)
	}
	dir := t.TempDir()
	config := filepath.Join(dir, "avahi-daemon.conf")
	if err := os.WriteFile(config, fmt.Appendf(nil, "[server]\nhost-name=%s\nuse-ipv4=yes\nuse-ipv6=yes\nenable-dbus=no\nallow-interfaces=%s\n[publish]\npublish-workstation=no\n", hostName, m.Interface), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"/run/avahi-daemon", "/etc/avahi/services"} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Its PID file and its services are its own: every avahi of the system has them at the same
	// paths.
	script := "mount -t tmpfs tmpfs /run/avahi-daemon && chown avahi:avahi /run/avahi-daemon && mount -t tmpfs tmpfs /etc/avahi/services" +
		` && printf '<service-group><name>test</name><service><type>_ipv6ddns-test._tcp</type><port>9</port></service></service-group>' > /etc/avahi/services/test.service` +
		" && exec avahi-daemon -f " + config + " --debug"
	cmd := m.Command("unshare", "-m", "sh", "-c", script)
	log := &output{}
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// As a host that shuts down: it says goodbye.
		_ = cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		if t.Failed() {
			t.Logf("avahi-daemon on %s wrote:\n%s", m.Name, log.String())
		}
	})
	// Its records are its own once it probed for them, and announced them.
	for deadline := time.Now().Add(20 * time.Second); !strings.Contains(log.String(), "Server startup complete. Host name is "+hostName+".local"); time.Sleep(100 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("avahi-daemon on %s did not start:\n%s", m.Name, log.String())
		}
	}
}
