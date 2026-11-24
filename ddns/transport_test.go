package ddns

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/internal/sshtest"
	"golang.org/x/crypto/ssh"
)

// shortTimeouts makes the timeouts of the updates short, for the test.
func shortTimeouts(t *testing.T) {
	t.Helper()
	http, update, dial := httpTimeout, updateTimeout, sshDialTimeout
	httpTimeout, updateTimeout, sshDialTimeout = 300*time.Millisecond, 600*time.Millisecond, 300*time.Millisecond
	t.Cleanup(func() { httpTimeout, updateTimeout, sshDialTimeout = http, update, dial })
}

// silentListener accepts connections and never says anything on them.
func silentListener(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var conns []net.Conn
	var mutex sync.Mutex
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mutex.Lock()
			conns = append(conns, conn)
			mutex.Unlock()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		mutex.Lock()
		defer mutex.Unlock()
		for _, conn := range conns {
			conn.Close()
		}
	})
	return listener.Addr().String()
}

// An update returns, with an error, when the other end stops answering, wherever it does: one
// that didn't would keep its name from being updated again.
func TestUpdatesTimeOut(t *testing.T) {
	shortTimeouts(t)
	silent := silentListener(t)

	// Hosts that answer up to a point, and then hang until the test ends.
	hang := make(chan struct{})
	t.Cleanup(func() { close(hang) })
	sshServer := sshtest.Start(t, "root", "secret", func(string) ([]byte, error) {
		<-hang
		return nil, nil
	})
	router := newFakeRouterOS(t, nil, func(string, map[string]string, map[string]string) ([]map[string]string, error) {
		<-hang
		return nil, nil
	})

	mikrotik := func(address string) *Mikrotik {
		service := &Mikrotik{Address: address, Username: "admin", Zone: "lan"}
		service.TTL.Duration = 5 * time.Minute
		return service
	}
	for name, service := range map[string]Service{
		"openwrt, no SSH handshake":      &OpenWrt{Address: silent, Username: "root", Password: "secret", Zone: "lan"},
		"openwrt, a command that hangs":  &OpenWrt{Address: sshServer.Address, Username: "root", Password: "secret", Zone: "lan", HostKey: sshServer.HostKey},
		"windows, no SSH handshake":      &WindowsDNS{Address: silent, Username: "admin", Password: "secret", Zone: "example.com"},
		"windows, a command that hangs":  &WindowsDNS{Address: sshServer.Address, Username: "root", Password: "secret", Zone: "example.com", HostKey: sshServer.HostKey},
		"mikrotik, no answer to a login": mikrotik(silent),
		"mikrotik, a command that hangs": mikrotik(router.address()),
		"cloudflare":                     &Cloudflare{APIToken: "token", Zone: "example.com", apiBaseURL: "http://" + silent},
		"route53":                        &Route53{AccessKeyID: "a", SecretAccessKey: "s", Region: "us-east-1", HostedZoneID: "Z1", endpoint: "http://" + silent},
		"technitium":                     &Technitium{Address: "http://" + silent, Token: "t", Zone: "lan"},
		"opnsense":                       &OpnsenseUnbound{Address: "http://" + silent, Key: "k", Secret: "s", Zone: "lan"},
		"pfsense":                        &PfsenseRestapiUnbound{Address: "http://" + silent, Key: "k", Zone: "lan"},
		"adguardhome":                    &AdGuardHome{Address: "http://" + silent, Username: "u", Password: "p", Zone: "lan"},
		"pihole":                         &PiHole{Address: "http://" + silent, Password: "p", Zone: "lan"},
		"gravity":                        &Gravity{Server: "http://" + silent, APIKey: "k", Zone: "lan."},
		"duckdns":                        &DuckDNS{APIToken: duckToken, updateURL: "http://" + silent},
	} {
		t.Run(name, func(t *testing.T) {
			done := make(chan error, 1)
			go func() { done <- service.Update("nas", desired()) }()
			select {
			case err := <-done:
				if err == nil {
					t.Error("the update succeeded")
				}
				if strings.Contains(name, "a command that hangs") && !strings.Contains(name, "mikrotik") && !strings.Contains(err.Error(), "timed out") {
					t.Errorf("the error doesn't tell of the timeout: %v", err)
				}
			case <-time.After(20 * time.Second):
				t.Fatal("the update is still running")
			}
		})
	}
}

// A host with several keys shows one, of the kind the client prefers: host_key can be any of them.
func TestSSHHostKeyAnyOfTheHost(t *testing.T) {
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var signers []ssh.Signer
	for _, key := range []any{ed25519Key, ecdsaKey} {
		signer, err := ssh.NewSignerFromKey(key)
		if err != nil {
			t.Fatal(err)
		}
		signers = append(signers, signer)
	}
	server := sshtest.StartWithHostKeys(t, "root", "secret", func(string) ([]byte, error) { return nil, nil }, signers...)

	// How many connections each dial took.
	var connections []int
	for _, hostKey := range server.HostKeys {
		// Twice: the second time it asks for the key of that kind at once, in one connection.
		for range 2 {
			before := server.Connections()
			client, shown, err := dialSSH(sshTarget{Address: server.Address, Username: "root", Password: "secret", HostKey: hostKey})
			if err != nil {
				t.Fatalf("pinned to %s: %v", hostKey, err)
			}
			client.Close()
			if shown != hostKey {
				t.Errorf("pinned to %s: connected to a host showing %s", hostKey, shown)
			}
			connections = append(connections, server.Connections()-before)
		}
	}
	if got := server.Logins(); got != 4 {
		t.Errorf("got %d logins, want 4: the password is for the host with the key expected only", got)
	}
	// One of the keys is the one shown by default, found at once both times; the other takes a
	// second connection the first time, and one once the algorithms that show it are remembered.
	slices.Sort(connections)
	if !slices.Equal(connections, []int{1, 1, 1, 2}) {
		t.Errorf("the dials took %v connections, want one each but the first for the key not shown by default, two", connections)
	}

	// The key of no one: the error tells both keys, and the password was not sent.
	other := "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	_, _, err = dialSSH(sshTarget{Address: server.Address, Username: "root", Password: "secret", HostKey: other})
	if err == nil || !strings.Contains(err.Error(), "host key mismatch") {
		t.Fatalf("pinned to another key: got %v", err)
	}
	for _, hostKey := range server.HostKeys {
		if !strings.Contains(err.Error(), hostKey) {
			t.Errorf("the error doesn't tell the key %s: %v", hostKey, err)
		}
	}
	if got := server.Logins(); got != 4 {
		t.Errorf("the password was sent to a host with another key")
	}

	// A wrong password is not tried again with each kind of key.
	_, _, err = dialSSH(sshTarget{Address: server.Address, Username: "root", Password: "wrong", HostKey: server.HostKeys[0]})
	if err == nil {
		t.Fatal("a wrong password: want an error")
	}
	if got := server.Logins(); got != 5 {
		t.Errorf("a wrong password was given %d times, want once", got-4)
	}

	// Without a host key, the one it shows by default, to pin it with.
	client, shown, err := dialSSH(sshTarget{Address: server.Address, Username: "root", Password: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
	if shown != server.HostKeys[0] && shown != server.HostKeys[1] {
		t.Errorf("unpinned: shown %s, want one of %v", shown, server.HostKeys)
	}
}

// The updates leave no connection open: nothing would use it again.
func TestUpdatesLeaveNoConnections(t *testing.T) {
	var mutex sync.Mutex
	open, opened := 0, 0
	fake := &fakeDuckDNS{}
	server := httptest.NewUnstartedServer(fake)
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		mutex.Lock()
		defer mutex.Unlock()
		switch state {
		case http.StateNew:
			open++
			opened++
		case http.StateClosed, http.StateHijacked:
			open--
		}
	}
	server.Start()
	defer server.Close()

	service := &DuckDNS{APIToken: duckToken, updateURL: server.URL}
	for range 5 {
		if err := service.Update("nas", collectionWith("2001:db8::9")); err != nil {
			t.Fatal(err)
		}
	}
	// The server learns of a connection closed a moment after.
	deadline := time.Now().Add(5 * time.Second)
	for {
		mutex.Lock()
		left, total := open, opened
		mutex.Unlock()
		if left == 0 && total > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d connections are still open", left, total)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
