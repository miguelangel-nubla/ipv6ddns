//go:build !windows

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestMain runs the command itself, in place of the tests, for a test that starts it: the test
// binary is the command, with its arguments after IPV6DDNS_RUN_COMMAND.
func TestMain(m *testing.M) {
	if os.Getenv("IPV6DDNS_RUN_COMMAND") == "1" {
		os.Args = append([]string{"ipv6ddns"}, strings.Fields(os.Getenv("IPV6DDNS_COMMAND_ARGS"))...)
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// command is the command running, of a configuration: its output, its web server and its
// resolver.
type command struct {
	cmd      *exec.Cmd
	output   *syncBuffer
	web, dns string
}

type syncBuffer struct {
	mutex sync.Mutex
	b     bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.b.Write(p)
}

func (b *syncBuffer) String() string {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.b.String()
}

// startCommand starts the command with the configuration at path, and waits until it is healthy.
func startCommand(t *testing.T, path, web, dnsAddress string) *command {
	t.Helper()
	c := &command{output: &syncBuffer{}, web: web, dns: dnsAddress}
	c.cmd = exec.Command(os.Args[0], "-test.run=^$")
	c.cmd.Env = append(os.Environ(), "IPV6DDNS_RUN_COMMAND=1", "IPV6DDNS_COMMAND_ARGS=--config "+path)
	c.cmd.Stdout, c.cmd.Stderr = c.output, c.output
	if err := c.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if c.cmd.ProcessState == nil {
			_ = c.cmd.Process.Kill()
			_ = c.cmd.Wait()
		}
		if t.Failed() {
			t.Logf("the command wrote:\n%s", c.output.String())
		}
	})
	for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if resp, err := http.Get("http://" + web + "/healthz"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return c
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the command never became healthy:\n%s", c.output.String())
		}
	}
}

// stop stops the command as a service manager does, and waits for it.
func (c *command) stop(t *testing.T) {
	t.Helper()
	if err := c.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- c.cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the command ended with %v:\n%s", err, c.output.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("the command didn't stop:\n%s", c.output.String())
	}
}

func (c *command) get(t *testing.T, page string) (int, string) {
	t.Helper()
	resp, err := http.Get("http://" + c.web + page)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// freePort is a port of 127.0.0.1 that is free now, over UDP and TCP both.
func freePort(t *testing.T) string {
	t.Helper()
	for range 20 {
		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		_, port, _ := net.SplitHostPort(c.LocalAddr().String())
		l, err := net.Listen("tcp", "127.0.0.1:"+port)
		c.Close()
		if err == nil {
			l.Close()
			return port
		}
	}
	t.Fatal("no free port")
	return ""
}

const e2eSecret = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

// The command, of a configuration with dynamic updates: a VPS sends its own addresses, signed with
// its key, over UDP; the task publishes them in the resolver's zone, which any client asks; the
// log, the status and the metrics tell of it; the push source, of no password, refuses the web
// server's requests; a wrong key is refused; and after a stop and a start, the addresses are there.
func TestEndToEndUpdates(t *testing.T) {
	dir := t.TempDir()
	web := "127.0.0.1:" + freePort(t)
	dnsAddress := "127.0.0.1:" + freePort(t)
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf(`
webservers:
  main:
    listen:
      - %s
log_level: info
credentials:
  home:
    provider: resolver
    settings:
      zone: home.arpa
resolvers:
  lan:
    listen:
      - %s
    upstream:
      - 127.0.0.1:%s
    updates:
      keys:
        vps:
          secret: %s
          permissions:
            - addresses:
                source: vps
                zone: example.com
sources:
  vps:
    type: push
tasks:
  vps:
    sources:
      - vps
    endpoints:
      home:
        - vps
discovery:
  ipv6:
    enabled: false
`, web, dnsAddress, freePort(t), e2eSecret)), 0o600); err != nil {
		t.Fatal(err)
	}
	c := startCommand(t, path, web, dnsAddress)

	send := func(m *dns.Msg, key, secret string) *dns.Msg {
		t.Helper()
		m.SetTsig(key+".", dns.HmacSHA256, 300, time.Now().Unix())
		client := &dns.Client{Timeout: 3 * time.Second, TsigSecret: map[string]string{key + ".": secret}}
		resp, _, err := client.Exchange(m, dnsAddress)
		if resp == nil {
			t.Fatalf("no answer: %v", err)
		}
		return resp
	}
	update := new(dns.Msg)
	update.SetUpdate("example.com.")
	a, _ := dns.NewRR("vps.example.com. 300 IN A 192.0.2.7")
	aaaa, _ := dns.NewRR("vps.example.com. 300 IN AAAA 2001:db8::7")
	update.Insert([]dns.RR{a, aaaa})
	if resp := send(update, "vps", e2eSecret); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("the update: %s", dns.RcodeToString[resp.Rcode])
	}

	// Any client, unsigned, of the resolver's zone: the task published them.
	published := func(c *command) []string {
		t.Helper()
		var got []string
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(50 * time.Millisecond) {
			got = nil
			for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
				m := new(dns.Msg)
				m.SetQuestion("vps.home.arpa.", qtype)
				resp, _, err := (&dns.Client{Timeout: 3 * time.Second}).Exchange(m, c.dns)
				if err != nil {
					t.Fatal(err)
				}
				for _, rr := range resp.Answer {
					switch rr := rr.(type) {
					case *dns.A:
						got = append(got, rr.A.String())
					case *dns.AAAA:
						got = append(got, rr.AAAA.String())
					}
				}
			}
			if len(got) == 2 || time.Now().After(deadline) {
				return got
			}
		}
	}
	if got := published(c); !slices.Equal(got, []string{"192.0.2.7", "2001:db8::7"}) {
		t.Errorf("published: %v", got)
	}

	// A key it doesn't know, and the right key's name with a wrong secret: NOTAUTH, nothing changed.
	other := new(dns.Msg)
	other.SetUpdate("example.com.")
	other.Insert([]dns.RR{a})
	if resp := send(other, "intruder", e2eSecret); resp.Rcode != dns.RcodeNotAuth {
		t.Errorf("an unknown key: %s", dns.RcodeToString[resp.Rcode])
	}
	wrong := new(dns.Msg)
	wrong.SetUpdate("example.com.")
	wrong.RemoveName([]dns.RR{a})
	if resp := send(wrong, "vps", "d3Jvbmcgc2VjcmV0LCBvZiAzMiBieXRlcywgLi4uLi4uLi4="); resp.Rcode != dns.RcodeNotAuth {
		t.Errorf("a wrong secret: %s", dns.RcodeToString[resp.Rcode])
	}

	// The web server's updates, to a push source without a password: refused.
	if code, body := c.get(t, "/nic/update?hostname=vps&myip=198.51.100.1"); code != http.StatusUnauthorized || !strings.HasPrefix(body, "badauth") {
		t.Errorf("/nic/update: %d %q", code, body)
	}

	// The log, the status and the metrics.
	for deadline := time.Now().Add(3 * time.Second); !strings.Contains(c.output.String(), "key vps: updated addresses: vps.example.com"); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Errorf("the update isn't logged")
			break
		}
	}
	_, body := c.get(t, "/status.json")
	var status struct {
		Resolvers []struct {
			Keys []struct {
				Name    string            `json:"name"`
				Updates map[string]uint64 `json:"updates"`
			} `json:"keys"`
		} `json:"resolvers"`
	}
	if err := json.Unmarshal([]byte(body), &status); err != nil {
		t.Fatal(err)
	}
	if len(status.Resolvers) != 1 || len(status.Resolvers[0].Keys) != 1 || status.Resolvers[0].Keys[0].Updates["applied"] != 1 {
		t.Errorf("the status: %+v", status.Resolvers)
	}
	if strings.Contains(body, e2eSecret) {
		t.Error("the status has the key's secret")
	}
	if _, metrics := c.get(t, "/metrics"); !strings.Contains(metrics, `ipv6ddns_resolver_updates_total{resolver="lan",key="vps",result="applied"} 1`) {
		t.Errorf("the metrics have no update")
	}

	// Stopped, and started again: the source's file has the addresses.
	c.stop(t)
	if strings.Contains(c.output.String(), e2eSecret) {
		t.Error("the log has the key's secret")
	}
	again := startCommand(t, path, web, dnsAddress)
	if got := published(again); !slices.Equal(got, []string{"192.0.2.7", "2001:db8::7"}) {
		t.Errorf("after a restart: %v", got)
	}
	again.stop(t)
}
