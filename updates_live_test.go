//go:build live

package ipv6ddns

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestLiveUpdatesACMEClients gets a certificate with each of certbot, lego and acme.sh, through
// the resolver's dynamic updates, of Pebble: each client sends its challenges, signed with a key
// of its own, to ipv6ddns, which writes them to BIND with the rfc2136 provider, where Pebble
// checks them. tools/live-providers.sh runs BIND and Pebble, in one network, which the clients
// join, and sets:
//
//	IPV6DDNS_LIVE_RFC2136        the rfc2136 provider's settings, of BIND's zone
//	IPV6DDNS_LIVE_RFC2136_DNS    BIND, as host:port, which the resolver asks, as the internet
//	IPV6DDNS_LIVE_PEBBLE_CA      the file of Pebble's certificate
//	IPV6DDNS_LIVE_ACME_NETWORK   the network of the clients, as docker run takes it
//	IPV6DDNS_LIVE_ACME_HOST      this machine's address, from that network
//	IPV6DDNS_LIVE_CERTBOT_IMAGE, IPV6DDNS_LIVE_LEGO_IMAGE, IPV6DDNS_LIVE_ACMESH_IMAGE
//
// Pebble is at 127.0.0.1:14000 of that network.
func TestLiveUpdatesACMEClients(t *testing.T) {
	settings, network, host := os.Getenv("IPV6DDNS_LIVE_RFC2136"), os.Getenv("IPV6DDNS_LIVE_ACME_NETWORK"), os.Getenv("IPV6DDNS_LIVE_ACME_HOST")
	if settings == "" || network == "" || host == "" {
		t.Skip("IPV6DDNS_LIVE_RFC2136, IPV6DDNS_LIVE_ACME_NETWORK and IPV6DDNS_LIVE_ACME_HOST not set: tools/live-providers.sh sets them")
	}
	var bind struct {
		Zone string `json:"zone"`
	}
	if err := json.Unmarshal([]byte(settings), &bind); err != nil {
		t.Fatal(err)
	}
	zone := bind.Zone
	bindDNS := os.Getenv("IPV6DDNS_LIVE_RFC2136_DNS")

	// A key of each client's: its secret, and the names of its certificate.
	secrets := map[string]string{}
	for _, k := range []string{"certbot", "lego", "acmesh"} {
		secrets[k] = randomSecret(t)
	}
	port := freeDNSPort(t)
	w := workerOf(t, fmt.Sprintf(`
credentials:
  public:
    provider: rfc2136
    settings: %s
resolvers:
  lan:
    listen: 0.0.0.0:%s
    allow:
      - 0.0.0.0/0
      - ::/0
    upstream: %s
    updates:
      keys:
        certbot:
          secret: %s
          permissions:
            - challenges:
                credential: public
                names:
                  - nas.lan
                  - apps
                  - "*.apps"
        lego:
          secret: %s
          permissions:
            - challenges:
                credential: public
                names:
                  - lego
        acmesh:
          secret: %s
          permissions:
            - challenges:
                credential: public
                names:
                  - acmesh
tasks:
  none:
    filter:
      - mac:
          address: "00:00:5e:00:53:ff"
    endpoints:
      public:
        - none
discovery:
  ipv6:
    enabled: false
`, settings, port, bindDNS, secrets["certbot"], secrets["lego"], secrets["acmesh"]))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	ca, err := os.ReadFile(os.Getenv("IPV6DDNS_LIVE_PEBBLE_CA"))
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("pebble-ca.pem", string(ca))
	write("certbot.ini", fmt.Sprintf("dns_rfc2136_server = %s\ndns_rfc2136_port = %s\ndns_rfc2136_name = certbot\ndns_rfc2136_secret = %s\ndns_rfc2136_algorithm = HMAC-SHA256\ndns_rfc2136_sign_query = true\n",
		host, port, secrets["certbot"]))
	write("acmesh.key", fmt.Sprintf("key \"acmesh\" {\n\talgorithm hmac-sha256;\n\tsecret \"%s\";\n};\n", secrets["acmesh"]))
	const pebble = "https://127.0.0.1:14000/dir"

	for _, c := range []struct {
		client string
		names  []string
		args   []string
	}{
		{"certbot", []string{"nas.lan." + zone, "apps." + zone, "*.apps." + zone}, []string{
			// Python 3.13 refuses Pebble's own certificate, which has no authority key identifier:
			// the connection to Pebble isn't what is tested, so it isn't checked, as acme.sh's.
			image(t, "CERTBOT"),
			"certonly", "-n", "--agree-tos", "--register-unsafely-without-email", "--server", pebble, "--no-verify-ssl",
			"--dns-rfc2136", "--dns-rfc2136-credentials", "/work/certbot.ini", "--dns-rfc2136-propagation-seconds", "1",
			"--config-dir", "/work/certbot/config", "--work-dir", "/work/certbot/work", "--logs-dir", "/work/certbot/logs",
			"-d", "nas.lan." + zone, "-d", "apps." + zone, "-d", "*.apps." + zone,
		}},
		{"lego", []string{"lego." + zone}, []string{
			"-e", "LEGO_CA_CERTIFICATES=/work/pebble-ca.pem",
			"-e", "DNSUPDATE_NAMESERVER=" + net.JoinHostPort(host, port), "-e", "DNSUPDATE_TSIG_KEY=lego",
			"-e", "DNSUPDATE_TSIG_SECRET=" + secrets["lego"], "-e", "DNSUPDATE_TSIG_ALGORITHM=hmac-sha256.",
			image(t, "LEGO"), "run", "--server", pebble, "--accept-tos", "--email", "live@" + zone,
			"--dns", "dnsupdate", "--dns.resolvers", "127.0.0.1:53", "--dns.propagation.wait", "1s",
			"--domains", "lego." + zone, "--path", "/work/lego",
		}},
		{"acme.sh", []string{"acmesh." + zone}, []string{
			"-e", "NSUPDATE_SERVER=" + host, "-e", "NSUPDATE_SERVER_PORT=" + port, "-e", "NSUPDATE_KEY=/work/acmesh.key",
			"--entrypoint", "sh", image(t, "ACMESH"), "-c",
			"acme.sh --home /work/acmesh/home --issue --dns dns_nsupdate --dnssleep 1 --insecure --server " + pebble + " --accountemail live@" + zone +
				" --cert-home /work/acmesh -d acmesh." + zone,
		}},
	} {
		t.Run(c.client, func(t *testing.T) {
			// As this user: on Linux, the files a container's root writes are root's, and the
			// certificates and keys of certbot and lego can't be read then.
			user := fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
			args := append([]string{"run", "--rm", "--network", network, "--user", user, "-v", dir + ":/work"}, c.args...)
			cmd := exec.Command("docker", args...)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s: %v\n%s", c.client, err, tail(string(out), 40))
			}
			// The certificate, of its names.
			if found, unread := certificateOf(t, dir, c.names); !found {
				t.Errorf("%s: no certificate of %v in its files, of which these can't be read: %v\n%s", c.client, c.names, unread, tail(string(out), 20))
			}
		})
	}

	// Each key's challenges, written and removed, and none left at BIND.
	keys := w.Status(true).Resolvers[0].Keys
	for _, k := range keys {
		if k.Updates["applied"] < 2 || k.Updates["failed"] != 0 {
			t.Errorf("key %s: %+v", k.Name, k)
		}
	}
	for _, name := range []string{"nas.lan", "apps", "lego", "acmesh"} {
		fqdn := "_acme-challenge." + name + "." + zone + "."
		m := new(dns.Msg)
		m.SetQuestion(fqdn, dns.TypeTXT)
		resp, _, err := (&dns.Client{Timeout: 3 * time.Second}).Exchange(m, bindDNS)
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Answer) != 0 {
			t.Errorf("%s left: %v", fqdn, resp.Answer)
		}
	}
}

// image is the client's image, of IPV6DDNS_LIVE_<client>_IMAGE.
func image(t *testing.T, client string) string {
	t.Helper()
	v := os.Getenv("IPV6DDNS_LIVE_" + client + "_IMAGE")
	if v == "" {
		t.Skipf("IPV6DDNS_LIVE_%s_IMAGE not set", client)
	}
	return v
}

// randomSecret is a key's secret, of 32 bytes, in base64.
func randomSecret(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("sh", "-c", "head -c 32 /dev/urandom | base64").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

// certificateOf tells whether a certificate of dir, of PEM, has every one of names; and the
// files it couldn't read.
func certificateOf(t *testing.T, dir string, names []string) (bool, []string) {
	t.Helper()
	found := false
	var unread []string
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			unread = append(unread, path)
			return nil
		}
		if d.IsDir() || found {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			unread = append(unread, path)
			return nil
		}
		if !strings.Contains(string(data), "BEGIN CERTIFICATE") {
			return nil
		}
		if certs := parseCertificates(data); len(certs) > 0 {
			ok := true
			for _, n := range names {
				ok = ok && slices.Contains(certs[0].DNSNames, n)
			}
			found = ok
		}
		return nil
	})
	return found, unread
}

// parseCertificates are the certificates of PEM data, in order.
func parseCertificates(data []byte) []*x509.Certificate {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return certs
		}
		if c, err := x509.ParseCertificate(block.Bytes); err == nil && block.Type == "CERTIFICATE" {
			certs = append(certs, c)
		}
	}
}

// tail is the last n lines of s.
func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// TestLiveUpdatesNsupdate sends a host's own addresses to ipv6ddns with nsupdate, signed with a
// key, as a VPS would: they go to a push source, whose task writes them to BIND with the rfc2136
// provider. nsupdate finds the zone itself, by the resolver, which asks BIND as the internet. It
// runs in BIND's container, of the clients' network.
func TestLiveUpdatesNsupdate(t *testing.T) {
	settings, network, host := os.Getenv("IPV6DDNS_LIVE_RFC2136"), os.Getenv("IPV6DDNS_LIVE_ACME_NETWORK"), os.Getenv("IPV6DDNS_LIVE_ACME_HOST")
	container, ok := strings.CutPrefix(network, "container:")
	if settings == "" || !ok || host == "" {
		t.Skip("IPV6DDNS_LIVE_RFC2136, IPV6DDNS_LIVE_ACME_NETWORK and IPV6DDNS_LIVE_ACME_HOST not set: tools/live-providers.sh sets them")
	}
	var bind struct {
		Zone string `json:"zone"`
	}
	if err := json.Unmarshal([]byte(settings), &bind); err != nil {
		t.Fatal(err)
	}
	zone, bindDNS := bind.Zone, os.Getenv("IPV6DDNS_LIVE_RFC2136_DNS")
	secret := randomSecret(t)
	port := freeDNSPort(t)
	w := workerOf(t, fmt.Sprintf(`
credentials:
  public:
    provider: rfc2136
    settings: %s
    debounce: 1ms
resolvers:
  lan:
    listen: 0.0.0.0:%s
    allow:
      - 0.0.0.0/0
      - ::/0
    upstream: %s
    updates:
      keys:
        vps:
          secret: %s
          permissions:
            - addresses:
                source: vps
                zone: %s
sources:
  vps:
    type: push
    state_file: %s
tasks:
  vps:
    sources:
      - vps
    endpoints:
      public:
        - vps
discovery:
  ipv6:
    enabled: false
`, settings, port, bindDNS, secret, zone, filepath.Join(t.TempDir(), "push-vps.json")))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}

	key := fmt.Sprintf("key \"vps\" {\n\talgorithm hmac-sha256;\n\tsecret \"%s\";\n};\n", secret)
	nsupdate := func(lines ...string) {
		t.Helper()
		script := fmt.Sprintf("server %s %s\n%s\nsend\n", host, port, strings.Join(lines, "\n"))
		cmd := exec.Command("docker", "exec", "-i", "-e", "KEY="+key, container, "sh", "-c",
			`printf '%s' "$KEY" > /tmp/vps.key && nsupdate -v -k /tmp/vps.key`)
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("nsupdate: %v\n%s", err, out)
		}
	}
	name := "vps." + zone + "."
	atBIND := func(want ...string) {
		t.Helper()
		var got []string
		for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(200 * time.Millisecond) {
			got = nil
			for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
				m := new(dns.Msg)
				m.SetQuestion(name, qtype)
				resp, _, err := (&dns.Client{Timeout: 3 * time.Second}).Exchange(m, bindDNS)
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
			slices.Sort(got)
			if slices.Equal(got, want) || time.Now().After(deadline) {
				break
			}
		}
		if !slices.Equal(got, want) {
			t.Errorf("BIND has %v of %s, want %v", got, name, want)
		}
	}

	nsupdate("update delete "+name+" A", "update add "+name+" 300 A 192.0.2.77", "update add "+name+" 300 AAAA 2001:db8::77")
	atBIND("192.0.2.77", "2001:db8::77")
	nsupdate("update delete " + name + " AAAA")
	atBIND("192.0.2.77")
	nsupdate("update delete " + name)
	atBIND()
	if k := w.Status(true).Resolvers[0].Keys[0]; k.Updates["applied"] != 3 || k.Updates["refused"] != 0 {
		t.Errorf("the key: %+v", k)
	}
}

// TestLiveUpdatesKea has Kea's DHCP-DDNS send a DHCP server's names to ipv6ddns: the requests
// kea-dhcp4 sends it after a lease are sent to it here, and it updates ipv6ddns, with its
// conflict resolution, RFC 4703's, signed with a key. A name goes to the host discovery has at
// its address, and the task writes it to BIND. It runs in BIND's network, of the clients, with
// IPV6DDNS_LIVE_KEA_IMAGE.
func TestLiveUpdatesKea(t *testing.T) {
	settings, network, host := os.Getenv("IPV6DDNS_LIVE_RFC2136"), os.Getenv("IPV6DDNS_LIVE_ACME_NETWORK"), os.Getenv("IPV6DDNS_LIVE_ACME_HOST")
	container, ok := strings.CutPrefix(network, "container:")
	if settings == "" || !ok || host == "" {
		t.Skip("IPV6DDNS_LIVE_RFC2136, IPV6DDNS_LIVE_ACME_NETWORK and IPV6DDNS_LIVE_ACME_HOST not set: tools/live-providers.sh sets them")
	}
	keaImage := image(t, "KEA")
	var bind struct {
		Zone string `json:"zone"`
	}
	if err := json.Unmarshal([]byte(settings), &bind); err != nil {
		t.Fatal(err)
	}
	zone, bindDNS := bind.Zone, os.Getenv("IPV6DDNS_LIVE_RFC2136_DNS")
	old := namesRefresh
	namesRefresh = 200 * time.Millisecond
	t.Cleanup(func() { namesRefresh = old })

	secret := randomSecret(t)
	port := freeDNSPort(t)
	dir := t.TempDir()
	w := workerOf(t, fmt.Sprintf(`
credentials:
  public:
    provider: rfc2136
    settings: %s
    debounce: 1ms
resolvers:
  lan:
    listen: 0.0.0.0:%s
    allow:
      - 0.0.0.0/0
      - ::/0
    upstream: %s
    updates:
      keys:
        kea:
          secret: %s
          permissions:
            - names:
                zone: lan.%s
tasks:
  lan:
    filter:
      - ip:
          family:
            - 4
    endpoints:
      public:
        - "{hostname}.lan"
discovery:
  ipv6:
    enabled: false
  ipv4:
    enabled: true
    listen: false
  hostnames:
    lifetime: 2s
`, settings, port, bindDNS, secret, zone))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	printer, _ := net.ParseMAC("00:00:5e:00:53:20")
	w.discWorker.State.Register(printer, netip.MustParseAddr("192.0.2.20"), "eth0", time.Hour, nil)

	// Kea's DHCP-DDNS, in BIND's network, taking the requests at 127.0.0.1:53001.
	d2 := fmt.Sprintf(`{"DhcpDdns": {
  "ip-address": "127.0.0.1", "port": 53001, "dns-server-timeout": 3000,
  "tsig-keys": [{"name": "kea", "algorithm": "HMAC-SHA256", "secret": "%s"}],
  "forward-ddns": {"ddns-domains": [{"name": "lan.%s.", "key-name": "kea",
    "dns-servers": [{"ip-address": "%s", "port": %s}]}]},
  "reverse-ddns": {"ddns-domains": []},
  "loggers": [{"name": "kea-dhcp-ddns", "output-options": [{"output": "stdout"}], "severity": "INFO"}]
}}`, secret, zone, host, port)
	if err := os.WriteFile(filepath.Join(dir, "d2.conf"), []byte(d2), 0o644); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("ipv6ddns-live-kea-%d", os.Getpid())
	if out, err := exec.Command("docker", "run", "-d", "--name", name, "--platform", "linux/amd64", "--network", network,
		"-v", dir+":/work:ro", keaImage, "/usr/sbin/kea-dhcp-ddns", "-c", "/work/d2.conf").CombinedOutput(); err != nil {
		t.Fatalf("Kea: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := exec.Command("docker", "logs", "--tail", "40", name).CombinedOutput()
			t.Logf("Kea's log:\n%s", out)
		}
		_ = exec.Command("docker", "rm", "-f", name).Run()
	})
	for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(time.Second) {
		out, _ := exec.Command("docker", "logs", name).CombinedOutput()
		if strings.Contains(string(out), "DHCP_DDNS_STARTED") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Kea didn't start:\n%s", tail(string(out), 20))
		}
	}

	// A name change request, as kea-dhcp4 sends it: its JSON, after its length.
	ncr := func(add bool, fqdn, ip, dhcid string) {
		t.Helper()
		change := 1
		if add {
			change = 0
		}
		body := fmt.Sprintf(`{"change-type":%d,"forward-change":true,"reverse-change":false,"fqdn":"%s","ip-address":"%s","dhcid":"%s","lease-expires-on":"%s","lease-length":3600,"conflict-resolution-mode":"check-with-dhcid"}`,
			change, fqdn, ip, dhcid, time.Now().Add(time.Hour).UTC().Format("20060102150405"))
		msg := append([]byte{byte(len(body) >> 8), byte(len(body))}, body...)
		// BIND's image is Alpine's: its nc sends the datagram.
		cmd := exec.Command("docker", "exec", "-e", "NCR="+base64.StdEncoding.EncodeToString(msg), container, "sh", "-c",
			`echo "$NCR" | base64 -d | nc -u -w 1 127.0.0.1 53001`)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("sending the request: %v\n%s", err, out)
		}
	}
	dhcid := func(client string) string {
		sum := sha256.Sum256([]byte(client))
		return "000201" + hex.EncodeToString(sum[:])
	}
	fqdn := "printer.lan." + zone + "."
	published := "printer.lan." + zone + "."
	atBIND := func(want ...string) {
		t.Helper()
		var got []string
		for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(200 * time.Millisecond) {
			got = nil
			m := new(dns.Msg)
			m.SetQuestion(published, dns.TypeA)
			resp, _, err := (&dns.Client{Timeout: 3 * time.Second}).Exchange(m, bindDNS)
			if err != nil {
				t.Fatal(err)
			}
			for _, rr := range resp.Answer {
				if a, ok := rr.(*dns.A); ok {
					got = append(got, a.A.String())
				}
			}
			if slices.Equal(got, want) || time.Now().After(deadline) {
				break
			}
		}
		if !slices.Equal(got, want) {
			t.Fatalf("BIND has %v of %s, want %v", got, published, want)
		}
	}
	key := func() map[string]uint64 { return w.Status(true).Resolvers[0].Keys[0].Updates }

	// The lease: the name goes to the printer, and the task writes it.
	ncr(true, fqdn, "192.0.2.20", dhcid("printer"))
	atBIND("192.0.2.20")

	// Another client asks for the name: Kea's conflict resolution keeps the printer's.
	before := key()["refused"]
	ncr(true, fqdn, "192.0.2.99", dhcid("another"))
	for deadline := time.Now().Add(20 * time.Second); key()["refused"] < before+2; time.Sleep(200 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("Kea's checks of the other client weren't refused: %v", key())
		}
	}
	atBIND("192.0.2.20")

	// The lease ends: the name goes, once discovery's names lifetime is over, and the task removes
	// it.
	ncr(false, fqdn, "192.0.2.20", dhcid("printer"))
	atBIND()
	if u := key(); u["applied"] < 2 || u["failed"] != 0 {
		t.Errorf("the key: %v", u)
	}
}
