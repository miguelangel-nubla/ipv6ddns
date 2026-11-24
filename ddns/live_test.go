//go:build live

// The live tests: the providers against the real software, not a fake of it written by the hand
// that wrote the provider. tools/live-providers.sh starts the servers that run in a container,
// provisions them and runs these: each test starts from the environment variables of its server,
// and is skipped without them.
//
// A server is given as the settings of its provider, in JSON as a credential has them, and the
// address of the DNS server that answers for its zone. In the zone, before the test:
//
//	other  AAAA 2001:db8::f
//	live   TXT  "keep"
//	@      TXT  "keep"   where the zone itself has records of its own
//
// Every change goes through NewService and Update, as the worker's, and is then looked up with a
// DNS query to the server: what the provider's own listing says is not asked.

package ddns

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	liveOtherIP = "2001:db8::f"
	liveKeep    = "keep"
)

// liveRecord is a record as the server has it: its data and TTL.
type liveRecord struct {
	data string
	ttl  int
}

// liveServer is a provider at a real server.
type liveServer struct {
	provider string
	settings map[string]any
	// The zone, without the final dot.
	zone string
	// The records of a name and type, asked of the server apart from the provider.
	records func(t *testing.T, fqdn, rrType string) []liveRecord
	// The TTLs of the settings to go through, and whether the records show them: empty for a
	// provider without one.
	ttls []string
	// The time the server has to serve a change after the update returned: none, unless the
	// real one is known to take it.
	settle time.Duration
	// service makes the provider from its settings, and counts the changes it asks of the
	// server: nil where nothing can stand between them to count.
	service func(t *testing.T, settings json.RawMessage) (Service, func() int)
	// fixtures checks what the test must leave alone.
	fixtures func(t *testing.T)
}

// liveSettings reads the settings of a provider from the environment, or skips the test.
func liveSettings(t *testing.T, variable string) map[string]any {
	t.Helper()
	value := os.Getenv(variable)
	if value == "" {
		t.Skipf("%s is not set: see tools/live-providers.sh", variable)
	}
	var settings map[string]any
	if err := json.Unmarshal([]byte(value), &settings); err != nil {
		t.Fatalf("%s: %v", variable, err)
	}
	return settings
}

func liveEnv(t *testing.T, variable string) string {
	t.Helper()
	value := os.Getenv(variable)
	if value == "" {
		t.Skipf("%s is not set: see tools/live-providers.sh", variable)
	}
	return value
}

// with returns the settings with one changed.
func (s *liveServer) with(key string, value any) json.RawMessage {
	settings := make(map[string]any, len(s.settings)+1)
	for k, v := range s.settings {
		settings[k] = v
	}
	if key != "" {
		settings[key] = value
	}
	raw, _ := json.Marshal(settings)
	return raw
}

// countingProxy stands between a provider and its real server at target, and counts the requests
// that change something there.
func countingProxy(t *testing.T, target string, isWrite func(*http.Request) bool) (string, func() int) {
	t.Helper()
	upstream, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	var writes atomic.Int64
	proxy := &httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) {
		if isWrite(r.In) {
			writes.Add(1)
		}
		r.SetURL(upstream)
	}}
	server := httptest.NewServer(proxy)
	t.Cleanup(server.Close)
	return server.URL, func() int { return int(writes.Load()) }
}

// queryDNS asks server, a host:port, for the records of a name and type, without recursion, and
// returns the answers of that type: none for a name without them, or that doesn't exist.
func queryDNS(t *testing.T, server, name, rrType string) []liveRecord {
	t.Helper()
	qtype := map[string]dnsmessage.Type{"A": dnsmessage.TypeA, "AAAA": dnsmessage.TypeAAAA, "TXT": dnsmessage.TypeTXT}[rrType]
	qname, err := dnsmessage.NewName(strings.TrimSuffix(name, ".") + ".")
	if err != nil {
		t.Fatalf("name %s: %v", name, err)
	}
	query := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: uint16(time.Now().UnixNano())},
		Questions: []dnsmessage.Question{{Name: qname, Type: qtype, Class: dnsmessage.ClassINET}},
	}
	packed, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}

	exchange := func(network string) (dnsmessage.Message, error) {
		var reply dnsmessage.Message
		conn, err := net.DialTimeout(network, server, 3*time.Second)
		if err != nil {
			return reply, err
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		out := packed
		if network == "tcp" {
			out = append([]byte{byte(len(packed) >> 8), byte(len(packed))}, packed...)
		}
		if _, err := conn.Write(out); err != nil {
			return reply, err
		}
		buffer := make([]byte, 65535+2)
		n := 0
		if network == "tcp" {
			for n < 2 || n < 2+int(buffer[0])<<8+int(buffer[1]) {
				m, err := conn.Read(buffer[n:])
				if err != nil {
					return reply, err
				}
				n += m
			}
			buffer, n = buffer[2:], n-2
		} else if n, err = conn.Read(buffer); err != nil {
			return reply, err
		}
		if err := reply.Unpack(buffer[:n]); err != nil {
			return reply, err
		}
		if reply.ID != query.ID {
			return reply, errors.New("an answer to another query")
		}
		return reply, nil
	}

	var reply dnsmessage.Message
	for attempt := range 3 { // UDP loses packets
		if reply, err = exchange("udp"); err == nil {
			break
		}
		if attempt == 2 {
			t.Fatalf("DNS query of %s %s to %s: %v", name, rrType, server, err)
		}
	}
	if reply.Truncated {
		if reply, err = exchange("tcp"); err != nil {
			t.Fatalf("DNS query of %s %s to %s over TCP: %v", name, rrType, server, err)
		}
	}
	if reply.RCode != dnsmessage.RCodeSuccess && reply.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("DNS query of %s %s to %s: %v", name, rrType, server, reply.RCode)
	}

	var records []liveRecord
	for _, answer := range reply.Answers {
		record := liveRecord{ttl: int(answer.Header.TTL)}
		switch body := answer.Body.(type) {
		case *dnsmessage.AResource:
			record.data = net.IP(body.A[:]).String()
		case *dnsmessage.AAAAResource:
			record.data = net.IP(body.AAAA[:]).String()
		case *dnsmessage.TXTResource:
			record.data = strings.Join(body.TXT, "")
		default:
			continue
		}
		if answer.Header.Type == qtype {
			records = append(records, record)
		}
	}
	return records
}

// dnsRecords are the records of a liveServer whose zone the DNS server at address answers for.
func dnsRecords(address string) func(*testing.T, string, string) []liveRecord {
	return func(t *testing.T, fqdn, rrType string) []liveRecord {
		t.Helper()
		return queryDNS(t, address, fqdn, rrType)
	}
}

// addresses are the A and AAAA records of fqdn at the server, as "AAAA 2001:db8::1", sorted, and
// the TTLs they have.
func (s *liveServer) addresses(t *testing.T, fqdn string) (addresses []string, ttls []int) {
	t.Helper()
	for _, rrType := range []string{"A", "AAAA"} {
		for _, record := range s.records(t, fqdn, rrType) {
			ip, ok := canonicalIP(record.data)
			if !ok {
				t.Errorf("%s has the %s record %q, not an address", fqdn, rrType, record.data)
			}
			addresses = append(addresses, rrType+" "+ip)
			if !slices.Contains(ttls, record.ttl) {
				ttls = append(ttls, record.ttl)
			}
		}
	}
	slices.Sort(addresses)
	return addresses, ttls
}

// expect checks that the server has the addresses wanted for fqdn and no other, as
// "AAAA 2001:db8::1", with the TTL when there is one.
func (s *liveServer) expect(t *testing.T, step, fqdn, ttl string, want ...string) {
	t.Helper()
	slices.Sort(want)
	wantTTL := 0
	if ttl != "" {
		d, err := time.ParseDuration(ttl)
		if err != nil {
			t.Fatal(err)
		}
		wantTTL = int(d.Seconds())
	}
	matches := func() (bool, []string, []int) {
		got, ttls := s.addresses(t, fqdn)
		ok := slices.Equal(got, want)
		if wantTTL != 0 && len(want) > 0 && !slices.Equal(ttls, []int{wantTTL}) {
			ok = false
		}
		return ok, got, ttls
	}
	ok, got, ttls := matches()
	for deadline := time.Now().Add(s.settle); !ok && time.Now().Before(deadline); {
		time.Sleep(50 * time.Millisecond)
		ok, got, ttls = matches()
	}
	if !ok {
		t.Errorf("%s: the server has %v for %s, with the TTLs %v: want %v, with the TTL %d", step, got, fqdn, ttls, want, wantTTL)
	}
	if s.fixtures != nil {
		s.fixtures(t)
	}
}

// dnsFixtures checks the records the script made, which no update is to touch: those of another
// name, and those of another type of the names updated.
func (s *liveServer) dnsFixtures(names ...string) func(*testing.T) {
	return func(t *testing.T) {
		t.Helper()
		other := "other." + s.zone
		if got := s.records(t, other, "AAAA"); len(got) != 1 || got[0].data != liveOtherIP {
			t.Errorf("%s has %v, want its record of %s untouched", other, got, liveOtherIP)
		}
		for _, name := range names {
			if got := s.records(t, name, "TXT"); len(got) != 1 || got[0].data != liveKeep {
				t.Errorf("%s has the TXT records %v, want its %q untouched", name, got, liveKeep)
			}
		}
	}
}

// run takes the records of fqdn through what an Update is for: created, of both families, left as
// they are, changed, their TTL changed, one family gone, and all gone. Each update names the host
// with another of spellings, which are all the same name: the records one made are the ones the
// next finds.
func (s *liveServer) run(t *testing.T, fqdn string, spellings ...string) {
	ttls := s.ttls
	if len(ttls) == 0 {
		ttls = []string{"", ""}
	}
	setting := ""
	if ttls[0] != "" {
		setting = "ttl"
	}
	service, writes := s.service(t, s.with(setting, ttls[0]))
	if got := service.Domain(spellings[0]); !strings.EqualFold(got, fqdn) {
		t.Errorf("Domain(%q) = %q, want %q", spellings[0], got, fqdn)
	}
	clear := func() error {
		service, err := NewService(s.provider, s.with("", nil))
		if err != nil {
			t.Fatal(err)
		}
		return service.Update(spellings[0], collectionWith())
	}
	// A name with addresses that are not the test's is not the test's either: it ends here, before
	// anything deletes them. Those a test that was killed left are deleted.
	got, _ := s.addresses(t, fqdn)
	for _, address := range got {
		if !strings.HasPrefix(address, "AAAA 2001:db8::") && !strings.HasPrefix(address, "A 192.0.2.") {
			t.Fatalf("%s has %v before the test: want no addresses", fqdn, got)
		}
	}
	if len(got) != 0 {
		if err := clear(); err != nil {
			t.Fatalf("%s has %v, of a test before: %v", fqdn, got, err)
		}
		s.expect(t, "cleared, before the test", fqdn, "")
	}
	s.fixtures(t)
	// The name is left without addresses, whatever the test does from here.
	t.Cleanup(func() {
		if err := clear(); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})

	spelling := 0
	update := func(step string, service Service, ips ...string) {
		t.Helper()
		hostname := spellings[spelling%len(spellings)]
		spelling++
		if err := service.Update(hostname, collectionWith(ips...)); err != nil {
			t.Fatalf("%s: Update(%q): %v", step, hostname, err)
		}
	}
	// unchanged runs the update again, under each spelling: the server is asked for nothing.
	unchanged := func(step string, service Service, writes func() int, ips ...string) {
		t.Helper()
		for range spellings {
			before := 0
			if writes != nil {
				before = writes()
			}
			update(step, service, ips...)
			if writes == nil {
				continue
			}
			if made := writes() - before; made != 0 {
				t.Errorf("%s: Update(%q) again asked for %d changes, want none", step, spellings[(spelling-1)%len(spellings)], made)
			}
		}
	}

	step := "created"
	update(step, service, "2001:db8::1", "2001:db8::2", "192.0.2.1")
	if writes != nil && writes() == 0 {
		t.Fatalf("%s: no change was counted: the count of the others means nothing", step)
	}
	s.expect(t, step, fqdn, ttls[0], "AAAA 2001:db8::1", "AAAA 2001:db8::2", "A 192.0.2.1")
	unchanged(step, service, writes, "2001:db8::1", "2001:db8::2", "192.0.2.1")
	s.expect(t, step+", and updated again", fqdn, ttls[0], "AAAA 2001:db8::1", "AAAA 2001:db8::2", "A 192.0.2.1")

	step = "changed"
	update(step, service, "2001:db8::2", "2001:db8::3", "192.0.2.2")
	s.expect(t, step, fqdn, ttls[0], "AAAA 2001:db8::2", "AAAA 2001:db8::3", "A 192.0.2.2")
	unchanged(step, service, writes, "2001:db8::2", "2001:db8::3", "192.0.2.2")

	if ttls[0] != "" {
		step = "TTL changed"
		service, writes = s.service(t, s.with("ttl", ttls[1]))
		update(step, service, "2001:db8::2", "2001:db8::3", "192.0.2.2")
		s.expect(t, step, fqdn, ttls[1], "AAAA 2001:db8::2", "AAAA 2001:db8::3", "A 192.0.2.2")
		unchanged(step, service, writes, "2001:db8::2", "2001:db8::3", "192.0.2.2")
	}

	step = "IPv6 only"
	update(step, service, "2001:db8::3")
	s.expect(t, step, fqdn, ttls[1], "AAAA 2001:db8::3")
	unchanged(step, service, writes, "2001:db8::3")

	step = "IPv4 only"
	update(step, service, "192.0.2.2")
	s.expect(t, step, fqdn, ttls[1], "A 192.0.2.2")

	step = "without addresses"
	update(step, service)
	s.expect(t, step, fqdn, "")
	unchanged(step, service, writes)
	s.expect(t, step+", and updated again", fqdn, "")
}

// zoneSpellings are the ways to name host in zone that are the same name: alone, with the zone,
// with its final dot, and in another case. An empty host is the zone itself.
func zoneSpellings(host, zone string) []string {
	if host == "" {
		return []string{"", zone, zone + ".", strings.ToUpper(zone)}
	}
	return []string{host, host + "." + zone, host + "." + zone + ".", strings.ToUpper(host[:1]) + host[1:] + "." + strings.ToUpper(zone)}
}

// httpService makes the provider with the address of its settings, under key, through a
// countingProxy.
func (s *liveServer) httpService(key string, isWrite func(*http.Request) bool) func(*testing.T, json.RawMessage) (Service, func() int) {
	return func(t *testing.T, raw json.RawMessage) (Service, func() int) {
		t.Helper()
		var settings map[string]any
		json.Unmarshal(raw, &settings)
		proxied, writes := countingProxy(t, fmt.Sprint(settings[key]), isWrite)
		settings[key] = proxied
		raw, _ = json.Marshal(settings)
		service, err := NewService(s.provider, raw)
		if err != nil {
			t.Fatal(err)
		}
		return service, writes
	}
}

// Technitium DNS Server: IPV6DDNS_LIVE_TECHNITIUM has the settings, with the primary zone, and
// IPV6DDNS_LIVE_TECHNITIUM_DNS the address of its DNS server.
func TestLiveTechnitium(t *testing.T) {
	s := &liveServer{provider: "technitium", settings: liveSettings(t, "IPV6DDNS_LIVE_TECHNITIUM"), ttls: []string{"10m", "1m30s"}}
	s.zone = fmt.Sprint(s.settings["zone"])
	s.records = dnsRecords(liveEnv(t, "IPV6DDNS_LIVE_TECHNITIUM_DNS"))
	s.service = s.httpService("address", func(r *http.Request) bool { return !strings.HasSuffix(r.URL.Path, "/records/get") })
	s.fixtures = s.dnsFixtures("live."+s.zone, s.zone)

	t.Run("name", func(t *testing.T) { s.run(t, "live."+s.zone, zoneSpellings("live", s.zone)...) })
	t.Run("zone", func(t *testing.T) { s.run(t, s.zone, zoneSpellings("", s.zone)...) })
}

// AdGuard Home: IPV6DDNS_LIVE_ADGUARDHOME has the settings, and IPV6DDNS_LIVE_ADGUARDHOME_DNS the
// address of its DNS server. A name with a rewrite answers nothing of another type, so the only
// record to leave alone is the other name's.
func TestLiveAdGuardHome(t *testing.T) {
	s := &liveServer{provider: "adguardhome", settings: liveSettings(t, "IPV6DDNS_LIVE_ADGUARDHOME")}
	s.zone = fmt.Sprint(s.settings["zone"])
	s.records = dnsRecords(liveEnv(t, "IPV6DDNS_LIVE_ADGUARDHOME_DNS"))
	s.service = s.httpService("address", func(r *http.Request) bool { return r.Method != http.MethodGet })
	s.fixtures = s.dnsFixtures()

	t.Run("name", func(t *testing.T) { s.run(t, "live."+s.zone, zoneSpellings("live", s.zone)...) })
	t.Run("zone", func(t *testing.T) { s.run(t, s.zone, zoneSpellings("", s.zone)...) })
}

// Pi-hole: IPV6DDNS_LIVE_PIHOLE has the settings, and IPV6DDNS_LIVE_PIHOLE_DNS the address of its
// DNS server. A session is no change.
func TestLivePiHole(t *testing.T) {
	s := &liveServer{provider: "pihole", settings: liveSettings(t, "IPV6DDNS_LIVE_PIHOLE")}
	s.zone = fmt.Sprint(s.settings["zone"])
	s.records = dnsRecords(liveEnv(t, "IPV6DDNS_LIVE_PIHOLE_DNS"))
	s.service = s.httpService("address", func(r *http.Request) bool {
		return r.Method != http.MethodGet && !strings.HasSuffix(r.URL.Path, "/api/auth")
	})
	s.fixtures = s.dnsFixtures("live."+s.zone, s.zone)

	t.Run("name", func(t *testing.T) { s.run(t, "live."+s.zone, zoneSpellings("live", s.zone)...) })
	t.Run("zone", func(t *testing.T) { s.run(t, s.zone, zoneSpellings("", s.zone)...) })
}

// A server of RFC 2136, BIND: IPV6DDNS_LIVE_RFC2136 has the settings, with the TSIG key the zone
// takes updates signed with, and IPV6DDNS_LIVE_RFC2136_DNS the address of its DNS server. The
// changes are counted by a proxy of the TCP connections that carry an update; the queries that
// read the records go through it too.
func TestLiveRFC2136(t *testing.T) {
	s := &liveServer{provider: "rfc2136", settings: liveSettings(t, "IPV6DDNS_LIVE_RFC2136"), ttls: []string{"10m", "1m30s"}}
	s.zone = fmt.Sprint(s.settings["zone"])
	s.records = dnsRecords(liveEnv(t, "IPV6DDNS_LIVE_RFC2136_DNS"))
	s.service = func(t *testing.T, raw json.RawMessage) (Service, func() int) {
		t.Helper()
		var settings map[string]any
		json.Unmarshal(raw, &settings)
		proxied, updates := countingDNSUpdates(t, fmt.Sprint(settings["server"]))
		settings["server"] = proxied
		raw, _ = json.Marshal(settings)
		service, err := NewService(s.provider, raw)
		if err != nil {
			t.Fatal(err)
		}
		return service, updates
	}
	s.fixtures = s.dnsFixtures("live."+s.zone, s.zone)

	t.Run("name", func(t *testing.T) { s.run(t, "live."+s.zone, zoneSpellings("live", s.zone)...) })
	t.Run("zone", func(t *testing.T) { s.run(t, s.zone, zoneSpellings("", s.zone)...) })

	// A key the server doesn't take: the update fails, and says why.
	t.Run("a wrong key", func(t *testing.T) {
		wrong := s.with("tsig_secret", "d3Jvbmctc2VjcmV0LXdyb25nLXNlY3JldC13cm9uZyE=")
		service, err := NewService(s.provider, wrong)
		if err != nil {
			t.Fatal(err)
		}
		err = service.Update("live", collectionWith("2001:db8::1"))
		if err == nil || !strings.Contains(err.Error(), "live-key") {
			t.Errorf("a wrong secret: %v", err)
		}
		s.fixtures(t)
	})
}

// countingDNSUpdates stands between a provider and a DNS server over TCP at target, and counts the
// updates: the messages whose opcode is UPDATE.
func countingDNSUpdates(t *testing.T, target string) (string, func() int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	var updates atomic.Int64
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer client.Close()
				server, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer server.Close()
				go io.Copy(client, server)
				reader := bufio.NewReader(client)
				for {
					var length [2]byte
					if _, err := io.ReadFull(reader, length[:]); err != nil {
						return
					}
					message := make([]byte, int(length[0])<<8|int(length[1]))
					if _, err := io.ReadFull(reader, message); err != nil {
						return
					}
					// The opcode is bits 1 to 4 of the third byte: 5 is UPDATE.
					if len(message) > 2 && message[2]>>3&0xf == 5 {
						updates.Add(1)
					}
					if _, err := server.Write(append(length[:], message...)); err != nil {
						return
					}
				}
			}()
		}
	}()
	return listener.Addr().String(), func() int { return int(updates.Load()) }
}

// Gravity: IPV6DDNS_LIVE_GRAVITY has the settings, with the zone, and IPV6DDNS_LIVE_GRAVITY_DNS
// the address of its DNS server.
func TestLiveGravity(t *testing.T) {
	s := &liveServer{provider: "gravity", settings: liveSettings(t, "IPV6DDNS_LIVE_GRAVITY"), ttls: []string{"10m", "1m30s"}}
	s.zone = strings.TrimSuffix(fmt.Sprint(s.settings["zone"]), ".")
	s.records = dnsRecords(liveEnv(t, "IPV6DDNS_LIVE_GRAVITY_DNS"))
	s.service = s.httpService("server", func(r *http.Request) bool { return r.Method != http.MethodGet })
	s.fixtures = s.dnsFixtures("live."+s.zone, s.zone)

	t.Run("name", func(t *testing.T) { s.run(t, "live."+s.zone, zoneSpellings("live", s.zone)...) })
	t.Run("zone", func(t *testing.T) { s.run(t, s.zone, zoneSpellings("", s.zone)...) })

	// The default TTL, of the settings without one.
	t.Run("default TTL", func(t *testing.T) {
		s := *s
		delete(s.settings, "ttl")
		s.ttls = nil
		service, _ := s.service(t, s.with("", nil))
		t.Cleanup(func() { service.Update("live", collectionWith()) })
		if err := service.Update("live", collectionWith("2001:db8::1")); err != nil {
			t.Fatal(err)
		}
		s.expect(t, "created", "live."+s.zone, gravityDefaultTTL.String(), "AAAA 2001:db8::1")
	})
}

// countingRunner counts the commands that change something on the host.
type countingRunner struct {
	commandRunner
	writes *atomic.Int64
}

func (r countingRunner) Run(command string) ([]byte, error) {
	if command != "uci -X show dhcp" && command != "uci changes dhcp" {
		r.writes.Add(1)
	}
	return r.commandRunner.Run(command)
}

// openWrtService makes the provider, which connects over SSH as it does, and counts the commands
// that change something.
func openWrtService(t *testing.T, raw json.RawMessage) (Service, func() int) {
	t.Helper()
	service, err := NewService("openwrt", raw)
	if err != nil {
		t.Fatal(err)
	}
	var writes atomic.Int64
	openwrt := service.(*OpenWrt)
	openwrt.dial = func() (commandRunner, error) {
		runner, err := openwrt.connect()
		if err != nil {
			return nil, err
		}
		return countingRunner{runner, &writes}, nil
	}
	return service, func() int { return int(writes.Load()) }
}

// OpenWrt: IPV6DDNS_LIVE_OPENWRT has the settings, with the SSH key, and
// IPV6DDNS_LIVE_OPENWRT_DNS the address of its dnsmasq.
func TestLiveOpenWrt(t *testing.T) {
	s := &liveServer{provider: "openwrt", settings: liveSettings(t, "IPV6DDNS_LIVE_OPENWRT"), service: openWrtService}
	s.zone = fmt.Sprint(s.settings["zone"])
	s.records = dnsRecords(liveEnv(t, "IPV6DDNS_LIVE_OPENWRT_DNS"))
	s.fixtures = s.dnsFixtures("live." + s.zone)

	t.Run("name", func(t *testing.T) { s.run(t, "live."+s.zone, zoneSpellings("live", s.zone)...) })
	t.Run("zone", func(t *testing.T) { s.run(t, s.zone, zoneSpellings("", s.zone)...) })
}

// The host key of a real dropbear: without one in the settings the update goes on and the warning
// tells the fingerprint, which then verifies it, as does that of the host's other key. Another
// fingerprint ends the update before a command.
func TestLiveOpenWrtHostKey(t *testing.T) {
	s := &liveServer{provider: "openwrt", settings: liveSettings(t, "IPV6DDNS_LIVE_OPENWRT")}
	hostKeys := strings.Fields(liveEnv(t, "IPV6DDNS_LIVE_OPENWRT_HOST_KEYS"))
	if len(hostKeys) < 2 {
		t.Fatalf("IPV6DDNS_LIVE_OPENWRT_HOST_KEYS has %d fingerprints, want those of the host's keys, of two kinds or more", len(hostKeys))
	}

	update := func(hostKey string) (Service, error) {
		t.Helper()
		service, err := NewService("openwrt", s.with("host_key", hostKey))
		if err != nil {
			t.Fatal(err)
		}
		return service, service.Update("live", collectionWith())
	}

	service, err := update("")
	if err != nil {
		t.Fatalf("without a host key: %v", err)
	}
	warnings := service.(Warner).Warnings()
	if len(warnings) != 1 || !slices.ContainsFunc(hostKeys, func(key string) bool { return strings.HasSuffix(warnings[0], key) }) {
		t.Errorf("without a host key, the warnings are %q: want one, with a fingerprint of the host's, %v", warnings, hostKeys)
	}

	for _, hostKey := range hostKeys {
		service, err := update(hostKey)
		if err != nil {
			t.Errorf("with the host key %s: %v", hostKey, err)
		}
		if warnings := service.(Warner).Warnings(); len(warnings) != 0 {
			t.Errorf("with the host key %s, the warnings are %q: want none", hostKey, warnings)
		}
	}

	other := "SHA256:" + strings.Repeat("A", 43)
	if _, err := update(other); !errors.Is(err, errHostKeyMismatch) {
		t.Errorf("with the key of another host: got %v, want %v", err, errHostKeyMismatch)
	}
}

// countingRouterOSProxy stands between the provider and the API of a real RouterOS at target, and
// counts the commands that change its static DNS.
func countingRouterOSProxy(t *testing.T, target string) (string, func() int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	var writes atomic.Int64
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				router, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer router.Close()
				go func() {
					io.Copy(conn, router)
					conn.Close()
				}()
				// A command is counted before the router has it, and so before the provider
				// has its answer.
				r := bufio.NewReader(io.TeeReader(conn, router))
				for {
					words, err := readSentence(r)
					if err != nil {
						return
					}
					switch words[0] {
					case "/ip/dns/static/add", "/ip/dns/static/set", "/ip/dns/static/remove":
						writes.Add(1)
					}
				}
			}()
		}
	}()
	return listener.Addr().String(), func() int { return int(writes.Load()) }
}

// Mikrotik RouterOS: IPV6DDNS_LIVE_MIKROTIK has the settings, of the API without TLS, and
// IPV6DDNS_LIVE_MIKROTIK_DNS the address of its DNS server, which answers remote requests.
//
// The names are not spelled in another case here: RouterOS answers for a static record whatever
// the case of the query, and lists those of a name in the case asked only. The records of a name
// written in another case are, to the provider, those of another name.
func TestLiveMikrotik(t *testing.T) {
	s := &liveServer{provider: "mikrotik", settings: liveSettings(t, "IPV6DDNS_LIVE_MIKROTIK"), ttls: []string{"10m", "1m30s"}}
	s.zone = fmt.Sprint(s.settings["zone"])
	s.records = dnsRecords(liveEnv(t, "IPV6DDNS_LIVE_MIKROTIK_DNS"))
	s.service = func(t *testing.T, raw json.RawMessage) (Service, func() int) {
		t.Helper()
		var settings map[string]any
		json.Unmarshal(raw, &settings)
		proxied, writes := countingRouterOSProxy(t, fmt.Sprint(settings["address"]))
		settings["address"] = proxied
		raw, _ = json.Marshal(settings)
		service, err := NewService("mikrotik", raw)
		if err != nil {
			t.Fatal(err)
		}
		return service, writes
	}
	s.fixtures = s.dnsFixtures("live."+s.zone, s.zone)

	t.Run("name", func(t *testing.T) { s.run(t, "live."+s.zone, zoneSpellings("live", s.zone)[:3]...) })
	t.Run("zone", func(t *testing.T) { s.run(t, s.zone, zoneSpellings("", s.zone)[:3]...) })
}

// The api-ssl service of a real RouterOS, with the certificate it made for itself:
// IPV6DDNS_LIVE_MIKROTIK_TLS has the settings, with its address and the fingerprint of the
// certificate. The fingerprint is what verifies it: without one the update ends with it in the
// error, to configure, and with another it ends too.
func TestLiveMikrotikTLS(t *testing.T) {
	s := &liveServer{provider: "mikrotik", settings: liveSettings(t, "IPV6DDNS_LIVE_MIKROTIK_TLS")}
	s.zone = fmt.Sprint(s.settings["zone"])
	s.records = dnsRecords(liveEnv(t, "IPV6DDNS_LIVE_MIKROTIK_DNS"))
	fingerprint := fmt.Sprint(s.settings["tls_fingerprint"])

	update := func(fingerprint string, ips ...string) error {
		t.Helper()
		service, err := NewService("mikrotik", s.with("tls_fingerprint", fingerprint))
		if err != nil {
			t.Fatal(err)
		}
		return service.Update("live-tls", collectionWith(ips...))
	}
	t.Cleanup(func() { update(fingerprint) })

	if err := update(fingerprint, "2001:db8::1"); err != nil {
		t.Fatalf("with the fingerprint of its certificate: %v", err)
	}
	s.expect(t, "over TLS", "live-tls."+s.zone, fmt.Sprint(s.settings["ttl"]), "AAAA 2001:db8::1")

	if err := update("", "2001:db8::2"); err == nil || !strings.Contains(err.Error(), fingerprint) {
		t.Errorf("without a fingerprint: got %v, want an error with the fingerprint, %s", err, fingerprint)
	}
	if err := update(strings.Repeat("0", 64), "2001:db8::2"); err == nil {
		t.Errorf("with the fingerprint of another certificate: the update went on")
	}
	s.expect(t, "after the updates refused", "live-tls."+s.zone, fmt.Sprint(s.settings["ttl"]), "AAAA 2001:db8::1")
}
