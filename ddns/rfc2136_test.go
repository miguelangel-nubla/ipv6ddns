package ddns

import (
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const (
	rfc2136Key    = "ipv6ddns."
	rfc2136Secret = "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0IQ=="
)

// fakeRFC2136 is the primary of example.com: it applies the updates the TSIG key signs, or every
// one without a key, and answers queries from its records, which it keeps as their text.
type fakeRFC2136 struct {
	t       *testing.T
	mutex   sync.Mutex
	records []string
	updates int
	// What it answers an update with instead of applying it, when not zero.
	refuse int
	// Whether it answers an update without applying it, as a server that isn't the primary.
	ignore bool
	signed bool
}

func startFakeRFC2136(t *testing.T, f *fakeRFC2136, secret map[string]string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// It takes updates, which a server of the library refuses by default.
	server := &dns.Server{Listener: listener, Net: "tcp", Handler: f, TsigSecret: secret,
		MsgAcceptFunc: func(dns.Header) dns.MsgAcceptAction { return dns.MsgAccept }}
	go server.ActivateAndServe()
	t.Cleanup(func() { server.Shutdown() })
	return listener.Addr().String()
}

func (f *fakeRFC2136) ServeDNS(w dns.ResponseWriter, m *dns.Msg) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	reply := new(dns.Msg)
	reply.SetReply(m)
	sign := func() {
		if tsig := m.IsTsig(); tsig != nil {
			reply.SetTsig(tsig.Hdr.Name, tsig.Algorithm, 300, time.Now().Unix())
		}
	}
	if m.Opcode == dns.OpcodeUpdate {
		switch {
		case f.signed && (m.IsTsig() == nil || w.TsigStatus() != nil):
			reply.Rcode = dns.RcodeRefused
		case f.refuse != 0:
			reply.Rcode = f.refuse
		case len(m.Question) != 1 || m.Question[0].Name != "example.com.":
			reply.Rcode = dns.RcodeNotZone
		case !f.ignore:
			f.updates++
			for _, rr := range m.Ns {
				h := rr.Header()
				switch h.Class {
				case dns.ClassANY:
					f.records = slices.DeleteFunc(f.records, func(r string) bool {
						parsed, _ := dns.NewRR(r)
						return strings.EqualFold(parsed.Header().Name, h.Name) && parsed.Header().Rrtype == h.Rrtype
					})
				case dns.ClassINET:
					f.records = append(f.records, rr.String())
				default:
					f.t.Errorf("an update of the class %d", h.Class)
				}
			}
		}
		sign()
		w.WriteMsg(reply)
		return
	}
	reply.Authoritative = true
	q := m.Question[0]
	for _, r := range f.records {
		parsed, _ := dns.NewRR(r)
		if strings.EqualFold(parsed.Header().Name, q.Name) && parsed.Header().Rrtype == q.Qtype {
			reply.Answer = append(reply.Answer, parsed)
		}
	}
	sign()
	w.WriteMsg(reply)
}

func (f *fakeRFC2136) of(name string) []string {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	var got []string
	for _, r := range f.records {
		if strings.HasPrefix(r, name+"\t") {
			got = append(got, r)
		}
	}
	slices.Sort(got)
	return got
}

func TestRFC2136Update(t *testing.T) {
	for _, signed := range []bool{false, true} {
		name := "by address"
		if signed {
			name = "signed"
		}
		t.Run(name, func(t *testing.T) {
			fake := &fakeRFC2136{t: t, signed: signed, records: []string{
				"nas.example.com.\t300\tIN\tAAAA\t" + wantedIP,
				"nas.example.com.\t300\tIN\tAAAA\t" + obsoleteIP,
				"nas.example.com.\t300\tIN\tTXT\t\"keep\"",
				"other.example.com.\t300\tIN\tAAAA\t" + obsoleteIP,
			}}
			var secret map[string]string
			if signed {
				secret = map[string]string{rfc2136Key: rfc2136Secret}
			}
			address := startFakeRFC2136(t, fake, secret)
			service := &RFC2136{Server: address, Zone: "example.com"}
			service.TTL.Duration = 10 * time.Minute
			if signed {
				service.TSIGKey, service.TSIGSecret = "ipv6ddns", rfc2136Secret
			}

			if err := service.Update("NAS", desired()); err != nil {
				t.Fatal(err)
			}
			want := []string{
				"nas.example.com.\t300\tIN\tTXT\t\"keep\"",
				"nas.example.com.\t600\tIN\tA\t" + newIPv4,
				"nas.example.com.\t600\tIN\tAAAA\t" + newIP,
				"nas.example.com.\t600\tIN\tAAAA\t" + wantedIP,
			}
			slices.Sort(want)
			if got := fake.of("nas.example.com."); !slices.Equal(got, want) {
				t.Errorf("records:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
			}
			if got := fake.of("other.example.com."); len(got) != 1 {
				t.Errorf("the other name has %v", got)
			}

			before := fake.updates
			if err := service.Update("nas.example.com.", desired()); err != nil {
				t.Fatal(err)
			}
			if fake.updates != before {
				t.Errorf("the update again sent %d updates, want none", fake.updates-before)
			}

			// A changed TTL is an update too, and no addresses leaves the name its other records.
			service.TTL.Duration = time.Minute
			if err := service.Update("nas", desired()); err != nil {
				t.Fatal(err)
			}
			if got := fake.of("nas.example.com."); len(got) != 4 || !strings.Contains(strings.Join(got, "\n"), "\t60\tIN\tA\t") {
				t.Errorf("records after the TTL changed: %v", got)
			}
			if err := service.Update("nas", collectionWith()); err != nil {
				t.Fatal(err)
			}
			if got := fake.of("nas.example.com."); !slices.Equal(got, []string{"nas.example.com.\t300\tIN\tTXT\t\"keep\""}) {
				t.Errorf("records without addresses: %v", got)
			}
			if got := service.Domain("NAS"); got != "nas.example.com" {
				t.Errorf("Domain: %q", got)
			}
		})
	}
}

// What the server refuses tells why, and what to change on it; a key the server doesn't take, the
// same. The secret is never in an error.
func TestRFC2136Errors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fake   *fakeRFC2136
		secret map[string]string
		key    string
		want   []string
	}{
		{"refused, unsigned", &fakeRFC2136{refuse: dns.RcodeRefused}, nil, "", []string{"REFUSED", "from this address", "give a TSIG key"}},
		{"refused, signed", &fakeRFC2136{refuse: dns.RcodeRefused}, map[string]string{rfc2136Key: rfc2136Secret}, rfc2136Secret, []string{"REFUSED", "doesn't let this key update the zone example.com"}},
		{"not the primary", &fakeRFC2136{refuse: dns.RcodeNotAuth}, nil, "", []string{"NOTAUTH", "isn't the primary"}},
		{"a wrong secret", &fakeRFC2136{signed: true}, map[string]string{rfc2136Key: rfc2136Secret}, "d3Jvbmctc2VjcmV0", []string{"TSIG key ipv6ddns"}},
		{"applied, not served", &fakeRFC2136{ignore: true}, nil, "", []string{"was updated, but after", "is it the primary"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saved := rfc2136Served
			rfc2136Served = 300 * time.Millisecond
			t.Cleanup(func() { rfc2136Served = saved })
			tc.fake.t = t
			address := startFakeRFC2136(t, tc.fake, tc.secret)
			service := &RFC2136{Server: address, Zone: "example.com"}
			service.TTL.Duration = 5 * time.Minute
			if tc.key != "" {
				service.TSIGKey, service.TSIGSecret = "ipv6ddns", tc.key
			}
			err := service.Update("nas", desired())
			if err == nil {
				t.Fatal("no error")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q, without %q", err, want)
				}
			}
			if strings.Contains(err.Error(), tc.key) && tc.key != "" {
				t.Errorf("the secret is in the error %q", err)
			}
		})
	}
}

func TestRFC2136KeyAndSecretTogether(t *testing.T) {
	for _, settings := range []string{
		`{"server": "ns", "zone": "example.com", "ttl": "5m", "tsig_key": "k"}`,
		`{"server": "ns", "zone": "example.com", "ttl": "5m", "tsig_secret": "c2VjcmV0"}`,
	} {
		if _, err := NewService("rfc2136", []byte(settings)); err == nil || !strings.Contains(err.Error(), "together") {
			t.Errorf("%s: %v", settings, err)
		}
	}
}
