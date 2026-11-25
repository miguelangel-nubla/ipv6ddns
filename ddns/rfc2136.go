package ddns

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/duration"
	"github.com/miguelangel-nubla/ipv6disc"
)

// RFC2136 keeps the addresses of a name at a DNS server that takes dynamic updates, RFC 2136, as
// BIND, Knot and PowerDNS do, and Windows DNS where it allows nonsecure updates: in one update, which the server applies whole or not
// at all, signed with a TSIG key when there is one.
type RFC2136 struct {
	Server        string            `json:"server"`
	Zone          string            `json:"zone"`
	TTL           duration.Duration `json:"ttl"`
	TSIGKey       string            `json:"tsig_key"`
	TSIGSecret    string            `json:"tsig_secret"`
	TSIGAlgorithm string            `json:"tsig_algorithm"`
}

func init() {
	RegisterProvider("rfc2136", NewRFC2136)
	RegisterTXT("rfc2136")
}

func NewRFC2136(settings json.RawMessage) (Service, error) {
	var service RFC2136
	if err := decodeSettings(settings, "rfc2136", &service); err != nil {
		return nil, err
	}
	if (service.TSIGKey == "") != (service.TSIGSecret == "") {
		return nil, errors.New("rfc2136: give tsig_key and tsig_secret together, or neither")
	}
	return &service, nil
}

// rfc2136Algorithms are the TSIG algorithms, by the names the settings take.
var rfc2136Algorithms = map[string]string{
	"hmac-sha1":   dns.HmacSHA1,
	"hmac-sha224": dns.HmacSHA224,
	"hmac-sha256": dns.HmacSHA256,
	"hmac-sha384": dns.HmacSHA384,
	"hmac-sha512": dns.HmacSHA512,
}

// rfc2136Served is how long the server has to answer with the records after it applied the update:
// at once, for the servers that apply an update before they answer it, as BIND does. A variable,
// for the tests to shorten.
var (
	rfc2136Served         = 5 * time.Second
	rfc2136ServedInterval = 100 * time.Millisecond
)

func (r *RFC2136) Update(hostname string, addrCollection *ipv6disc.AddrCollection) error {
	server := withDefaultPort(r.Server, "53")
	name := dns.Fqdn(r.Domain(hostname))
	ttl := uint32(r.TTL.Seconds())
	desired := desiredRecords(addrCollection)

	current, err := r.records(server, name)
	if err != nil {
		return fmt.Errorf("failed to read the records of %s: %w", name, err)
	}
	if rfc2136Same(current, desired, ttl) {
		return nil
	}

	// One update, applied whole: the name's A and AAAA records go, and the addresses are added.
	// Its records of other types stay.
	update := new(dns.Msg)
	update.SetUpdate(dns.Fqdn(r.Zone))
	header := func(rrType uint16) dns.RR_Header {
		return dns.RR_Header{Name: name, Rrtype: rrType, Class: dns.ClassINET, Ttl: ttl}
	}
	update.RemoveRRset([]dns.RR{&dns.A{Hdr: header(dns.TypeA)}, &dns.AAAA{Hdr: header(dns.TypeAAAA)}})
	var inserts []dns.RR
	for _, ip := range slices.Sorted(maps.Keys(desired)) {
		parsed := net.ParseIP(ip)
		if desired[ip] == "A" {
			inserts = append(inserts, &dns.A{Hdr: header(dns.TypeA), A: parsed.To4()})
		} else {
			inserts = append(inserts, &dns.AAAA{Hdr: header(dns.TypeAAAA), AAAA: parsed})
		}
	}
	if len(inserts) > 0 {
		update.Insert(inserts)
	}
	reply, err := r.exchange(update, server)
	if err != nil {
		return fmt.Errorf("failed to update %s: %w", name, err)
	}
	if reply.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("failed to update %s: %s", name, rfc2136Refusal(reply.Rcode, r.Zone, r.TSIGKey != ""))
	}

	// The update returns once the server answers with the records.
	deadline := time.Now().Add(rfc2136Served)
	for {
		current, err = r.records(server, name)
		if err == nil && rfc2136Same(current, desired, ttl) {
			return nil
		}
		if time.Now().After(deadline) {
			if err != nil {
				return fmt.Errorf("%s was updated, but reading it back failed: %w", name, err)
			}
			return fmt.Errorf("%s was updated, but after %s the server answers with %v: is it the primary of %s, and does it serve what it is sent?", name, rfc2136Served, slices.Sorted(maps.Keys(current)), r.Zone)
		}
		time.Sleep(rfc2136ServedInterval)
	}
}

// rfc2136Record is an address record as the server answers it: its type and TTL.
type rfc2136Record struct {
	rrType string
	ttl    uint32
}

// records are the A and AAAA records of name, as the server answers them, by address.
func (r *RFC2136) records(server, name string) (map[string]rfc2136Record, error) {
	records := make(map[string]rfc2136Record)
	for _, rrType := range []uint16{dns.TypeA, dns.TypeAAAA} {
		query := new(dns.Msg)
		query.SetQuestion(name, rrType)
		query.RecursionDesired = false
		reply, err := r.exchange(query, server)
		if err != nil {
			return nil, err
		}
		if reply.Rcode != dns.RcodeSuccess && reply.Rcode != dns.RcodeNameError {
			return nil, fmt.Errorf("the server answers %s", dns.RcodeToString[reply.Rcode])
		}
		for _, rr := range reply.Answer {
			if !strings.EqualFold(rr.Header().Name, name) {
				continue
			}
			switch rr := rr.(type) {
			case *dns.A:
				if ip, ok := canonicalIP(rr.A.String()); ok {
					records[ip] = rfc2136Record{"A", rr.Hdr.Ttl}
				}
			case *dns.AAAA:
				if ip, ok := canonicalIP(rr.AAAA.String()); ok {
					records[ip] = rfc2136Record{"AAAA", rr.Hdr.Ttl}
				}
			}
		}
	}
	return records, nil
}

// exchange sends the message over TCP, signed with the key when there is one, within the timeout
// of a request.
func (r *RFC2136) exchange(m *dns.Msg, server string) (*dns.Msg, error) {
	client := &dns.Client{Net: "tcp", Timeout: httpTimeout}
	if r.TSIGKey != "" {
		key := dns.Fqdn(r.TSIGKey)
		algorithm := rfc2136Algorithms[r.TSIGAlgorithm]
		if algorithm == "" {
			algorithm = dns.HmacSHA256
		}
		m.SetTsig(key, algorithm, 300, time.Now().Unix())
		client.TsigSecret = map[string]string{key: r.TSIGSecret}
	}
	reply, _, err := client.Exchange(m, server)
	if err != nil {
		if errors.Is(err, dns.ErrAuth) || errors.Is(err, dns.ErrSig) || errors.Is(err, dns.ErrSecret) || errors.Is(err, dns.ErrKeyAlg) {
			return nil, fmt.Errorf("%w: the server doesn't take the TSIG key %s: check its name, its secret and its algorithm", err, r.TSIGKey)
		}
		return nil, err
	}
	return reply, nil
}

// rfc2136Refusal tells why the server refused an update, and what to change on it.
func rfc2136Refusal(rcode int, zone string, signed bool) string {
	name := dns.RcodeToString[rcode]
	switch rcode {
	case dns.RcodeRefused:
		if signed {
			return name + ": the server doesn't let this key update the zone " + zone + ": allow it, as BIND's update-policy or allow-update does"
		}
		return name + ": the server doesn't take updates of the zone " + zone + " from this address: allow them, or give a TSIG key"
	case dns.RcodeNotAuth:
		return name + ": the server isn't the primary of the zone " + zone + ", or doesn't take the TSIG key"
	case dns.RcodeNotZone:
		return name + ": the name isn't in the zone " + zone
	}
	return name
}

// rfc2136Same tells whether the records are the addresses desired, with the TTL.
func rfc2136Same(current map[string]rfc2136Record, desired map[string]string, ttl uint32) bool {
	if len(current) != len(desired) {
		return false
	}
	for ip, rrType := range desired {
		record, ok := current[ip]
		if !ok || record.rrType != rrType || record.ttl != ttl {
			return false
		}
	}
	return true
}

// Domain is the name in the zone, in lower case, without the final dot.
func (r *RFC2136) Domain(hostname string) string {
	return lowerASCII(FQDN(hostname, r.Zone))
}

// SetTXT makes the TXT records of hostname the values, in one update, as Update does its
// addresses.
func (r *RFC2136) SetTXT(hostname string, values []string) error {
	server := withDefaultPort(r.Server, "53")
	name := dns.Fqdn(r.Domain(hostname))
	update := new(dns.Msg)
	update.SetUpdate(dns.Fqdn(r.Zone))
	header := dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: txtTTL}
	update.RemoveRRset([]dns.RR{&dns.TXT{Hdr: header}})
	var inserts []dns.RR
	for _, v := range values {
		inserts = append(inserts, &dns.TXT{Hdr: header, Txt: []string{v}})
	}
	if len(inserts) > 0 {
		update.Insert(inserts)
	}
	reply, err := r.exchange(update, server)
	if err != nil {
		return fmt.Errorf("failed to update the TXT records of %s: %w", name, err)
	}
	if reply.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("failed to update the TXT records of %s: %s", name, rfc2136Refusal(reply.Rcode, r.Zone, r.TSIGKey != ""))
	}
	want := slices.Sorted(slices.Values(values))
	deadline := time.Now().Add(rfc2136Served)
	for {
		got, err := r.txt(server, name)
		if err == nil && slices.Equal(got, want) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the TXT records of %s were updated, but after %s the server answers with %v: is it the primary of %s?", name, rfc2136Served, got, r.Zone)
		}
		time.Sleep(rfc2136ServedInterval)
	}
}

// txt are the TXT records of name, as the server answers them, sorted: each the text of its
// strings, joined.
func (r *RFC2136) txt(server, name string) ([]string, error) {
	query := new(dns.Msg)
	query.SetQuestion(name, dns.TypeTXT)
	query.RecursionDesired = false
	reply, err := r.exchange(query, server)
	if err != nil {
		return nil, err
	}
	var values []string
	for _, rr := range reply.Answer {
		if t, ok := rr.(*dns.TXT); ok && strings.EqualFold(t.Hdr.Name, name) {
			values = append(values, strings.Join(t.Txt, ""))
		}
	}
	slices.Sort(values)
	return values, nil
}

// FullName is Domain: the zone is known.
func (r *RFC2136) FullName(hostname string) (string, error) { return r.Domain(hostname), nil }
