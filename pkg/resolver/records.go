package resolver

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DefaultTTL is the TTL of a resolver's records that give none, and of a zone's records and
// names, when its credential gives none.
const DefaultTTL = time.Minute

// NegativeTTL is how long a client keeps that a name has no data of a type: the minimum of the
// SOA the resolver makes for its zones. Short, so that a name whose host has no address yet has
// it soon after the host shows.
const NegativeTTL = 10 * time.Second

// lineOf takes off what miekg's parser adds to its errors: the line and column of the text it was
// given, which is the record's alone here, quoted beside.
var lineOf = regexp.MustCompile(` at line: \d+:\d+$`)

// ParseRecord reads a record in the syntax of a zone file, as "printer A 192.168.1.20" or
// "www.example.com. 300 CNAME nas.home.arpa.": a name, a TTL or not, the class IN or not, a type
// and its data. Relative names are of origin, a zone; without one, every name is to be absolute,
// with its trailing dot. A record without a TTL has ttl.
func ParseRecord(line, origin string, ttl time.Duration) (dns.RR, error) {
	text := strings.TrimSpace(line)
	if text == "" || strings.HasPrefix(text, ";") {
		return nil, errors.New("empty record: give a name, a type and its data, as printer A 192.168.1.20")
	}
	if strings.HasPrefix(text, "$") {
		return nil, errors.New("zone file directives aren't records: give only the records")
	}
	if strings.ContainsAny(text, "\n\r") {
		return nil, errors.New("more than one line: give each record as its own entry")
	}
	name := strings.Fields(text)[0]
	if origin == "" && !strings.HasSuffix(name, ".") {
		return nil, fmt.Errorf("the name %s must be absolute, ending in a dot, as %s.: these records belong to no zone", name, name)
	}
	head := fmt.Sprintf("$TTL %d\n", int(ttl.Seconds()))
	if origin != "" {
		head += "$ORIGIN " + dns.Fqdn(origin) + "\n"
	}
	parser := dns.NewZoneParser(strings.NewReader(head+text+"\n"), "", "")
	var records []dns.RR
	for rr, ok := parser.Next(); ok; rr, ok = parser.Next() {
		records = append(records, rr)
	}
	if err := parser.Err(); err != nil {
		message := strings.TrimPrefix(lineOf.ReplaceAllString(err.Error(), ""), "dns: ")
		if origin == "" {
			message += ": every name in these records must be absolute, ending in a dot"
		}
		return nil, errors.New(message)
	}
	if len(records) != 1 {
		return nil, errors.New("not one record")
	}
	rr := records[0]
	h := rr.Header()
	if h.Class != dns.ClassINET {
		return nil, fmt.Errorf("class %s isn't supported: only IN", dns.ClassToString[h.Class])
	}
	// The parser takes a type with no data, as "printer A", for a record of updates.
	if strings.TrimSpace(strings.TrimPrefix(rr.String(), h.String())) == "" {
		return nil, fmt.Errorf("a %s record with no data", dns.TypeToString[h.Rrtype])
	}
	switch h.Rrtype {
	case dns.TypeSOA:
		return nil, errors.New("SOA records aren't allowed: the resolver makes its zones' own")
	case dns.TypeOPT, dns.TypeTSIG, dns.TypeTKEY, dns.TypeIXFR, dns.TypeAXFR, dns.TypeANY:
		return nil, fmt.Errorf("%s records belong to DNS messages, not to names", dns.TypeToString[h.Rrtype])
	}
	h.Name = strings.ToLower(h.Name)
	return rr, nil
}

// Name is the absolute name, in lower case, of hostname in zone, as the providers spell an
// endpoint's name: "" is the zone, a name that ends in the zone is that name, any other is under
// it. "*.x" is a wildcard.
func Name(hostname, zone string) string {
	hostname = strings.ToLower(strings.Trim(hostname, "."))
	zone = strings.ToLower(strings.Trim(zone, "."))
	switch {
	case hostname == "":
		return dns.Fqdn(zone)
	case zone == "":
		return dns.Fqdn(hostname)
	case hostname == zone || strings.HasSuffix(hostname, "."+zone):
		return dns.Fqdn(hostname)
	}
	return dns.Fqdn(hostname + "." + zone)
}

// InZone tells whether name, absolute, is zone or under it.
func InZone(name, zone string) bool {
	return dns.IsSubDomain(dns.Fqdn(zone), name)
}
