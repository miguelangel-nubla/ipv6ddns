package resolver

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// The answers to a name blocked: no such name, or an address that is none.
const (
	BlockNXDomain = "nxdomain"
	BlockNull     = "null"
)

// Block is what a resolver answers as blocked: the names of its lists, but those of Allow.
type Block struct {
	// The lists, by name, and each list's names, in the same order: Lists of the configuration,
	// Sets of the worker, which downloads them.
	Lists []string
	Sets  []Blocklist
	// The names never blocked, with every name below them: absolute, in lower case.
	Allow []string
	// BlockNXDomain, NXDOMAIN; or BlockNull, 0.0.0.0 and :: of A and AAAA, and no data of another
	// type.
	Answer string
	// Of the answer, and of its SOA, which tells the clients how long to keep a NXDOMAIN.
	TTL time.Duration
}

// Blocklist is the names of a list: Match tells the name it has that blocks name, of any case and
// with a final dot or not, which is it or a parent.
type Blocklist interface {
	Match(name string) (string, bool)
}

// DefaultBlockTTL is the TTL of a blocked answer that gives none: a name unblocked, of a list
// changed or of allow, is answered a minute later, as a record of the resolver's is.
const DefaultBlockTTL = DefaultTTL

// MaxBlockTTL is the longest TTL of a blocked answer: a name unblocked is answered a day later at
// most.
const MaxBlockTTL = 24 * time.Hour

// checkBlock tells what is wrong with a resolver's block.
func checkBlock(cfg Config) error {
	b := cfg.Block
	if b == nil {
		return nil
	}
	if len(b.Sets) != len(b.Lists) {
		return fmt.Errorf("%s.block: %d lists, and %d of their names", cfg.Path, len(b.Lists), len(b.Sets))
	}
	if b.Answer != "" && b.Answer != BlockNXDomain && b.Answer != BlockNull {
		return fmt.Errorf("%s.block.answer: %q: use nxdomain or null", cfg.Path, b.Answer)
	}
	return nil
}

// blocked tells, of a name the resolver would forward, the list that blocks it: none for a name of
// allow, or under resolver.arpa, which tells the clients of the resolver itself.
func (s *Server) blocked(name string) (string, bool) {
	b := s.config.Block
	if b == nil || len(b.Sets) == 0 {
		return "", false
	}
	name = strings.ToLower(dns.Fqdn(name))
	if dns.IsSubDomain("resolver.arpa.", name) {
		return "", false
	}
	for _, a := range b.Allow {
		if dns.IsSubDomain(a, name) {
			return "", false
		}
	}
	for i, set := range b.Sets {
		if _, ok := set.Match(name); ok {
			return b.Lists[i], true
		}
	}
	return "", false
}

// blockTTL is the TTL of the blocked answers, in seconds.
func (s *Server) blockTTL() uint32 {
	if ttl := s.config.Block.TTL; ttl > 0 {
		return uint32(ttl.Seconds())
	}
	return uint32(DefaultBlockTTL.Seconds())
}

// answerBlocked makes resp the answer to a name blocked, of type qtype: NXDOMAIN, or 0.0.0.0 and
// :: as BlockNull has it, with an SOA of the name itself for no data and no such name, which
// tells the clients the TTL.
func (s *Server) answerBlocked(resp *dns.Msg, name string, qtype uint16) {
	ttl := s.blockTTL()
	header := func(rrtype uint16) dns.RR_Header {
		return dns.RR_Header{Name: name, Rrtype: rrtype, Class: dns.ClassINET, Ttl: ttl}
	}
	if s.config.Block.Answer == BlockNull {
		switch qtype {
		case dns.TypeA:
			resp.Answer = append(resp.Answer, &dns.A{Hdr: header(dns.TypeA), A: make([]byte, 4)})
			return
		case dns.TypeAAAA:
			resp.Answer = append(resp.Answer, &dns.AAAA{Hdr: header(dns.TypeAAAA), AAAA: make([]byte, 16)})
			return
		}
	} else {
		resp.Rcode = dns.RcodeNameError
	}
	apex := soa(strings.ToLower(dns.Fqdn(name)))
	apex.Hdr.Ttl, apex.Minttl = ttl, ttl
	resp.Ns = append(resp.Ns, apex)
}

// BlockStatus is a resolver's block, for the report and /status.json.
type BlockStatus struct {
	Lists []string `json:"lists"`
	Allow []string `json:"allow"`
	// nxdomain or null.
	Answer string `json:"answer"`
	// In seconds.
	TTL int `json:"ttl"`
}

// blockStatus is the resolver's block: nil without.
func (s *Server) blockStatus() *BlockStatus {
	b := s.config.Block
	if b == nil {
		return nil
	}
	status := &BlockStatus{Lists: append([]string{}, b.Lists...), Allow: []string{}, Answer: b.Answer, TTL: int(s.blockTTL())}
	if status.Answer == "" {
		status.Answer = BlockNXDomain
	}
	for _, a := range b.Allow {
		status.Allow = append(status.Allow, strings.TrimSuffix(a, "."))
	}
	return status
}
