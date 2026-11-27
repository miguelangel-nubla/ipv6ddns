// Package blocklist reads the lists of names a resolver answers as blocked, keeps each in memory
// in little space, and keeps it up to date: downloaded at an interval, with a copy on disk that a
// start reads, offline, and that a failed download leaves as it was.
//
// A list is a name per line, as hagezi's wildcard onlydomains lists: a name blocks itself and every
// name below it. Lines of a hosts file, 0.0.0.0 ads.example.com, and the adblock rules of a domain,
// ||ads.example.com^, and *.ads.example.com, are the same. Comments, # and !, and blank lines are
// skipped; any other line is unreadable, and counted.
package blocklist

import (
	"bufio"
	"bytes"
	"io"
	"net/netip"
	"slices"
	"strings"
)

// Set is the names of a list, sorted, each once, in lower case and with no final dot: in one
// string, each ending where ends says, which is four bytes a name beside its text.
type Set struct {
	text string
	ends []uint32
}

// Len is the names of the set.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.ends)
}

// Bytes is the memory the set's names take.
func (s *Set) Bytes() int {
	if s == nil {
		return 0
	}
	return len(s.text) + 4*len(s.ends)
}

// name is the set's i-th name.
func (s *Set) name(i int) string {
	start := uint32(0)
	if i > 0 {
		start = s.ends[i-1]
	}
	return s.text[start:s.ends[i]]
}

// has tells whether the set has name, as it is.
func (s *Set) has(name string) bool {
	lo, hi := 0, len(s.ends)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if s.name(mid) < name {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo < len(s.ends) && s.name(lo) == name
}

// Match tells the name of the set that blocks name, of any case and with a final dot or not: it,
// or the closest of its parents that the set has.
func (s *Set) Match(name string) (string, bool) {
	if s.Len() == 0 {
		return "", false
	}
	name = Normalize(name)
	for name != "" {
		if s.has(name) {
			return name, true
		}
		_, parent, ok := strings.Cut(name, ".")
		if !ok {
			break
		}
		name = parent
	}
	return "", false
}

// Normalize is a name in lower case, with no final dot, as a set has its names.
func Normalize(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// Parsed is what reading a list found: its names, and the lines it couldn't read.
type Parsed struct {
	Set        *Set
	Unreadable int
}

// maxLine is the longest line read: longer, it is unreadable.
const maxLine = 4096

// Parse reads a list, a line at a time.
func Parse(r io.Reader) (Parsed, error) { return parse(r, 0) }

// parse reads a list of size bytes, or about: its names take as much at most, held at once, rather
// than in a buffer that grows twice as large.
func parse(r io.Reader, size int64) (Parsed, error) {
	type span struct{ start, end uint32 }
	var (
		text       = make([]byte, 0, min(max(size, 0), MaxSize))
		spans      []span
		unreadable int
	)
	br := bufio.NewReaderSize(r, maxLine)
	for {
		line, err := br.ReadSlice('\n')
		if err == bufio.ErrBufferFull {
			unreadable++
			// The rest of the line.
			for err == bufio.ErrBufferFull {
				_, err = br.ReadSlice('\n')
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return Parsed{}, err
			}
			continue
		}
		if err != nil && err != io.EOF {
			return Parsed{}, err
		}
		names, ok := parseLine(string(line))
		if !ok {
			unreadable++
		}
		for _, n := range names {
			start := uint32(len(text))
			text = append(text, n...)
			spans = append(spans, span{start, uint32(len(text))})
		}
		if err == io.EOF {
			break
		}
	}
	slices.SortFunc(spans, func(a, b span) int { return bytes.Compare(text[a.start:a.end], text[b.start:b.end]) })
	var b strings.Builder
	b.Grow(len(text))
	ends := make([]uint32, 0, len(spans))
	var last []byte
	for i, sp := range spans {
		n := text[sp.start:sp.end]
		if i > 0 && bytes.Equal(n, last) {
			continue
		}
		b.Write(n)
		ends = append(ends, uint32(b.Len()))
		last = n
	}
	return Parsed{Set: &Set{text: b.String(), ends: slices.Clip(ends)}, Unreadable: unreadable}, nil
}

// hostsOwn are the names a hosts file has of the machine itself, which no list blocks.
var hostsOwn = map[string]bool{
	"localhost": true, "localhost.localdomain": true, "local": true, "broadcasthost": true,
	"ip6-localhost": true, "ip6-loopback": true, "ip6-localnet": true, "ip6-mcastprefix": true,
	"ip6-allnodes": true, "ip6-allrouters": true, "ip6-allhosts": true, "0.0.0.0": true,
}

// parseLine reads a line of a list: the names it blocks, none of a comment or a blank line, and
// whether it could be read.
func parseLine(line string) ([]string, bool) {
	line = strings.TrimSpace(line)
	// A comment after a name, of a hosts file, follows a space: ## is an adblock rule.
	if i := strings.IndexByte(line, '#'); i == 0 {
		return nil, true
	} else if i > 0 && (line[i-1] == ' ' || line[i-1] == '\t') {
		line = strings.TrimSpace(line[:i])
	}
	if line == "" || line[0] == '!' || line[0] == '[' {
		return nil, true
	}
	fields := strings.Fields(line)
	if len(fields) > 1 {
		// A hosts file's: an address, and its names.
		if _, err := netip.ParseAddr(fields[0]); err != nil {
			return nil, false
		}
		var names []string
		for _, f := range fields[1:] {
			n := Normalize(f)
			if hostsOwn[n] {
				continue
			}
			if !ValidName(n) {
				return nil, false
			}
			names = append(names, n)
		}
		return names, true
	}
	n := fields[0]
	switch {
	case strings.HasPrefix(n, "||"):
		// An adblock rule of a domain, of no options: any other is of paths, or of pages.
		n, ok := strings.CutSuffix(n[2:], "^")
		if !ok {
			return nil, false
		}
		return checked(n)
	case strings.HasPrefix(n, "*."):
		return checked(n[2:])
	}
	return checked(n)
}

// checked is a name of a line, when it is one.
func checked(n string) ([]string, bool) {
	n = Normalize(n)
	if !ValidName(n) {
		return nil, false
	}
	return []string{n}, true
}

// ValidName tells whether n, in lower case and with no final dot, is a name a list may block: of
// labels of letters, digits, - and _, 63 bytes at most each, and 253 in all; no address. A name of
// other letters is given in punycode, as xn--bcher-kva.example.
func ValidName(n string) bool {
	if n == "" || len(n) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(n); err == nil {
		return false
	}
	for label := range strings.SplitSeq(n, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
				return false
			}
		}
	}
	return true
}
