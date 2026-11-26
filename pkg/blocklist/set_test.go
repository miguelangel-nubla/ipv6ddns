package blocklist

import (
	"fmt"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestParseLine(t *testing.T) {
	for _, c := range []struct {
		line  string
		names []string
		ok    bool
	}{
		{"ads.example.com", []string{"ads.example.com"}, true},
		{"  Ads.Example.COM.  ", []string{"ads.example.com"}, true},
		{"xn--bcher-kva.example", []string{"xn--bcher-kva.example"}, true},
		{"_dmarc.example.com", []string{"_dmarc.example.com"}, true},
		{"", nil, true},
		{"   ", nil, true},
		{"# a comment", nil, true},
		{"! an adblock comment", nil, true},
		{"[Adblock Plus 2.0]", nil, true},
		{"ads.example.com # a comment", []string{"ads.example.com"}, true},
		{"0.0.0.0 ads.example.com", []string{"ads.example.com"}, true},
		{"127.0.0.1\tads.example.com\ttrack.example.com", []string{"ads.example.com", "track.example.com"}, true},
		{":: ads.example.com", []string{"ads.example.com"}, true},
		{"127.0.0.1 localhost", nil, true},
		{"0.0.0.0 0.0.0.0", nil, true},
		{"||ads.example.com^", []string{"ads.example.com"}, true},
		{"*.ads.example.com", []string{"ads.example.com"}, true},
		{"||ads.example.com^$third-party", nil, false},
		{"||example.com/ads^", nil, false},
		{"@@||example.com^", nil, false},
		{"example.com##.ad", nil, false},
		{"/ads/", nil, false},
		{"bücher.example", nil, false},
		{"ads example com", nil, false},
		{"192.0.2.1", nil, false},
		{"a..b", nil, false},
		{strings.Repeat("a", 64) + ".example", nil, false},
	} {
		names, ok := parseLine(c.line)
		if !slices.Equal(names, c.names) || ok != c.ok {
			t.Errorf("%q: %q, %v; want %q, %v", c.line, names, ok, c.names, c.ok)
		}
	}
}

func TestParse(t *testing.T) {
	list := "# hagezi\nads.example.com\ntrack.example.net\nads.example.com\n||ads.example.org^\n0.0.0.0 tv.example\n" +
		"||example.com/x^\n" + strings.Repeat("x", maxLine+10) + "\nlast.example"
	p, err := Parse(strings.NewReader(list))
	if err != nil {
		t.Fatal(err)
	}
	if p.Set.Len() != 5 || p.Unreadable != 2 {
		t.Errorf("%d names, %d unreadable; want 5, 2", p.Set.Len(), p.Unreadable)
	}
	var names []string
	for i := range p.Set.Len() {
		names = append(names, p.Set.name(i))
	}
	if want := []string{"ads.example.com", "ads.example.org", "last.example", "track.example.net", "tv.example"}; !slices.Equal(names, want) {
		t.Errorf("names %q, want %q", names, want)
	}
}

func TestMatch(t *testing.T) {
	p, err := Parse(strings.NewReader("ads.example.com\nxn--bcher-kva.example\ncom.example\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, listed string
	}{
		{"ads.example.com", "ads.example.com"},
		{"ads.example.com.", "ads.example.com"},
		{"ADS.Example.Com.", "ads.example.com"},
		{"x.y.ads.example.com.", "ads.example.com"},
		{"xn--bcher-kva.example.", "xn--bcher-kva.example"},
		{"shop.xn--bcher-kva.example.", "xn--bcher-kva.example"},
		{"example.com.", ""},
		{"notads.example.com.", ""},
		{"ads.example.com.evil.", ""},
		{"com.", ""},
		{".", ""},
		{"", ""},
	} {
		listed, ok := p.Set.Match(c.name)
		if listed != c.listed || ok != (c.listed != "") {
			t.Errorf("%q: %q, %v; want %q", c.name, listed, ok, c.listed)
		}
	}
	var none *Set
	if _, ok := none.Match("ads.example.com"); ok {
		t.Error("a set of none matched")
	}
}

// names is a list of n names, as long as those of hagezi's, about 22 bytes each.
func names(n int) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "host%07d.ads-%03d.example.com\n", i*7919%n, i%1000)
	}
	return b.String()
}

// The memory of a list's names, as the heap has it once the list is read, for 500,000 names and
// for 1.5 million: well under 100 MB.
func TestMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("reads lists of millions of names")
	}
	for _, n := range []int{500_000, 1_500_000} {
		list := names(n)
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		p, err := parse(strings.NewReader(list), int64(len(list)))
		if err != nil {
			t.Fatal(err)
		}
		runtime.GC()
		runtime.ReadMemStats(&after)
		runtime.KeepAlive(list)
		heap := int64(after.HeapAlloc) - int64(before.HeapAlloc)
		read := after.TotalAlloc - before.TotalAlloc
		t.Logf("%d names, of %.1f MiB of text: %.1f MiB of the set, %.1f MiB more of the heap, %.1f MiB allocated while reading", p.Set.Len(), float64(len(list))/(1<<20),
			float64(p.Set.Bytes())/(1<<20), float64(heap)/(1<<20), float64(read)/(1<<20))
		if p.Set.Len() != n {
			t.Errorf("%d names, want %d", p.Set.Len(), n)
		}
		if heap > 100<<20 {
			t.Errorf("%d names take %d bytes", n, heap)
		}
		runtime.KeepAlive(p)
	}
}

func BenchmarkParse(b *testing.B) {
	list := names(500_000)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Parse(strings.NewReader(list)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMatch(b *testing.B) {
	p, err := Parse(strings.NewReader(names(500_000)))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		p.Set.Match("www.cdn.host0123456.ads-007.example.com.")
		p.Set.Match("www.not-listed.example.org.")
	}
}
