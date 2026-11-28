package config

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/blocklist"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/resolver"
)

// blockConfig is resolverConfig of lan with block, and blocklists, in YAML.
func blockConfig(t *testing.T, block, blocklists string) (Config, error) {
	t.Helper()
	return resolverConfig(t, lanResolver+"\n    block:"+block, homeCredential, nasTask+"\nblocklists:"+blocklists)
}

const proList = `
  pro:
    url: https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro-onlydomains.txt`

func TestBlock(t *testing.T) {
	c, err := blockConfig(t, `
      lists:
        - pro
      allow:
        - School.Example.com.
        - "*.games.example"
      answer: "null"
      ttl: 30s`, proList+`
    interval: 6h
  tif:
    url: http://lists.example/tif.txt`)
	if err != nil {
		t.Fatal(err)
	}
	b := c.Resolvers["lan"].Spec.Block
	if b == nil || !slices.Equal(b.Lists, []string{"pro"}) || !slices.Equal(b.Allow, []string{"school.example.com.", "games.example."}) || b.Answer != resolver.BlockNull || b.TTL != 30*time.Second {
		t.Errorf("block %+v", b)
	}
	if got := c.Blocklists["pro"].IntervalOf().Duration; got != 6*time.Hour {
		t.Errorf("interval %s", got)
	}
	if got := c.Blocklists["tif"].IntervalOf().Duration; got != blocklist.DefaultInterval {
		t.Errorf("default interval %s", got)
	}
	// tif is of no resolver.
	if !slices.ContainsFunc(c.Warnings, func(w string) bool { return strings.HasPrefix(w, "blocklists.tif: no resolver's block names it") }) {
		t.Errorf("warnings %q", c.Warnings)
	}

	c, err = blockConfig(t, "\n      lists: pro", proList)
	if err != nil {
		t.Fatal(err)
	}
	if b := c.Resolvers["lan"].Spec.Block; b.Answer != resolver.BlockNXDomain || b.TTL != resolver.DefaultBlockTTL {
		t.Errorf("defaults %+v", b)
	}
	if len(c.Warnings) != 0 {
		t.Errorf("warnings %q", c.Warnings)
	}
}

func TestBlockErrors(t *testing.T) {
	for _, c := range []struct {
		block, blocklists, want string
	}{
		{"\n      allow: a.example", proList, "resolvers.lan.block.lists is missing: give the blocklists"},
		{"\n      lists: pr", proList, "resolvers.lan.block.lists: there's no blocklist pr: the blocklists are pro"},
		{"\n      lists: pro", " {}", "resolvers.lan.block.lists: there's no blocklist pro: blocklists is empty. Add it, as\n\nblocklists:\n  pro:\n    url: https://"},
		{"\n      lists:\n        - pro\n        - pro", proList, "resolvers.lan.block.lists: pro is given twice"},
		{"\n      lists: []", proList, "resolvers.lan.block.lists is empty"},
		{"\n      lists: pro\n      allow: school example", proList, `resolvers.lan.block.allow: "school example" is not a name, as school.example.com`},
		{"\n      lists: pro\n      allow: bücher.example", proList, `resolvers.lan.block.allow: "bücher.example" is not a name`},
		{"\n      lists: pro\n      answer: refused", proList, "answer"},
		{"\n      lists: pro", "\n  pro:\n    url: ftp://lists.example/pro.txt", `blocklists.pro.url: "ftp://lists.example/pro.txt" is not a URL of http:// or https://`},
		{"\n      lists: pro", "\n  pro:\n    url: lists.example/pro.txt", `blocklists.pro.url: "lists.example/pro.txt" is not a URL`},
		{"\n      lists: pro", "\n  pro:\n    interval: 2h", "url"},
		{"\n      lists: pro\n      ttl: 0s", proList, "resolvers.lan.block.ttl: 0s is not a TTL of the blocked answers: give one of 1s to 24h0m0s"},
		{"\n      lists: pro\n      ttl: 500ms", proList, "resolvers.lan.block.ttl: 500ms is not a TTL"},
		{"\n      lists: pro\n      ttl: 48h", proList, "resolvers.lan.block.ttl: 48h0m0s is not a TTL"},
		{"\n      lists: pro", proList + "\n    interval: 10m", "blocklists.pro.interval: 10m0s is too short: the least is 1h0m0s"},
		{"\n      lists: pro", proList + "\n  hagezi/pro:\n    url: https://lists.example/pro.txt", `blocklists: the name "hagezi/pro" is that of its file in state_dir`},
		{"\n      lists: pro", proList + "\n  Pro:\n    url: https://lists.example/pro.txt", "blocklists: the names Pro and pro differ by their case alone, and each is that of its file in state_dir, which would be one where the file system doesn't tell them apart: give one of them another name"},
	} {
		_, err := blockConfig(t, c.block, c.blocklists)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q, %q: %v; want %q", c.block, c.blocklists, err, c.want)
		}
	}
}

func TestBlockPrinted(t *testing.T) {
	c, err := blockConfig(t, "\n      lists: pro\n      allow: school.example.com", "\n  pro:\n    url: https://lists.example/pro.txt?token=secret")
	if err != nil {
		t.Fatal(err)
	}
	shown := c.PrettyPrint("", true)
	for _, want := range []string{
		"            Block:\n                Lists: pro\n                Allow: school.example.com\n                Answer: nxdomain\n",
		"    Blocklists:\n        pro:\n            URL: https://lists.example/pro.txt?" + hidden + "\n            Interval: 24h0m0s\n",
	} {
		if !strings.Contains(shown, want) {
			t.Errorf("no %q in\n%s", want, shown)
		}
	}
	if strings.Contains(shown, "secret") {
		t.Error("the token is shown")
	}
}
