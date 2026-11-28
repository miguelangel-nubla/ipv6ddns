package config

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/blocklist"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/duration"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/resolver"
)

// Blocklist is a list of names that resolvers answer as blocked, downloaded at an interval, and
// kept in the state folder. See docs/resolver.md.
type Blocklist struct {
	// Required. Where it is downloaded from: http:// or https://.
	URL string `json:"url,omitempty"`
	// How often it is downloaded again. Default: blocklist.DefaultInterval; blocklist.MinInterval
	// at least.
	Interval *duration.Duration `json:"interval,omitempty"`
}

// Block is what a resolver answers as blocked, of the names it would forward.
type Block struct {
	// Required. The blocklists, by name.
	Lists StringList `json:"lists,omitempty"`
	// The names never blocked, with every name below them.
	Allow StringList `json:"allow,omitempty"`
	// nxdomain, the default, or null.
	Answer string `json:"answer,omitempty"`
	// Of the blocked answers. Default: resolver.DefaultBlockTTL.
	TTL *duration.Duration `json:"ttl,omitempty"`
}

// blocklistName is a blocklist's name, which its file in the state folder has.
var blocklistName = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// checkBlocks tells, of a configuration not yet checked by the schema, that a resolver's block is
// to name its lists: in words, where the schema would only say that a key is missing.
func checkBlocks(configData []byte) error {
	var c struct {
		Resolvers map[string]struct {
			Block map[string]json.RawMessage `json:"block"`
		} `json:"resolvers"`
	}
	if json.Unmarshal(configData, &c) != nil {
		return nil
	}
	for _, name := range slices.Sorted(maps.Keys(c.Resolvers)) {
		if b := c.Resolvers[name].Block; b != nil {
			if _, ok := b["lists"]; !ok {
				return fmt.Errorf("resolvers.%s.block.lists is missing: give the blocklists whose names the resolver answers as blocked, by their names under blocklists, as\n\nblocklists:\n  pro:\n    url: https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro-onlydomains.txt\nresolvers:\n  %s:\n    block:\n      lists:\n        - pro", name, name)
			}
		}
	}
	return nil
}

// setUpBlocklists checks the blocklists, and warns of those no resolver blocks the names of.
func (c *Config) setUpBlocklists() error {
	used := map[string]bool{}
	for _, r := range c.Resolvers {
		if r.Block != nil {
			for _, l := range r.Block.Lists {
				used[l] = true
			}
		}
	}
	files := map[string]string{}
	for _, name := range slices.Sorted(maps.Keys(c.Blocklists)) {
		path := "blocklists." + name
		if !blocklistName.MatchString(name) {
			return fmt.Errorf("blocklists: the name %q is that of its file in state_dir: use letters, digits, - and _ alone, as hagezi_pro", name)
		}
		// The file's name, without its case, which some file systems don't tell apart.
		if other, ok := files[strings.ToLower(name)]; ok {
			return fmt.Errorf("blocklists: the names %s and %s differ by their case alone, and each is that of its file in state_dir, which would be one where the file system doesn't tell them apart: give one of them another name", other, name)
		}
		files[strings.ToLower(name)] = name
		l := c.Blocklists[name]
		u, err := url.Parse(l.URL)
		switch {
		case l.URL == "":
			return fmt.Errorf("%s.url is missing: give where the list is downloaded from, as https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro-onlydomains.txt", path)
		case err != nil || u.Scheme != "http" && u.Scheme != "https" || u.Host == "":
			return fmt.Errorf("%s.url: %q is not a URL of http:// or https://, as https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro-onlydomains.txt", path, l.URL)
		}
		if l.Interval != nil && l.Interval.Duration < blocklist.MinInterval {
			return fmt.Errorf("%s.interval: %s is too short: the least is %s, as a list's server would refuse more, and lists change daily", path, l.Interval.Duration, blocklist.MinInterval)
		}
		if !used[name] {
			c.Warnings = append(c.Warnings, fmt.Sprintf("%s: no resolver's block names it, so it is never downloaded: name it in a resolver's block.lists, or remove it", path))
		}
	}
	return nil
}

// IntervalOf is the interval of the blocklist: its own, or the default.
func (l Blocklist) IntervalOf() duration.Duration {
	if l.Interval != nil {
		return *l.Interval
	}
	return duration.Duration{Duration: blocklist.DefaultInterval}
}

// setUpBlock reads the block of a resolver, at path, into spec: its lists, which the worker gives
// their names, its allow, its answer and its TTL.
func (c *Config) setUpBlock(path string, r Resolver, spec *resolver.Config) error {
	if r.Block == nil {
		return nil
	}
	path += ".block"
	names := slices.Sorted(maps.Keys(c.Blocklists))
	b := &resolver.Block{Answer: r.Block.Answer, TTL: resolver.DefaultBlockTTL}
	if b.Answer == "" {
		b.Answer = resolver.BlockNXDomain
	}
	if r.Block.TTL != nil {
		b.TTL = r.Block.TTL.Duration
		// Of whole seconds, as a TTL is: under one is 0, which the clients keep not at all.
		if b.TTL < time.Second || b.TTL > resolver.MaxBlockTTL {
			return fmt.Errorf("%s.ttl: %s is not a TTL of the blocked answers: give one of 1s to %s, as 1m, the default", path, b.TTL, resolver.MaxBlockTTL)
		}
	}
	if len(r.Block.Lists) == 0 {
		return fmt.Errorf("%s.lists is empty: give the blocklists whose names the resolver answers as blocked, by their names under blocklists", path)
	}
	for i, l := range r.Block.Lists {
		if slices.Contains(r.Block.Lists[:i], l) {
			return fmt.Errorf("%s.lists: %s is given twice: give each blocklist once", path, l)
		}
		if _, ok := c.Blocklists[l]; !ok {
			if len(names) == 0 {
				return fmt.Errorf("%s.lists: there's no blocklist %s: blocklists is empty. Add it, as\n\nblocklists:\n  %s:\n    url: https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro-onlydomains.txt", path, l, l)
			}
			return fmt.Errorf("%s.lists: there's no blocklist %s: the blocklists are %s", path, l, strings.Join(names, ", "))
		}
		b.Lists = append(b.Lists, l)
	}
	for _, a := range r.Block.Allow {
		n := blocklist.Normalize(strings.TrimPrefix(a, "*."))
		if !blocklist.ValidName(n) {
			return fmt.Errorf("%s.allow: %q is not a name, as school.example.com, which is answered with every name below it. A name of other letters is given in punycode, as xn--bcher-kva.example", path, a)
		}
		b.Allow = append(b.Allow, dns.Fqdn(n))
	}
	spec.Block = b
	return nil
}
