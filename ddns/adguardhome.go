package ddns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/miguelangel-nubla/ipv6disc"
)

// AdGuardHome keeps the addresses of a name as DNS rewrites of AdGuard Home, through its API. A
// rewrite is a domain and one answer: a name with several addresses has one rewrite for each.
type AdGuardHome struct {
	Address        string `json:"address"`
	TLSFingerprint string `json:"tls_fingerprint"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	Zone           string `json:"zone"`
}

func init() {
	RegisterProvider("adguardhome", NewAdGuardHome)
}

func NewAdGuardHome(settings json.RawMessage) (Service, error) {
	var service AdGuardHome
	if err := decodeSettings(settings, "adguardhome", &service); err != nil {
		return nil, err
	}
	return &service, nil
}

// adGuardRewrite is a rewrite as the API lists it. Enabled is missing from the versions before
// v0.107.68, where every rewrite is.
type adGuardRewrite struct {
	Domain  string `json:"domain"`
	Answer  string `json:"answer"`
	Enabled *bool  `json:"enabled,omitempty"`
}

func (a *AdGuardHome) Update(hostname string, addrCollection *ipv6disc.AddrCollection) error {
	client := newHTTPClient(verifiedOrPinnedTLSConfig(urlHost(a.Address), a.TLSFingerprint))
	fqdn := a.Domain(hostname)

	var rewrites []adGuardRewrite
	if err := a.call(client, http.MethodGet, "list", nil, &rewrites); err != nil {
		return fmt.Errorf("failed to list the rewrites: %w", err)
	}

	desired := desiredRecords(addrCollection)

	// The rewrites of the name whose answer is an address, by the address. One with another
	// answer, a CNAME or the words A and AAAA, is the user's own, and so is a disabled one: its
	// address stays as it is, and gets no rewrite beside it.
	current := make(map[string][]adGuardRewrite)
	disabled := make(map[string]bool)
	for _, rewrite := range rewrites {
		if lowerASCII(strings.Trim(rewrite.Domain, ".")) != fqdn {
			continue
		}
		ip, ok := canonicalIP(rewrite.Answer)
		if !ok {
			continue
		}
		if rewrite.Enabled != nil && !*rewrite.Enabled {
			disabled[ip] = true
			continue
		}
		current[ip] = append(current[ip], rewrite)
	}

	for ip, entries := range current {
		_, wanted := desired[ip]
		// A delete takes every rewrite with the domain and the answer as they are written: one
		// address written in two ways is two.
		written := make(map[adGuardRewrite]bool)
		for _, entry := range entries {
			written[adGuardRewrite{Domain: entry.Domain, Answer: entry.Answer}] = true
		}
		if wanted && len(entries) == 1 {
			continue
		}
		for entry := range written {
			if err := a.call(client, http.MethodPost, "delete", entry, nil); err != nil {
				return fmt.Errorf("failed to delete the rewrite of %s to %s: %w", fqdn, ip, err)
			}
		}
		// Said more than once, it was deleted whole: it is added again, once.
		delete(current, ip)
	}

	for ip := range desired {
		if _, exists := current[ip]; exists || disabled[ip] {
			continue
		}
		if err := a.call(client, http.MethodPost, "add", adGuardRewrite{Domain: fqdn, Answer: ip}, nil); err != nil {
			return fmt.Errorf("failed to add the rewrite of %s to %s: %w", fqdn, ip, err)
		}
	}
	return nil
}

// call asks the rewrites API for action, with body when there is one, and reads its answer into
// out when there is where to. An answer that refuses is an error with its status and what
// AdGuard Home says, which for a password refused too often is for how long.
func (a *AdGuardHome) call(client *http.Client, method, action string, body, out any) error {
	u, err := url.Parse(a.Address)
	if err != nil {
		return err
	}
	u.Path, _ = url.JoinPath(u.Path, "/control/rewrite/"+action)

	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequest(method, u.String(), reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if a.Username != "" || a.Password != "" {
		req.SetBasicAuth(a.Username, a.Password)
	}
	resp, err := client.Do(req)
	if err != nil {
		return withoutURL(err)
	}
	defer resp.Body.Close()

	answer, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("HTTP %s: reading the answer: %w", resp.Status, err)
	}
	if resp.StatusCode != http.StatusOK {
		said := strings.TrimSpace(string(answer))
		switch {
		case resp.StatusCode == http.StatusUnauthorized && a.Username == "" && a.Password == "":
			return fmt.Errorf("HTTP %s: AdGuard Home asks for a user: give username and password", resp.Status)
		case resp.StatusCode == http.StatusUnauthorized:
			return fmt.Errorf("HTTP %s: the username or the password is refused. AdGuard Home blocks an address that fails several times, for 15 minutes by default", resp.Status)
		case said == "" || strings.HasPrefix(said, "<"):
			return fmt.Errorf("HTTP %s: not an answer of AdGuard Home's API", resp.Status)
		}
		if len(said) > 200 {
			said = said[:200]
		}
		return fmt.Errorf("HTTP %s: %s", resp.Status, said)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(answer, out); err != nil {
		return fmt.Errorf("HTTP %s: not an answer of AdGuard Home's API: %w", resp.Status, err)
	}
	return nil
}

// Domain is the name as AdGuard Home keeps it: in lower case, without the final dot.
func (a *AdGuardHome) Domain(hostname string) string {
	return lowerASCII(FQDN(hostname, a.Zone))
}
