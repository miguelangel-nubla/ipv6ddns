package ddns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/duration"
	"github.com/miguelangel-nubla/ipv6disc"
)

// Gandi is Gandi's LiveDNS, through its API: a domain of the account, whose names' A and AAAA
// records are each a set, written whole. See docs/reference/providers.md.
type Gandi struct {
	Token string            `json:"token"`
	Zone  string            `json:"zone"`
	TTL   duration.Duration `json:"ttl"`

	// The API's address, for tests: empty is Gandi's.
	apiBaseURL string

	mutex    sync.Mutex
	warnings []string
	warned   bool
}

// gandiAPI is Gandi's LiveDNS API.
const gandiAPI = "https://api.gandi.net/v5/livedns"

// The TTL of the records without one in the settings, Gandi's own, and the least it takes.
const (
	gandiDefaultTTL = 10800
	gandiMinimumTTL = 300
)

// gandiRRset is a set of records of a name and a type, as the API has them.
type gandiRRset struct {
	Name   string   `json:"rrset_name,omitempty"`
	Type   string   `json:"rrset_type,omitempty"`
	TTL    int      `json:"rrset_ttl"`
	Values []string `json:"rrset_values"`
}

func init() {
	RegisterProvider("gandi", NewGandi)
	RegisterTXT("gandi")
}

func NewGandi(settings json.RawMessage) (Service, error) {
	var service Gandi
	if err := decodeSettings(settings, "gandi", &service); err != nil {
		return nil, err
	}
	service.Zone = strings.ToLower(strings.Trim(service.Zone, "."))
	return &service, nil
}

func (g *Gandi) Domain(hostname string) string { return FQDN(hostname, g.Zone) }

func (g *Gandi) FullName(hostname string) (string, error) { return g.Domain(hostname), nil }

// Warnings are the TTL raised to Gandi's least, said once.
func (g *Gandi) Warnings() []string {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	w := g.warnings
	g.warnings = nil
	return w
}

// ttl is the records' TTL: the settings', Gandi's own without one, and Gandi's least when the
// settings' is lower, which it refuses, as said once.
func (g *Gandi) ttl() int {
	want := int(g.TTL.Seconds())
	switch {
	case want == 0:
		return gandiDefaultTTL
	case want < gandiMinimumTTL:
		g.mutex.Lock()
		if !g.warned {
			g.warned = true
			g.warnings = append(g.warnings, fmt.Sprintf("the ttl %s is below the least Gandi takes, %ds: the records have that one", g.TTL.Duration, gandiMinimumTTL))
		}
		g.mutex.Unlock()
		return gandiMinimumTTL
	}
	return want
}

// call asks the API path of the domain, with body as JSON, and reads its answer into out: false
// for a 404, of a set that isn't there. A request refused for coming too often, 429, is asked
// again a second later, while ctx lasts.
func (g *Gandi) call(ctx context.Context, method, path string, body, out any) (bool, error) {
	base := g.apiBaseURL
	if base == "" {
		base = gandiAPI
	}
	var data []byte
	if body != nil {
		var err error
		if data, err = json.Marshal(body); err != nil {
			return false, err
		}
	}
	client := newHTTPClient(nil)
	for {
		req, err := http.NewRequestWithContext(ctx, method, base+"/domains/"+url.PathEscape(g.Zone)+path, bytes.NewReader(data))
		if err != nil {
			return false, err
		}
		req.Header.Set("Authorization", "Bearer "+g.Token)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := client.Do(req)
		if err != nil {
			return false, err
		}
		answer, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		switch {
		// Refused, and so not applied: asked again, a request that makes a record makes one.
		case resp.StatusCode == http.StatusTooManyRequests:
			select {
			case <-ctx.Done():
				return false, fmt.Errorf("HTTP 429: Gandi refuses requests that come too often, past the update's time")
			case <-time.After(time.Second):
			}
			continue
		case resp.StatusCode == http.StatusNotFound && method == http.MethodGet && strings.HasPrefix(path, "/records/"):
			return false, nil
		case resp.StatusCode >= 300:
			var e struct {
				Message string `json:"message"`
				Cause   string `json:"cause"`
			}
			said := strings.TrimSpace(string(answer))
			if json.Unmarshal(answer, &e) == nil && e.Message != "" {
				said = e.Message
				if e.Cause != "" && e.Cause != e.Message {
					said = e.Cause + ": " + said
				}
			}
			switch resp.StatusCode {
			case http.StatusUnauthorized, http.StatusForbidden:
				return false, fmt.Errorf("HTTP %d: the token is refused, which must manage the domain's technical configuration: %s", resp.StatusCode, said)
			case http.StatusNotFound:
				return false, fmt.Errorf("HTTP 404: the domain %s isn't one of the account's, at LiveDNS: %s", g.Zone, said)
			}
			return false, fmt.Errorf("HTTP %d: %s", resp.StatusCode, said)
		}
		if out != nil && len(answer) > 0 {
			if err := json.Unmarshal(answer, out); err != nil {
				return false, fmt.Errorf("not an answer of Gandi's API: %w", err)
			}
		}
		return true, nil
	}
}

// set makes the set of the name and type the values, of ttl: written whole, or deleted for none.
// same tells two values apart, as Gandi gives them.
func (g *Gandi) set(ctx context.Context, sub, rrType string, values []string, ttl int, same func(a, b string) bool) error {
	path := "/records/" + url.PathEscape(sub) + "/" + rrType
	var have gandiRRset
	exists, err := g.call(ctx, http.MethodGet, path, nil, &have)
	if err != nil {
		return err
	}
	switch {
	case !exists && len(values) == 0:
		return nil
	case len(values) == 0:
		_, err := g.call(ctx, http.MethodDelete, path, nil, nil)
		return err
	case exists && have.TTL == ttl && sameValues(have.Values, values, same):
		return nil
	}
	_, err = g.call(ctx, http.MethodPut, path, gandiRRset{TTL: ttl, Values: slices.Clone(values)}, nil)
	return err
}

// subname is the name of a name of the zone, relative to it, @ for the zone itself.
func (g *Gandi) subname(hostname string) (string, string, error) {
	fqdn := FQDN(hostname, g.Zone)
	if !inZone(fqdn, g.Zone) {
		return "", "", fmt.Errorf("%s is not of the zone %s", fqdn, g.Zone)
	}
	sub := strings.ToLower(RelativeName(fqdn, g.Zone))
	if sub == "" {
		sub = "@"
	}
	return fqdn, sub, nil
}

// Update makes the A and AAAA sets of the name the addresses; its other sets stay.
func (g *Gandi) Update(hostname string, addresses *ipv6disc.AddrCollection) error {
	ctx, cancel := context.WithTimeout(context.Background(), updateTimeout)
	defer cancel()
	fqdn, sub, err := g.subname(hostname)
	if err != nil {
		return err
	}
	desired := map[string][]string{}
	for ip, recordType := range desiredRecords(addresses) {
		desired[recordType] = append(desired[recordType], ip)
	}
	ttl := g.ttl()
	for _, recordType := range []string{"A", "AAAA"} {
		if err := g.set(ctx, sub, recordType, desired[recordType], ttl, sameAddress); err != nil {
			return fmt.Errorf("writing the %s records of %s: %w", recordType, fqdn, err)
		}
	}
	return nil
}

// SetTXT makes the TXT set of the name the values, none removing it, of Gandi's least TTL: its
// other sets stay.
func (g *Gandi) SetTXT(hostname string, values []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), updateTimeout)
	defer cancel()
	fqdn, sub, err := g.subname(hostname)
	if err != nil {
		return err
	}
	var quoted []string
	for _, v := range values {
		quoted = append(quoted, quoteTXT(v))
	}
	if err := g.set(ctx, sub, "TXT", quoted, gandiMinimumTTL, func(a, b string) bool { return a == b }); err != nil {
		return fmt.Errorf("writing the TXT records of %s: %w", fqdn, err)
	}
	return nil
}
