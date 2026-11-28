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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/duration"
	"github.com/miguelangel-nubla/ipv6disc"
)

// DeSEC is deSEC's DNS, through its API: a zone of the account, whose names' A and AAAA records
// are each a set, changed together in one request, all or none. See docs/reference/providers.md.
type DeSEC struct {
	Token string            `json:"token"`
	Zone  string            `json:"zone"`
	TTL   duration.Duration `json:"ttl"`

	// The API's address, for tests: empty is deSEC's.
	apiBaseURL string

	mutex sync.Mutex
	// The zone's least TTL, once the API told it.
	minimumTTL int
	warnings   []string
}

// deSECAPI is deSEC's API.
const deSECAPI = "https://desec.io/api/v1"

// deSECRRset is a set of records of a name and a type, as deSEC's API has them: the name relative
// to the zone, "" for the zone itself.
type deSECRRset struct {
	Subname string   `json:"subname"`
	Type    string   `json:"type"`
	TTL     int      `json:"ttl,omitempty"`
	Records []string `json:"records"`
}

func init() {
	RegisterProvider("desec", NewDeSEC)
	RegisterTXT("desec")
}

func NewDeSEC(settings json.RawMessage) (Service, error) {
	var service DeSEC
	if err := decodeSettings(settings, "desec", &service); err != nil {
		return nil, err
	}
	service.Zone = strings.ToLower(strings.Trim(service.Zone, "."))
	return &service, nil
}

func (d *DeSEC) Domain(hostname string) string { return FQDN(hostname, d.Zone) }

func (d *DeSEC) FullName(hostname string) (string, error) { return d.Domain(hostname), nil }

// Warnings are the TTLs raised to the zone's least, each said once.
func (d *DeSEC) Warnings() []string {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	w := d.warnings
	d.warnings = nil
	return w
}

// call asks the API path of the zone, as /rrsets/, with body as JSON, and reads its answer into
// out. A request refused for coming too often, 429, is asked again after the wait the API says,
// while ctx lasts.
func (d *DeSEC) call(ctx context.Context, method, path string, body, out any) error {
	base := d.apiBaseURL
	if base == "" {
		base = deSECAPI
	}
	target := base + "/domains/" + url.PathEscape(d.Zone) + path
	var data []byte
	if body != nil {
		var err error
		if data, err = json.Marshal(body); err != nil {
			return err
		}
	}
	client := newHTTPClient(nil)
	for {
		req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(data))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Token "+d.Token)
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		answer, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		// Refused, and so not applied: asked again, a request that makes a record makes one.
		if resp.StatusCode == http.StatusTooManyRequests {
			wait := time.Second
			if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
				wait = time.Duration(s) * time.Second
			}
			select {
			case <-ctx.Done():
				return fmt.Errorf("HTTP 429: deSEC asks to wait %s, past the update's time", wait)
			case <-time.After(wait):
			}
			continue
		}
		if resp.StatusCode >= 300 {
			return d.refused(resp.StatusCode, answer)
		}
		if out != nil && len(answer) > 0 {
			if err := json.Unmarshal(answer, out); err != nil {
				return fmt.Errorf("not an answer of deSEC's API: %w", err)
			}
		}
		return nil
	}
}

// refused is the error of an answer that refuses, with what deSEC said.
func (d *DeSEC) refused(status int, answer []byte) error {
	said := strings.TrimSpace(string(answer))
	var detail struct {
		Detail string `json:"detail"`
	}
	if json.Unmarshal(answer, &detail) == nil && detail.Detail != "" {
		said = detail.Detail
	}
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("HTTP %d: the token is refused: %s", status, said)
	case http.StatusNotFound:
		return fmt.Errorf("HTTP 404: the zone %s isn't one of the account's: %s", d.Zone, said)
	}
	if len(said) > 300 {
		said = said[:300]
	}
	return fmt.Errorf("HTTP %d: %s", status, said)
}

// ttl is the TTL of the records: the settings', or the zone's least without one; and the least
// when the settings' is lower, which deSEC refuses, as said once in the warnings.
func (d *DeSEC) ttl(ctx context.Context) (int, error) {
	d.mutex.Lock()
	minimum := d.minimumTTL
	d.mutex.Unlock()
	if minimum == 0 {
		var domain struct {
			MinimumTTL int `json:"minimum_ttl"`
		}
		if err := d.call(ctx, http.MethodGet, "/", nil, &domain); err != nil {
			return 0, err
		}
		minimum = max(domain.MinimumTTL, 1)
		d.mutex.Lock()
		d.minimumTTL = minimum
		d.mutex.Unlock()
	}
	d.mutex.Lock()
	want := int(d.TTL.Seconds())
	d.mutex.Unlock()
	switch {
	case want == 0:
		return minimum, nil
	case want < minimum:
		d.mutex.Lock()
		d.warnings = append(d.warnings, fmt.Sprintf("the ttl %s is below the least deSEC allows the zone %s, %ds: the records have that one", d.TTL.Duration, d.Zone, minimum))
		d.TTL.Duration = time.Duration(minimum) * time.Second
		d.mutex.Unlock()
		return minimum, nil
	}
	return want, nil
}

// rrsets are the sets of records of a name, by type.
func (d *DeSEC) rrsets(ctx context.Context, subname string) (map[string]deSECRRset, error) {
	var sets []deSECRRset
	if err := d.call(ctx, http.MethodGet, "/rrsets/?subname="+url.QueryEscape(subname), nil, &sets); err != nil {
		return nil, err
	}
	out := make(map[string]deSECRRset)
	for _, s := range sets {
		if s.Subname == subname {
			out[s.Type] = s
		}
	}
	return out, nil
}

// Update makes the A and AAAA sets of the name the addresses, in one request: deSEC applies it
// whole or not at all, and serves it from its name servers within seconds. The name's other
// sets stay.
func (d *DeSEC) Update(hostname string, addresses *ipv6disc.AddrCollection) error {
	ctx, cancel := context.WithTimeout(context.Background(), updateTimeout)
	defer cancel()
	fqdn := FQDN(hostname, d.Zone)
	if !inZone(fqdn, d.Zone) {
		return fmt.Errorf("%s is not of the zone %s", fqdn, d.Zone)
	}
	subname := strings.ToLower(RelativeName(fqdn, d.Zone))
	ttl, err := d.ttl(ctx)
	if err != nil {
		return err
	}
	current, err := d.rrsets(ctx, subname)
	if err != nil {
		return fmt.Errorf("reading the records of %s: %w", fqdn, err)
	}
	desired := map[string][]string{"A": nil, "AAAA": nil}
	for ip, recordType := range desiredRecords(addresses) {
		desired[recordType] = append(desired[recordType], ip)
	}
	var changes []deSECRRset
	for _, recordType := range []string{"A", "AAAA"} {
		want := desired[recordType]
		slices.Sort(want)
		have := current[recordType]
		var got []string
		for _, r := range have.Records {
			ip, ok := canonicalIP(r)
			if !ok {
				return fmt.Errorf("a %s record of %s at deSEC isn't an address: %s", recordType, fqdn, r)
			}
			got = append(got, ip)
		}
		slices.Sort(got)
		got = slices.Compact(got)
		if slices.Equal(got, want) && (len(want) == 0 || have.TTL == ttl) {
			continue
		}
		if want == nil {
			want = []string{}
		}
		changes = append(changes, deSECRRset{Subname: subname, Type: recordType, TTL: ttl, Records: want})
	}
	if len(changes) == 0 {
		return nil
	}
	if err := d.call(ctx, http.MethodPatch, "/rrsets/", changes, nil); err != nil {
		return fmt.Errorf("writing the records of %s: %w", fqdn, err)
	}
	return nil
}

// SetTXT makes the TXT set of the name the values, none removing it, of the zone's least TTL, or
// txtTTL above it: its other sets stay.
func (d *DeSEC) SetTXT(hostname string, values []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), updateTimeout)
	defer cancel()
	fqdn := FQDN(hostname, d.Zone)
	if !inZone(fqdn, d.Zone) {
		return fmt.Errorf("%s is not of the zone %s", fqdn, d.Zone)
	}
	subname := strings.ToLower(RelativeName(fqdn, d.Zone))
	if _, err := d.ttl(ctx); err != nil {
		return err
	}
	d.mutex.Lock()
	ttl := max(d.minimumTTL, txtTTL)
	d.mutex.Unlock()
	current, err := d.rrsets(ctx, subname)
	if err != nil {
		return fmt.Errorf("reading the TXT records of %s: %w", fqdn, err)
	}
	want := []string{}
	for _, v := range values {
		want = append(want, quoteTXT(v))
	}
	slices.Sort(want)
	got := slices.Clone(current["TXT"].Records)
	slices.Sort(got)
	if slices.Equal(got, want) {
		return nil
	}
	change := []deSECRRset{{Subname: subname, Type: "TXT", TTL: ttl, Records: want}}
	if err := d.call(ctx, http.MethodPatch, "/rrsets/", change, nil); err != nil {
		return fmt.Errorf("writing the TXT records of %s: %w", fqdn, err)
	}
	return nil
}

// quoteTXT is a TXT record's value as a zone file has it, quoted, its quotes and backslashes
// escaped.
func quoteTXT(v string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`
}
