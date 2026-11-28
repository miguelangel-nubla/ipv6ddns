package ddns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/duration"
	"github.com/miguelangel-nubla/ipv6disc"
)

// DigitalOcean is DigitalOcean's DNS, through its API: a domain of the account, whose records are
// each its own, made, changed and deleted one at a time. See docs/reference/providers.md.
type DigitalOcean struct {
	APIToken string            `json:"api_token"`
	Zone     string            `json:"zone"`
	TTL      duration.Duration `json:"ttl"`

	// The API's address, for tests: empty is DigitalOcean's.
	apiBaseURL string
}

// digitalOceanAPI is DigitalOcean's API.
const digitalOceanAPI = "https://api.digitalocean.com/v2"

// The TTL of the records without one in the settings, DigitalOcean's own, and the least it takes.
const (
	digitalOceanDefaultTTL = 3600
	digitalOceanMinimumTTL = 30
)

// digitalOceanRecord is a record, as the API has it: its name relative to the domain, @ for the
// domain itself.
type digitalOceanRecord struct {
	ID   int64  `json:"id,omitempty"`
	Type string `json:"type"`
	Name string `json:"name"`
	Data string `json:"data"`
	TTL  int    `json:"ttl"`
}

func init() {
	RegisterProvider("digitalocean", NewDigitalOcean)
	RegisterTXT("digitalocean")
}

func NewDigitalOcean(settings json.RawMessage) (Service, error) {
	var service DigitalOcean
	if err := decodeSettings(settings, "digitalocean", &service); err != nil {
		return nil, err
	}
	service.Zone = strings.ToLower(strings.Trim(service.Zone, "."))
	if ttl := int(service.TTL.Seconds()); ttl != 0 && ttl < digitalOceanMinimumTTL {
		return nil, fmt.Errorf("digitalocean: the ttl %s is below the least DigitalOcean takes, %ds", service.TTL.Duration, digitalOceanMinimumTTL)
	}
	return &service, nil
}

func (d *DigitalOcean) Domain(hostname string) string { return FQDN(hostname, d.Zone) }

func (d *DigitalOcean) FullName(hostname string) (string, error) { return d.Domain(hostname), nil }

func (d *DigitalOcean) ttl() int {
	if ttl := int(d.TTL.Seconds()); ttl > 0 {
		return ttl
	}
	return digitalOceanDefaultTTL
}

// call asks the API path of the domain, with body as JSON, and reads its answer into out. A
// request refused for coming too often, 429, is asked again a second later, while ctx lasts.
func (d *DigitalOcean) call(ctx context.Context, method, path string, body, out any) error {
	base := d.apiBaseURL
	if base == "" {
		base = digitalOceanAPI
	}
	var data []byte
	if body != nil {
		var err error
		if data, err = json.Marshal(body); err != nil {
			return err
		}
	}
	client := newHTTPClient(nil)
	for {
		req, err := http.NewRequestWithContext(ctx, method, base+"/domains/"+url.PathEscape(d.Zone)+path, bytes.NewReader(data))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+d.APIToken)
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
			select {
			case <-ctx.Done():
				return fmt.Errorf("HTTP 429: DigitalOcean refuses requests that come too often, past the update's time")
			case <-time.After(time.Second):
			}
			continue
		}
		if resp.StatusCode >= 300 {
			var e struct {
				ID      string `json:"id"`
				Message string `json:"message"`
			}
			said := strings.TrimSpace(string(answer))
			if json.Unmarshal(answer, &e) == nil && e.Message != "" {
				said = e.Message
			}
			switch resp.StatusCode {
			case http.StatusUnauthorized, http.StatusForbidden:
				return fmt.Errorf("HTTP %d: the token is refused, which must have the write scope: %s", resp.StatusCode, said)
			case http.StatusNotFound:
				return fmt.Errorf("HTTP 404: the domain %s isn't one of the account's: %s", d.Zone, said)
			}
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, said)
		}
		if out != nil && len(answer) > 0 {
			if err := json.Unmarshal(answer, out); err != nil {
				return fmt.Errorf("not an answer of DigitalOcean's API: %w", err)
			}
		}
		return nil
	}
}

// records are the records of the name of a type, of every page.
func (d *DigitalOcean) records(ctx context.Context, fqdn, rrType string) ([]digitalOceanRecord, error) {
	var all []digitalOceanRecord
	for page := 1; ; page++ {
		var answer struct {
			Records []digitalOceanRecord `json:"domain_records"`
			Links   struct {
				Pages struct {
					Next string `json:"next"`
				} `json:"pages"`
			} `json:"links"`
		}
		path := fmt.Sprintf("/records?name=%s&type=%s&per_page=200&page=%d", url.QueryEscape(fqdn), rrType, page)
		if err := d.call(ctx, http.MethodGet, path, nil, &answer); err != nil {
			return nil, err
		}
		all = append(all, answer.Records...)
		if answer.Links.Pages.Next == "" || len(answer.Records) == 0 {
			return all, nil
		}
	}
}

// set makes the records of the name of rrType the values, of ttl, apart, as DigitalOcean keeps
// them.
func (d *DigitalOcean) set(ctx context.Context, fqdn, rrType string, values []string, ttl int, canonical func(string) (string, bool)) error {
	records, err := d.records(ctx, fqdn, rrType)
	if err != nil {
		return err
	}
	sub := RelativeName(fqdn, d.Zone)
	if sub == "" {
		sub = "@"
	}
	var current []providerRecord
	for _, r := range records {
		if r.Type == rrType {
			current = append(current, providerRecord{ID: strconv.FormatInt(r.ID, 10), Value: r.Data, TTL: r.TTL})
		}
	}
	return reconcile(current, values, ttl, canonical, recordChanges{
		create: func(v string) error {
			return d.call(ctx, http.MethodPost, "/records", digitalOceanRecord{Type: rrType, Name: sub, Data: v, TTL: ttl}, nil)
		},
		remove: func(r providerRecord) error {
			return d.call(ctx, http.MethodDelete, "/records/"+r.ID, nil, nil)
		},
		setTTL: func(r providerRecord) error {
			return d.call(ctx, http.MethodPatch, "/records/"+r.ID, map[string]int{"ttl": ttl}, nil)
		},
	})
}

// Update makes the A and AAAA records of the name the addresses; its other records stay.
func (d *DigitalOcean) Update(hostname string, addresses *ipv6disc.AddrCollection) error {
	ctx, cancel := context.WithTimeout(context.Background(), updateTimeout)
	defer cancel()
	fqdn := FQDN(hostname, d.Zone)
	if !inZone(fqdn, d.Zone) {
		return fmt.Errorf("%s is not of the zone %s", fqdn, d.Zone)
	}
	desired := map[string][]string{}
	for ip, recordType := range desiredRecords(addresses) {
		desired[recordType] = append(desired[recordType], ip)
	}
	for _, recordType := range []string{"A", "AAAA"} {
		if err := d.set(ctx, strings.ToLower(fqdn), recordType, desired[recordType], d.ttl(), canonicalIP); err != nil {
			return fmt.Errorf("the %s records of %s: %w", recordType, fqdn, err)
		}
	}
	return nil
}

// SetTXT makes the TXT records of the name the values, none removing them, of txtTTL: its other
// records stay.
func (d *DigitalOcean) SetTXT(hostname string, values []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), updateTimeout)
	defer cancel()
	fqdn := FQDN(hostname, d.Zone)
	if !inZone(fqdn, d.Zone) {
		return fmt.Errorf("%s is not of the zone %s", fqdn, d.Zone)
	}
	// DigitalOcean gives a TXT record's data as it was given, without quotes.
	same := func(s string) (string, bool) { return strings.Trim(s, `"`), true }
	if err := d.set(ctx, strings.ToLower(fqdn), "TXT", values, max(txtTTL, digitalOceanMinimumTTL), same); err != nil {
		return fmt.Errorf("the TXT records of %s: %w", fqdn, err)
	}
	return nil
}
