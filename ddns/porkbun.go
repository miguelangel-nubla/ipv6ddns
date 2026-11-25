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
	"sync"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/duration"
	"github.com/miguelangel-nubla/ipv6disc"
)

// Porkbun is Porkbun's DNS, through its API: a domain of the account, with API access turned on,
// whose records are each its own, made, edited and deleted one at a time. See
// docs/reference/providers.md.
type Porkbun struct {
	APIKey       string            `json:"api_key"`
	SecretAPIKey string            `json:"secret_api_key"`
	Zone         string            `json:"zone"`
	TTL          duration.Duration `json:"ttl"`

	// The API's address, for tests: empty is Porkbun's.
	apiBaseURL string

	mutex    sync.Mutex
	warnings []string
	warned   bool
}

// porkbunAPI is Porkbun's API.
const porkbunAPI = "https://api.porkbun.com/api/json/v3"

// porkbunMinimumTTL is the least TTL Porkbun takes.
const porkbunMinimumTTL = 600

// porkbunRecord is a record, as the API has it: its name in full, its TTL as text.
type porkbunRecord struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     string `json:"ttl"`
}

func init() {
	RegisterProvider("porkbun", NewPorkbun)
	RegisterTXT("porkbun")
}

func NewPorkbun(settings json.RawMessage) (Service, error) {
	var service Porkbun
	if err := decodeSettings(settings, "porkbun", &service); err != nil {
		return nil, err
	}
	service.Zone = strings.ToLower(strings.Trim(service.Zone, "."))
	return &service, nil
}

func (p *Porkbun) Domain(hostname string) string { return FQDN(hostname, p.Zone) }

func (p *Porkbun) FullName(hostname string) (string, error) { return p.Domain(hostname), nil }

// Warnings are the TTL raised to Porkbun's least, said once.
func (p *Porkbun) Warnings() []string {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	w := p.warnings
	p.warnings = nil
	return w
}

// ttl is the records' TTL: the settings', Porkbun's least without one, or when it is lower,
// which Porkbun refuses, as said once.
func (p *Porkbun) ttl() int {
	want := int(p.TTL.Seconds())
	if want == 0 {
		return porkbunMinimumTTL
	}
	if want < porkbunMinimumTTL {
		p.mutex.Lock()
		if !p.warned {
			p.warned = true
			p.warnings = append(p.warnings, fmt.Sprintf("the ttl %s is below the least Porkbun takes, %ds: the records have that one", p.TTL.Duration, porkbunMinimumTTL))
		}
		p.mutex.Unlock()
		return porkbunMinimumTTL
	}
	return want
}

// call asks the API path, with fields and the keys as its JSON body, and reads its answer into
// out. Every request is a POST. One refused for coming too often, 503 or 429, is asked again a
// second later, while ctx lasts.
func (p *Porkbun) call(ctx context.Context, path string, fields map[string]string, out any) error {
	base := p.apiBaseURL
	if base == "" {
		base = porkbunAPI
	}
	body := map[string]string{"apikey": p.APIKey, "secretapikey": p.SecretAPIKey}
	for k, v := range fields {
		body[k] = v
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	client := newHTTPClient(nil)
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(data))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		answer, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			select {
			case <-ctx.Done():
				return fmt.Errorf("HTTP %d: Porkbun refuses requests that come too often, past the update's time", resp.StatusCode)
			case <-time.After(time.Second):
			}
			continue
		}
		var status struct {
			Status  string `json:"status"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(answer, &status); err != nil {
			return fmt.Errorf("HTTP %d: not an answer of Porkbun's API", resp.StatusCode)
		}
		if status.Status != "SUCCESS" {
			return p.refused(resp.StatusCode, status.Message)
		}
		if out != nil {
			if err := json.Unmarshal(answer, out); err != nil {
				return fmt.Errorf("not an answer of Porkbun's API: %w", err)
			}
		}
		return nil
	}
}

// refused is the error of an answer that refuses, with what Porkbun said, and what to do for the
// two mistakes it says least plainly.
func (p *Porkbun) refused(status int, message string) error {
	lower := strings.ToLower(message)
	switch {
	case strings.Contains(lower, "invalid api key"), strings.Contains(lower, "api key"):
		return fmt.Errorf("HTTP %d: the keys are refused: %s", status, message)
	case strings.Contains(lower, "opted in") || strings.Contains(lower, "api access"):
		return fmt.Errorf("HTTP %d: %s: turn on API Access for %s, in Porkbun's Domain Management", status, message, p.Zone)
	}
	return fmt.Errorf("HTTP %d: %s", status, message)
}

// subname is the name of a name of the zone, relative to it, "" for the zone itself.
func (p *Porkbun) subname(hostname string) (string, string, error) {
	fqdn := FQDN(hostname, p.Zone)
	if !inZone(fqdn, p.Zone) {
		return "", "", fmt.Errorf("%s is not of the zone %s", fqdn, p.Zone)
	}
	return fqdn, strings.ToLower(RelativeName(fqdn, p.Zone)), nil
}

// records are the records of the name of a type.
func (p *Porkbun) records(ctx context.Context, sub, rrType string) ([]porkbunRecord, error) {
	path := "/dns/retrieveByNameType/" + url.PathEscape(p.Zone) + "/" + rrType
	if sub != "" {
		path += "/" + url.PathEscape(sub)
	}
	var answer struct {
		Records []porkbunRecord `json:"records"`
	}
	if err := p.call(ctx, path, nil, &answer); err != nil {
		return nil, err
	}
	return answer.Records, nil
}

// set makes the records of the name of rrType the values, of ttl: the missing ones made first, so
// the name always has some, then the others deleted, and the TTL of those kept made the one.
func (p *Porkbun) set(ctx context.Context, sub, rrType string, values []string, ttl int, canonical func(string) (string, bool)) error {
	current, err := p.records(ctx, sub, rrType)
	if err != nil {
		return err
	}
	have := make(map[string]bool)
	for _, r := range current {
		v, ok := canonical(r.Content)
		if !ok {
			return fmt.Errorf("a %s record at Porkbun isn't one: %s", rrType, r.Content)
		}
		have[v] = true
	}
	want := make(map[string]bool)
	for _, v := range values {
		want[v] = true
		if have[v] {
			continue
		}
		fields := map[string]string{"name": sub, "type": rrType, "content": v, "ttl": strconv.Itoa(ttl)}
		if err := p.call(ctx, "/dns/create/"+url.PathEscape(p.Zone), fields, nil); err != nil {
			return fmt.Errorf("making the %s record %s: %w", rrType, v, err)
		}
	}
	kept := make(map[string]bool)
	for _, r := range current {
		v, _ := canonical(r.Content)
		if !want[v] || kept[v] {
			if err := p.call(ctx, "/dns/delete/"+url.PathEscape(p.Zone)+"/"+url.PathEscape(r.ID), nil, nil); err != nil {
				return fmt.Errorf("deleting the %s record %s: %w", rrType, v, err)
			}
			continue
		}
		kept[v] = true
		if r.TTL != strconv.Itoa(ttl) {
			fields := map[string]string{"name": sub, "type": rrType, "content": r.Content, "ttl": strconv.Itoa(ttl)}
			if err := p.call(ctx, "/dns/edit/"+url.PathEscape(p.Zone)+"/"+url.PathEscape(r.ID), fields, nil); err != nil {
				return fmt.Errorf("setting the TTL of the %s record %s: %w", rrType, v, err)
			}
		}
	}
	return nil
}

// Update makes the A and AAAA records of the name the addresses; its other records stay.
func (p *Porkbun) Update(hostname string, addresses *ipv6disc.AddrCollection) error {
	ctx, cancel := context.WithTimeout(context.Background(), updateTimeout)
	defer cancel()
	fqdn, sub, err := p.subname(hostname)
	if err != nil {
		return err
	}
	desired := map[string][]string{}
	for ip, recordType := range desiredRecords(addresses) {
		desired[recordType] = append(desired[recordType], ip)
	}
	ttl := p.ttl()
	for _, recordType := range []string{"A", "AAAA"} {
		if err := p.set(ctx, sub, recordType, desired[recordType], ttl, canonicalIP); err != nil {
			return fmt.Errorf("the %s records of %s: %w", recordType, fqdn, err)
		}
	}
	return nil
}

// SetTXT makes the TXT records of the name the values, none removing them, of Porkbun's least
// TTL: its other records stay.
func (p *Porkbun) SetTXT(hostname string, values []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), updateTimeout)
	defer cancel()
	fqdn, sub, err := p.subname(hostname)
	if err != nil {
		return err
	}
	// Porkbun gives a TXT record's content as it was given, without quotes.
	same := func(s string) (string, bool) { return strings.Trim(s, `"`), true }
	if err := p.set(ctx, sub, "TXT", values, porkbunMinimumTTL, same); err != nil {
		return fmt.Errorf("the TXT records of %s: %w", fqdn, err)
	}
	return nil
}
