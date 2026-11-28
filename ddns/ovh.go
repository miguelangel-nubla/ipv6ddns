package ddns

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
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

// OVH is OVHcloud's DNS, through its API: a zone of the account, whose records are each its own,
// made, changed and deleted one at a time, and served once the zone is refreshed. Each request is
// signed with the application's secret and the consumer key. See docs/reference/providers.md.
type OVH struct {
	Endpoint          string            `json:"endpoint"`
	ApplicationKey    string            `json:"application_key"`
	ApplicationSecret string            `json:"application_secret"`
	ConsumerKey       string            `json:"consumer_key"`
	Zone              string            `json:"zone"`
	TTL               duration.Duration `json:"ttl"`

	// The API's address, of the endpoint.
	apiBaseURL string

	mutex sync.Mutex
	// How far OVH's clock is from this one's, once asked: each signature has OVH's time.
	clockDelta time.Duration
	clockKnown bool
	// A change was made that no refresh has served yet: one that failed leaves it so, for the
	// next update to refresh, which would otherwise find the records as wanted and nothing to do.
	// Kept in memory alone, as OPNsense's: the API tells of no change left to refresh.
	pending bool
}

// The endpoints of OVH's API, by their names.
var ovhEndpoints = map[string]string{
	"ovh-eu": "https://eu.api.ovh.com/1.0",
	"ovh-ca": "https://ca.api.ovh.com/1.0",
	"ovh-us": "https://api.us.ovhcloud.com/1.0",
}

// The TTL of the records without one in the settings, and the least OVH takes.
const (
	ovhDefaultTTL = 3600
	ovhMinimumTTL = 60
)

// ovhRecord is a record, as the API has it: its name relative to the zone, "" for the zone itself.
type ovhRecord struct {
	ID        int64  `json:"id,omitempty"`
	FieldType string `json:"fieldType"`
	SubDomain string `json:"subDomain"`
	Target    string `json:"target"`
	TTL       int    `json:"ttl"`
}

func init() {
	RegisterProvider("ovh", NewOVH)
	RegisterTXT("ovh")
}

func NewOVH(settings json.RawMessage) (Service, error) {
	var service OVH
	if err := decodeSettings(settings, "ovh", &service); err != nil {
		return nil, err
	}
	service.Zone = strings.ToLower(strings.Trim(service.Zone, "."))
	endpoint := service.Endpoint
	if endpoint == "" {
		endpoint = "ovh-eu"
	}
	if base, ok := ovhEndpoints[endpoint]; ok {
		service.apiBaseURL = base
	} else if u, err := url.Parse(endpoint); err == nil && u.Scheme == "https" && u.Host != "" {
		service.apiBaseURL = strings.TrimSuffix(endpoint, "/")
	} else {
		return nil, fmt.Errorf("ovh: the endpoint %q is none of ovh-eu, ovh-ca and ovh-us, nor an https:// URL", service.Endpoint)
	}
	if ttl := int(service.TTL.Seconds()); ttl != 0 && ttl < ovhMinimumTTL {
		return nil, fmt.Errorf("ovh: the ttl %s is below the least OVH takes, %ds", service.TTL.Duration, ovhMinimumTTL)
	}
	return &service, nil
}

func (o *OVH) Domain(hostname string) string { return FQDN(hostname, o.Zone) }

func (o *OVH) FullName(hostname string) (string, error) { return o.Domain(hostname), nil }

func (o *OVH) ttl() int {
	if ttl := int(o.TTL.Seconds()); ttl > 0 {
		return ttl
	}
	return ovhDefaultTTL
}

// now is the time of OVH's clock, asked of /auth/time once.
func (o *OVH) now(ctx context.Context) (time.Time, error) {
	o.mutex.Lock()
	known, delta := o.clockKnown, o.clockDelta
	o.mutex.Unlock()
	if !known {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.apiBaseURL+"/auth/time", nil)
		if err != nil {
			return time.Time{}, err
		}
		resp, err := newHTTPClient(nil).Do(req)
		if err != nil {
			return time.Time{}, err
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
		resp.Body.Close()
		server, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		if err != nil || resp.StatusCode != http.StatusOK {
			return time.Time{}, fmt.Errorf("OVH's time: HTTP %d, %q", resp.StatusCode, data)
		}
		delta = time.Until(time.Unix(server, 0))
		o.mutex.Lock()
		o.clockDelta, o.clockKnown = delta, true
		o.mutex.Unlock()
	}
	return time.Now().Add(delta), nil
}

// call asks the API path, of the zone unless it starts with /auth, with body as JSON, signed, and
// reads its answer into out. A request refused for coming too often, 429, is asked again a second
// later, while ctx lasts.
func (o *OVH) call(ctx context.Context, method, path string, body, out any) error {
	target := o.apiBaseURL + "/domain/zone/" + url.PathEscape(o.Zone) + path
	var data []byte
	if body != nil {
		var err error
		if data, err = json.Marshal(body); err != nil {
			return err
		}
	}
	client := newHTTPClient(nil)
	for {
		now, err := o.now(ctx)
		if err != nil {
			return err
		}
		timestamp := strconv.FormatInt(now.Unix(), 10)
		sum := sha1.Sum([]byte(strings.Join([]string{o.ApplicationSecret, o.ConsumerKey, method, target, string(data), timestamp}, "+")))
		req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(data))
		if err != nil {
			return err
		}
		req.Header.Set("X-Ovh-Application", o.ApplicationKey)
		req.Header.Set("X-Ovh-Consumer", o.ConsumerKey)
		req.Header.Set("X-Ovh-Timestamp", timestamp)
		req.Header.Set("X-Ovh-Signature", "$1$"+hex.EncodeToString(sum[:]))
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
				return fmt.Errorf("HTTP 429: OVH refuses requests that come too often, past the update's time")
			case <-time.After(time.Second):
			}
			continue
		}
		if resp.StatusCode >= 300 {
			var e struct {
				Message string `json:"message"`
			}
			said := strings.TrimSpace(string(answer))
			if json.Unmarshal(answer, &e) == nil && e.Message != "" {
				said = e.Message
			}
			switch resp.StatusCode {
			case http.StatusUnauthorized, http.StatusForbidden:
				return fmt.Errorf("HTTP %d: the keys are refused, of which the consumer key must allow GET, POST, PUT and DELETE on /domain/zone/%s/*: %s", resp.StatusCode, o.Zone, said)
			case http.StatusNotFound:
				return fmt.Errorf("HTTP 404: %s: the zone %s isn't one of the account's, or the endpoint isn't its", said, o.Zone)
			}
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, said)
		}
		if out != nil && len(answer) > 0 {
			if err := json.Unmarshal(answer, out); err != nil {
				return fmt.Errorf("not an answer of OVH's API: %w", err)
			}
		}
		return nil
	}
}

// records are the records of the name of a type: their ids listed, and each read. One of another
// name is not taken as its own, should the listing give it: an API that took the empty name of the
// zone itself for every name would have the zone's update delete the addresses of them all.
func (o *OVH) records(ctx context.Context, sub, rrType string) ([]ovhRecord, error) {
	var ids []int64
	if err := o.call(ctx, http.MethodGet, "/record?fieldType="+rrType+"&subDomain="+url.QueryEscape(sub), nil, &ids); err != nil {
		return nil, err
	}
	var out []ovhRecord
	for _, id := range ids {
		var r ovhRecord
		if err := o.call(ctx, http.MethodGet, "/record/"+strconv.FormatInt(id, 10), nil, &r); err != nil {
			return nil, err
		}
		if strings.EqualFold(r.SubDomain, sub) {
			out = append(out, r)
		}
	}
	return out, nil
}

// set makes the records of the name of rrType the values, of ttl, apart, and tells whether it
// changed any.
func (o *OVH) set(ctx context.Context, sub, rrType string, values []string, ttl int, canonical func(string) (string, bool)) (bool, error) {
	records, err := o.records(ctx, sub, rrType)
	if err != nil {
		return false, err
	}
	var current []providerRecord
	for _, r := range records {
		current = append(current, providerRecord{ID: strconv.FormatInt(r.ID, 10), Value: r.Target, TTL: r.TTL})
	}
	changed := false
	err = reconcile(current, values, ttl, canonical, recordChanges{
		create: func(v string) error {
			changed = true
			return o.call(ctx, http.MethodPost, "/record", ovhRecord{FieldType: rrType, SubDomain: sub, Target: v, TTL: ttl}, nil)
		},
		remove: func(r providerRecord) error {
			changed = true
			return o.call(ctx, http.MethodDelete, "/record/"+r.ID, nil, nil)
		},
		setTTL: func(r providerRecord) error {
			changed = true
			return o.call(ctx, http.MethodPut, "/record/"+r.ID, map[string]any{"subDomain": sub, "target": r.Value, "ttl": ttl}, nil)
		},
	})
	return changed, err
}

// refresh has OVH serve the zone as it is now: its changes are served once it is.
func (o *OVH) refresh(ctx context.Context) error {
	if err := o.call(ctx, http.MethodPost, "/refresh", nil, nil); err != nil {
		return fmt.Errorf("refreshing the zone: %w", err)
	}
	return nil
}

// subname is the name of a name of the zone, relative to it, "" for the zone itself.
func (o *OVH) subname(hostname string) (string, string, error) {
	fqdn := FQDN(hostname, o.Zone)
	if !inZone(fqdn, o.Zone) {
		return "", "", fmt.Errorf("%s is not of the zone %s", fqdn, o.Zone)
	}
	return fqdn, strings.ToLower(RelativeName(fqdn, o.Zone)), nil
}

// refreshPending refreshes the zone when this update changed a record, or an earlier one did and
// its refresh failed.
func (o *OVH) refreshPending(ctx context.Context, changed bool) error {
	o.mutex.Lock()
	o.pending = o.pending || changed
	pending := o.pending
	o.mutex.Unlock()
	if !pending {
		return nil
	}
	err := o.refresh(ctx)
	o.mutex.Lock()
	// Set again of a failure: another update's refresh, since, may have cleared it.
	o.pending = err != nil
	o.mutex.Unlock()
	return err
}

// Update makes the A and AAAA records of the name the addresses, and refreshes the zone when it
// changed any, or an earlier update did and failed before its refresh; its other records stay.
func (o *OVH) Update(hostname string, addresses *ipv6disc.AddrCollection) error {
	ctx, cancel := context.WithTimeout(context.Background(), updateTimeout)
	defer cancel()
	fqdn, sub, err := o.subname(hostname)
	if err != nil {
		return err
	}
	desired := map[string][]string{}
	for ip, recordType := range desiredRecords(addresses) {
		desired[recordType] = append(desired[recordType], ip)
	}
	changed := false
	for _, recordType := range []string{"A", "AAAA"} {
		c, err := o.set(ctx, sub, recordType, desired[recordType], o.ttl(), canonicalIP)
		changed = changed || c
		if err != nil {
			_ = o.refreshPending(ctx, changed)
			return fmt.Errorf("the %s records of %s: %w", recordType, fqdn, err)
		}
	}
	if err := o.refreshPending(ctx, changed); err != nil {
		return fmt.Errorf("the records of %s are written, and not served yet: %w", fqdn, err)
	}
	return nil
}

// SetTXT makes the TXT records of the name the values, none removing them, of OVH's least TTL, and
// refreshes the zone: its other records stay.
func (o *OVH) SetTXT(hostname string, values []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), updateTimeout)
	defer cancel()
	fqdn, sub, err := o.subname(hostname)
	if err != nil {
		return err
	}
	// OVH gives a TXT record's target as it was given, or quoted.
	same := func(s string) (string, bool) { return strings.Trim(s, `"`), true }
	changed, err := o.set(ctx, sub, "TXT", values, max(txtTTL, ovhMinimumTTL), same)
	if rerr := o.refreshPending(ctx, changed); err == nil {
		err = rerr
	}
	if err != nil {
		return fmt.Errorf("the TXT records of %s: %w", fqdn, err)
	}
	return nil
}
