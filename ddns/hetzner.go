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

// Hetzner is Hetzner's DNS, through the Hetzner Cloud API: a zone of the project, whose names'
// A and AAAA records are each a set. A change is an action, done once the API says it succeeded.
// See docs/reference/providers.md.
type Hetzner struct {
	APIToken string            `json:"api_token"`
	Zone     string            `json:"zone"`
	TTL      duration.Duration `json:"ttl"`

	// The API's address, for tests: empty is Hetzner's.
	apiBaseURL string
	// How often an action is asked whether it is done, for tests: 0 is a second.
	poll time.Duration

	mutex sync.Mutex
	// The zone's id, once the API told it.
	zoneID string
}

// hetznerAPI is the Hetzner Cloud API.
const hetznerAPI = "https://api.hetzner.cloud/v1"

// hetznerRRset is a set of records of a name and a type, as the API has them: the name relative to
// the zone, @ for the zone itself, and no TTL for the zone's own.
type hetznerRRset struct {
	Name    string          `json:"name"`
	Type    string          `json:"type"`
	TTL     *int            `json:"ttl"`
	Records []hetznerRecord `json:"records"`
}

type hetznerRecord struct {
	Value string `json:"value"`
}

// hetznerAction is a change the API makes on its own: done once its status is success.
type hetznerAction struct {
	ID     int64  `json:"id"`
	Status string `json:"status"`
	Error  *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func init() {
	RegisterProvider("hetzner", NewHetzner)
	RegisterTXT("hetzner")
}

func NewHetzner(settings json.RawMessage) (Service, error) {
	var service Hetzner
	if err := decodeSettings(settings, "hetzner", &service); err != nil {
		return nil, err
	}
	service.Zone = strings.ToLower(strings.Trim(service.Zone, "."))
	return &service, nil
}

func (h *Hetzner) Domain(hostname string) string { return FQDN(hostname, h.Zone) }

func (h *Hetzner) FullName(hostname string) (string, error) { return h.Domain(hostname), nil }

// call asks the API path, with body as JSON, and reads its answer into out. A request refused for
// coming too often, 429, is asked again a second later, while ctx lasts.
func (h *Hetzner) call(ctx context.Context, method, path string, body, out any) error {
	base := h.apiBaseURL
	if base == "" {
		base = hetznerAPI
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
		req, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(data))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+h.APIToken)
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
				return fmt.Errorf("HTTP 429: Hetzner refuses requests that come too often, past the update's time")
			case <-time.After(time.Second):
			}
			continue
		}
		if resp.StatusCode >= 300 {
			return h.refused(resp.StatusCode, answer)
		}
		if out != nil && len(answer) > 0 {
			if err := json.Unmarshal(answer, out); err != nil {
				return fmt.Errorf("not an answer of Hetzner's API: %w", err)
			}
		}
		return nil
	}
}

// refused is the error of an answer that refuses, with what Hetzner said.
func (h *Hetzner) refused(status int, answer []byte) error {
	var e struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	said := strings.TrimSpace(string(answer))
	if json.Unmarshal(answer, &e) == nil && e.Error.Message != "" {
		said = e.Error.Message
		if e.Error.Code != "" {
			said = e.Error.Code + ": " + said
		}
	}
	if len(said) > 300 {
		said = said[:300]
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return fmt.Errorf("HTTP %d: the token is refused, which must be of the project of the zone, and may read and write: %s", status, said)
	}
	return fmt.Errorf("HTTP %d: %s", status, said)
}

// zone is the zone's id, asked of the API once.
func (h *Hetzner) zone(ctx context.Context) (string, error) {
	h.mutex.Lock()
	id := h.zoneID
	h.mutex.Unlock()
	if id != "" {
		return id, nil
	}
	var zones struct {
		Zones []struct {
			ID   json.Number `json:"id"`
			Name string      `json:"name"`
		} `json:"zones"`
	}
	if err := h.call(ctx, http.MethodGet, "/zones?name="+url.QueryEscape(h.Zone), nil, &zones); err != nil {
		return "", fmt.Errorf("finding the zone %s: %w", h.Zone, err)
	}
	for _, z := range zones.Zones {
		if strings.EqualFold(strings.Trim(z.Name, "."), h.Zone) {
			h.mutex.Lock()
			h.zoneID = z.ID.String()
			h.mutex.Unlock()
			return z.ID.String(), nil
		}
	}
	return "", fmt.Errorf("the zone %s isn't one of the project's: make it in Hetzner's console, under DNS, or give the token of its project", h.Zone)
}

// wait waits until the action is done: an error if it failed.
func (h *Hetzner) wait(ctx context.Context, action hetznerAction) error {
	poll := h.poll
	if poll == 0 {
		poll = time.Second
	}
	for {
		switch action.Status {
		case "success":
			return nil
		case "error":
			if action.Error != nil {
				return fmt.Errorf("the change failed: %s: %s", action.Error.Code, action.Error.Message)
			}
			return fmt.Errorf("the change failed")
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("the change wasn't done within the update's time: %w", ctx.Err())
		case <-time.After(poll):
		}
		var answer struct {
			Action hetznerAction `json:"action"`
		}
		if err := h.call(ctx, http.MethodGet, "/actions/"+strconv.FormatInt(action.ID, 10), nil, &answer); err != nil {
			return err
		}
		action = answer.Action
	}
}

// subname is the name of the API, of a name of the zone: relative to it, @ for the zone itself.
func (h *Hetzner) subname(hostname string) (string, string, error) {
	fqdn := FQDN(hostname, h.Zone)
	if !inZone(fqdn, h.Zone) {
		return "", "", fmt.Errorf("%s is not of the zone %s", fqdn, h.Zone)
	}
	sub := strings.ToLower(RelativeName(fqdn, h.Zone))
	if sub == "" {
		sub = "@"
	}
	return fqdn, sub, nil
}

// rrset is the set of the name and type, nil for none. The zone is its id, a number Hetzner gave:
// it goes in the path as it is, and the name escaped.
func (h *Hetzner) rrset(ctx context.Context, zone, sub, rrType string) (*hetznerRRset, error) {
	var answer struct {
		RRsets []hetznerRRset `json:"rrsets"`
	}
	path := "/zones/" + zone + "/rrsets?name=" + url.QueryEscape(sub) + "&type=" + rrType
	if err := h.call(ctx, http.MethodGet, path, nil, &answer); err != nil {
		return nil, err
	}
	for _, s := range answer.RRsets {
		if strings.EqualFold(s.Name, sub) && s.Type == rrType {
			return &s, nil
		}
	}
	return nil, nil
}

// set makes the set of the name and type the values, of ttl, nil for the zone's: created, its
// records set, its TTL changed, or deleted, for none; and waits for each change to be done.
func (h *Hetzner) set(ctx context.Context, zone, sub, rrType string, values []string, ttl *int, same func(a, b string) bool) error {
	have, err := h.rrset(ctx, zone, sub, rrType)
	if err != nil {
		return err
	}
	records := []hetznerRecord{}
	for _, v := range values {
		records = append(records, hetznerRecord{Value: v})
	}
	setPath := "/zones/" + zone + "/rrsets/" + url.PathEscape(sub) + "/" + rrType
	var actions []hetznerAction
	switch {
	case have == nil && len(values) == 0:
		return nil
	case have == nil:
		var answer struct {
			Action hetznerAction `json:"action"`
		}
		if err := h.call(ctx, http.MethodPost, "/zones/"+zone+"/rrsets", hetznerRRset{Name: sub, Type: rrType, TTL: ttl, Records: records}, &answer); err != nil {
			return err
		}
		actions = append(actions, answer.Action)
	case len(values) == 0:
		var answer struct {
			Action hetznerAction `json:"action"`
		}
		if err := h.call(ctx, http.MethodDelete, setPath, nil, &answer); err != nil {
			return err
		}
		actions = append(actions, answer.Action)
	default:
		var got []string
		for _, r := range have.Records {
			got = append(got, r.Value)
		}
		if !sameValues(got, values, same) {
			var answer struct {
				Action hetznerAction `json:"action"`
			}
			if err := h.call(ctx, http.MethodPost, setPath+"/actions/set_records", map[string]any{"records": records}, &answer); err != nil {
				return err
			}
			actions = append(actions, answer.Action)
		}
		if ttl != nil && (have.TTL == nil || *have.TTL != *ttl) {
			var answer struct {
				Action hetznerAction `json:"action"`
			}
			if err := h.call(ctx, http.MethodPost, setPath+"/actions/change_ttl", map[string]any{"ttl": *ttl}, &answer); err != nil {
				return err
			}
			actions = append(actions, answer.Action)
		}
	}
	for _, a := range actions {
		if err := h.wait(ctx, a); err != nil {
			return err
		}
	}
	return nil
}

// sameAddress tells whether two addresses, as text, are one.
func sameAddress(a, b string) bool {
	x, okX := canonicalIP(a)
	y, okY := canonicalIP(b)
	return okX && okY && x == y
}

// sameValues tells whether two sets of values have the same, by same, whatever their order.
func sameValues(a, b []string, same func(a, b string) bool) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		if !slices.ContainsFunc(b, func(y string) bool { return same(x, y) }) {
			return false
		}
	}
	for _, y := range b {
		if !slices.ContainsFunc(a, func(x string) bool { return same(x, y) }) {
			return false
		}
	}
	return true
}

// Update makes the A and AAAA sets of the name the addresses, of the settings' TTL, or the zone's
// without one; the name's other sets stay. It returns once Hetzner says each change is done.
func (h *Hetzner) Update(hostname string, addresses *ipv6disc.AddrCollection) error {
	ctx, cancel := context.WithTimeout(context.Background(), updateTimeout)
	defer cancel()
	fqdn, sub, err := h.subname(hostname)
	if err != nil {
		return err
	}
	zone, err := h.zone(ctx)
	if err != nil {
		return err
	}
	var ttl *int
	if seconds := int(h.TTL.Seconds()); seconds > 0 {
		ttl = &seconds
	}
	desired := map[string][]string{}
	for ip, recordType := range desiredRecords(addresses) {
		desired[recordType] = append(desired[recordType], ip)
	}
	for _, recordType := range []string{"A", "AAAA"} {
		if err := h.set(ctx, zone, sub, recordType, desired[recordType], ttl, sameAddress); err != nil {
			return fmt.Errorf("writing the %s records of %s: %w", recordType, fqdn, err)
		}
	}
	return nil
}

// SetTXT makes the TXT set of the name the values, none removing it, of txtTTL: its other sets
// stay.
func (h *Hetzner) SetTXT(hostname string, values []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), updateTimeout)
	defer cancel()
	fqdn, sub, err := h.subname(hostname)
	if err != nil {
		return err
	}
	zone, err := h.zone(ctx)
	if err != nil {
		return err
	}
	var quoted []string
	for _, v := range values {
		quoted = append(quoted, quoteTXT(v))
	}
	ttl := txtTTL
	if err := h.set(ctx, zone, sub, "TXT", quoted, &ttl, func(a, b string) bool { return a == b }); err != nil {
		return fmt.Errorf("writing the TXT records of %s: %w", fqdn, err)
	}
	return nil
}
