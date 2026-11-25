package ddns

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/duration"
	"github.com/miguelangel-nubla/ipv6disc"
)

// UniFi keeps the addresses of a name as local DNS records of a UniFi gateway, its "DNS
// Records", through the UniFi Network API: of a UniFi OS console or UniFi OS Server, with an API
// key or a user, or of a self-hosted Network Application, with a user. A record is a name and one
// address: a name with several addresses has one record for each.
type UniFi struct {
	Address        string            `json:"address"`
	TLSFingerprint string            `json:"tls_fingerprint"`
	APIKey         string            `json:"api_key"`
	Username       string            `json:"username"`
	Password       string            `json:"password"`
	Site           string            `json:"site"`
	Zone           string            `json:"zone"`
	TTL            duration.Duration `json:"ttl"`

	// The session of a user: its cookies and CSRF token, kept between updates, as a login is
	// slow and UniFi OS limits how often one is made; and whether the server is UniFi OS, whose
	// Network API is under /proxy/network. Made at the first update, and again when refused.
	client   *http.Client
	loggedIn bool
	unifiOS  bool
	csrf     string
}

// unifiMaxTTL is the longest TTL the Network API takes for an A or AAAA record.
const unifiMaxTTL = 24 * time.Hour

func init() {
	RegisterProvider("unifi", NewUniFi)
}

func NewUniFi(settings json.RawMessage) (Service, error) {
	var service UniFi
	if err := decodeSettings(settings, "unifi", &service); err != nil {
		return nil, err
	}
	switch {
	case service.APIKey != "" && (service.Username != "" || service.Password != ""):
		return nil, errors.New("give api_key or username and password, not both")
	case service.APIKey == "" && (service.Username == "" || service.Password == ""):
		return nil, errors.New("give api_key, an API key of UniFi OS, or username and password, of a user that may change the network's settings")
	case service.TTL.Duration > unifiMaxTTL:
		return nil, fmt.Errorf("ttl: %s is longer than UniFi takes, %s", service.TTL.Duration, unifiMaxTTL)
	}
	if service.Site == "" {
		service.Site = "default"
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	service.client = newHTTPClient(verifiedOrPinnedTLSConfig(urlHost(service.Address), service.TLSFingerprint))
	service.client.Jar = jar
	// An API key is of UniFi OS alone.
	service.unifiOS = service.APIKey != ""
	return &service, nil
}

// unifiRecord is a local DNS record as the Network API has it. Other fields, as the priority of
// an SRV record, are left out: the API takes a record without them.
type unifiRecord struct {
	ID         string `json:"_id,omitempty"`
	Enabled    bool   `json:"enabled"`
	Key        string `json:"key"`
	RecordType string `json:"record_type"`
	Value      string `json:"value"`
	TTL        int    `json:"ttl"`
}

func (u *UniFi) Update(hostname string, addrCollection *ipv6disc.AddrCollection) error {
	fqdn := u.Domain(hostname)
	ttl := int(u.TTL.Seconds())

	var records []unifiRecord
	if err := u.call(http.MethodGet, "", nil, &records); err != nil {
		return fmt.Errorf("failed to list the DNS records: %w", err)
	}

	desired := desiredRecords(addrCollection)

	// The A and AAAA records of the name, by their address. One of another type, as a CNAME, is
	// the user's own, and so is a disabled one: its address stays as it is, and gets no record
	// beside it.
	current := make(map[string][]unifiRecord)
	disabled := make(map[string]bool)
	for _, record := range records {
		if lowerASCII(strings.Trim(record.Key, ".")) != fqdn || (record.RecordType != "A" && record.RecordType != "AAAA") {
			continue
		}
		ip, ok := canonicalIP(record.Value)
		if !ok {
			continue
		}
		if !record.Enabled {
			disabled[ip] = true
			continue
		}
		current[ip] = append(current[ip], record)
	}

	for ip, entries := range current {
		rtype, wanted := desired[ip]
		if wanted && len(entries) == 1 && entries[0].RecordType == rtype {
			if entries[0].TTL != ttl {
				fixed := entries[0]
				fixed.TTL = ttl
				if err := u.call(http.MethodPut, "/"+url.PathEscape(fixed.ID), fixed, nil); err != nil {
					return fmt.Errorf("failed to set the TTL of the record of %s to %s: %w", fqdn, ip, err)
				}
			}
			continue
		}
		for _, entry := range entries {
			if err := u.call(http.MethodDelete, "/"+url.PathEscape(entry.ID), nil, nil); err != nil {
				return fmt.Errorf("failed to delete the record of %s to %s: %w", fqdn, ip, err)
			}
		}
		// Of an address the name keeps, said more than once: it is added again, once.
		delete(current, ip)
	}

	for ip, rtype := range desired {
		if _, exists := current[ip]; exists || disabled[ip] {
			continue
		}
		record := unifiRecord{Enabled: true, Key: fqdn, RecordType: rtype, Value: ip, TTL: ttl}
		if err := u.call(http.MethodPost, "", record, nil); err != nil {
			return fmt.Errorf("failed to add the record of %s to %s: %w", fqdn, ip, err)
		}
	}
	return nil
}

// call asks the DNS records of the site, at the path under them, with body when there is one,
// and reads the answer into out when there is where to. A user logs in first, and again once
// when the session is refused.
func (u *UniFi) call(method, path string, body, out any) error {
	if u.APIKey == "" && !u.loggedIn {
		if err := u.login(); err != nil {
			return err
		}
	}
	status, answer, err := u.do(method, u.recordsPath()+path, body)
	if err == nil && status == http.StatusUnauthorized && u.APIKey == "" {
		u.loggedIn = false
		if err := u.login(); err != nil {
			return err
		}
		status, answer, err = u.do(method, u.recordsPath()+path, body)
	}
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return u.refused(status, answer)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(answer, out); err != nil {
		return fmt.Errorf("HTTP %d: not an answer of the UniFi Network API: %w", status, err)
	}
	return nil
}

// recordsPath is the path of the site's DNS records.
func (u *UniFi) recordsPath() string {
	path := "/v2/api/site/" + url.PathEscape(u.Site) + "/static-dns"
	if u.unifiOS {
		path = "/proxy/network" + path
	}
	return path
}

// do sends a request to path of the server, with the API key or the session, and returns the
// status and the answer.
func (u *UniFi) do(method, path string, body any) (int, []byte, error) {
	base, err := url.Parse(u.Address)
	if err != nil {
		return 0, nil, err
	}
	base.Path, _ = url.JoinPath(base.Path, path)
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequest(method, base.String(), reader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if u.APIKey != "" {
		req.Header.Set("X-API-KEY", u.APIKey)
	} else if u.csrf != "" {
		req.Header.Set("X-Csrf-Token", u.csrf)
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return 0, nil, withoutURL(err)
	}
	defer resp.Body.Close()
	// UniFi OS gives the session's CSRF token at its login, and a new one now and then: the
	// next request needs it.
	for _, header := range []string{"X-Csrf-Token", "X-Updated-Csrf-Token"} {
		if token := resp.Header.Get(header); token != "" {
			u.csrf = token
		}
	}
	answer, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return 0, nil, fmt.Errorf("HTTP %s: reading the answer: %w", resp.Status, err)
	}
	return resp.StatusCode, answer, nil
}

// login logs the user in: at UniFi OS's login, or at a self-hosted Network Application's, which
// answers UniFi OS's with an error of its own form, with meta. It keeps the session's cookies,
// and UniFi OS's CSRF token, which every change must send.
func (u *UniFi) login() error {
	u.csrf = ""
	credentials := map[string]any{"username": u.Username, "password": u.Password}
	u.unifiOS = true
	status, answer, err := u.do(http.MethodPost, "/api/auth/login", credentials)
	if err == nil && status != http.StatusOK && selfHostedAnswer(answer) {
		u.unifiOS = false
		status, answer, err = u.do(http.MethodPost, "/api/login", credentials)
	}
	switch {
	case err != nil:
		return fmt.Errorf("logging in: %w", err)
	case status == http.StatusOK:
		u.loggedIn = true
		return nil
	case status == http.StatusBadRequest || status == http.StatusUnauthorized || status == http.StatusForbidden:
		// A self-hosted Network Application refuses with 400, UniFi OS with 403.
		return fmt.Errorf("logging in: HTTP %d: the username or the password is refused. A user with two-factor authentication can't log in here: use an API key, or a local user without it", status)
	}
	return fmt.Errorf("logging in: %w", u.refused(status, answer))
}

// selfHostedAnswer tells an answer of a self-hosted Network Application's API, which has meta.
func selfHostedAnswer(answer []byte) bool {
	var said struct {
		Meta *struct{} `json:"meta"`
	}
	return json.Unmarshal(answer, &said) == nil && said.Meta != nil
}

// refused is the error of an answer that isn't 200: with what UniFi says, in whichever of its
// forms, and what to do about a refused key or user.
func (u *UniFi) refused(status int, answer []byte) error {
	var said struct {
		Message string `json:"message"`
		Error   struct {
			Message string `json:"message"`
		} `json:"error"`
		Meta struct {
			Msg string `json:"msg"`
		} `json:"meta"`
		Details struct {
			InvalidFields []string `json:"invalid_fields"`
		} `json:"details"`
	}
	message := ""
	if json.Unmarshal(answer, &said) == nil {
		message = said.Message
		if message == "" {
			message = said.Error.Message
		}
		if message == "" {
			message = said.Meta.Msg
		}
		if len(said.Details.InvalidFields) > 0 {
			message += " (" + strings.Join(said.Details.InvalidFields, ", ") + ")"
		}
	}
	text := fmt.Sprintf("HTTP %d", status)
	switch {
	case status == http.StatusUnauthorized && u.APIKey != "":
		return fmt.Errorf("%s: the API key is refused: create one in UniFi OS, Settings, Control Plane, Integrations", text)
	case status == http.StatusForbidden:
		return fmt.Errorf("%s: not allowed: the user, or the key's user, must be allowed to change the network's settings", text)
	case status == http.StatusTooManyRequests:
		return fmt.Errorf("%s: too many requests, or logins: UniFi asks to wait", text)
	case status == http.StatusNotFound && u.APIKey != "":
		return fmt.Errorf("%s: no DNS records of site %q here: the site, or the address, is wrong, or the UniFi Network is older than 8.2.93, the first with them. An API key is of UniFi OS alone: a self-hosted Network Application needs username and password", text, u.Site)
	case status == http.StatusNotFound:
		return fmt.Errorf("%s: no DNS records of site %q here: the site, or the address, is wrong, or the UniFi Network is older than 8.2.93, the first with them", text, u.Site)
	case message == "":
		return fmt.Errorf("%s: not an answer of the UniFi Network API", text)
	}
	if len(message) > 200 {
		message = message[:200]
	}
	return fmt.Errorf("%s: %s", text, message)
}

// Domain is the name as UniFi keeps it: in lower case, without the final dot.
func (u *UniFi) Domain(hostname string) string {
	return lowerASCII(FQDN(hostname, u.Zone))
}
