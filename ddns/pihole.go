package ddns

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/miguelangel-nubla/ipv6disc"
)

// PiHole keeps the addresses of a name as local DNS records of Pi-hole, through the API of its
// version 6: the entries of dns.hosts, each "address name".
type PiHole struct {
	Address        string `json:"address"`
	TLSFingerprint string `json:"tls_fingerprint"`
	Password       string `json:"password"`
	Zone           string `json:"zone"`

	// The session, kept from one update to the next: Pi-hole has a few to give, and each lasts
	// half an hour after its last request.
	mu  sync.Mutex
	sid string
}

func init() {
	RegisterProvider("pihole", NewPiHole)
}

func NewPiHole(settings json.RawMessage) (Service, error) {
	var service PiHole
	if err := decodeSettings(settings, "pihole", &service); err != nil {
		return nil, err
	}
	return &service, nil
}

// errPiHoleSession is the answer to a request without a session Pi-hole takes.
var errPiHoleSession = errors.New("no session")

func (p *PiHole) Update(hostname string, addrCollection *ipv6disc.AddrCollection) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	client := newHTTPClient(verifiedOrPinnedTLSConfig(urlHost(p.Address), p.TLSFingerprint))
	fqdn := p.Domain(hostname)

	var listed struct {
		Config struct {
			DNS struct {
				Hosts []string `json:"hosts"`
			} `json:"dns"`
		} `json:"config"`
	}
	if err := p.call(client, http.MethodGet, "config/dns/hosts", &listed); err != nil {
		return fmt.Errorf("failed to list the local DNS records: %w", err)
	}

	desired := desiredRecords(addrCollection)

	// The entries of the name alone, "address name", by the address. One with more names is the
	// user's own: it is left as it is.
	current := make(map[string][]string)
	for _, entry := range listed.Config.DNS.Hosts {
		fields := strings.Fields(entry)
		if len(fields) != 2 || lowerASCII(strings.Trim(fields[1], ".")) != fqdn {
			continue
		}
		if ip, ok := canonicalIP(fields[0]); ok {
			current[ip] = append(current[ip], entry)
		}
	}

	for ip, entries := range current {
		// An address written in two ways is two entries: one stays.
		if _, wanted := desired[ip]; wanted {
			entries = entries[1:]
		} else {
			delete(current, ip)
		}
		for _, entry := range entries {
			if err := p.call(client, http.MethodDelete, "config/dns/hosts/"+url.PathEscape(entry), nil); err != nil {
				return fmt.Errorf("failed to delete the record of %s to %s: %w", fqdn, ip, err)
			}
		}
	}

	for ip := range desired {
		if _, exists := current[ip]; exists {
			continue
		}
		if err := p.call(client, http.MethodPut, "config/dns/hosts/"+url.PathEscape(ip+" "+fqdn), nil); err != nil {
			return fmt.Errorf("failed to add the record of %s to %s: %w", fqdn, ip, err)
		}
	}
	return nil
}

// call asks the API, with the session when Pi-hole has a password. A session Pi-hole no longer
// takes, as after its restart, is asked for again, once.
func (p *PiHole) call(client *http.Client, method, path string, out any) error {
	err := p.request(client, method, path, nil, out)
	if !errors.Is(err, errPiHoleSession) {
		return err
	}
	if p.Password == "" {
		return errors.New("Pi-hole asks for a password: give password, the one of its web interface or an application password")
	}
	if err := p.login(client); err != nil {
		return err
	}
	if err := p.request(client, method, path, nil, out); errors.Is(err, errPiHoleSession) {
		return errors.New("Pi-hole refuses the session it just gave")
	} else {
		return err
	}
}

// login asks for a session with the password.
func (p *PiHole) login(client *http.Client) error {
	p.sid = ""
	var answer struct {
		Session struct {
			Valid bool   `json:"valid"`
			SID   string `json:"sid"`
		} `json:"session"`
	}
	body, _ := json.Marshal(map[string]string{"password": p.Password})
	if err := p.request(client, http.MethodPost, "auth", body, &answer); err != nil {
		if errors.Is(err, errPiHoleSession) {
			return errors.New("the password is refused. With two-factor authentication, give an application password, from Settings, Web interface / API")
		}
		return fmt.Errorf("failed to log in: %w", err)
	}
	if !answer.Session.Valid || answer.Session.SID == "" {
		return errors.New("the password is refused. With two-factor authentication, give an application password, from Settings, Web interface / API")
	}
	p.sid = answer.Session.SID
	return nil
}

// request makes one request of the API, and reads its answer into out when there is where to.
// An answer that refuses is an error with its status and what Pi-hole says.
func (p *PiHole) request(client *http.Client, method, path string, body []byte, out any) error {
	u, err := url.Parse(p.Address)
	if err != nil {
		return err
	}
	// The entry of a record is in the path, escaped: the path is kept as it is written.
	base := strings.TrimSuffix(u.EscapedPath(), "/")
	u.RawPath = base + "/api/" + path
	if u.Path, err = url.PathUnescape(u.RawPath); err != nil {
		return err
	}

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, u.String(), reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if p.sid != "" {
		req.Header.Set("X-FTL-SID", p.sid)
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
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return errPiHoleSession
	case method == http.MethodDelete && resp.StatusCode == http.StatusNotFound:
		return nil // Already gone
	case resp.StatusCode >= 300:
		var refused struct {
			Error struct {
				Key     string `json:"key"`
				Message string `json:"message"`
				Hint    any    `json:"hint"`
			} `json:"error"`
		}
		if json.Unmarshal(answer, &refused) != nil || refused.Error.Message == "" {
			return fmt.Errorf("HTTP %s: not an answer of Pi-hole's API, which is of its version 6 and later", resp.Status)
		}
		if hint, ok := refused.Error.Hint.(string); ok && hint != "" {
			return fmt.Errorf("HTTP %s: %s (%s)", resp.Status, refused.Error.Message, hint)
		}
		return fmt.Errorf("HTTP %s: %s", resp.Status, refused.Error.Message)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(answer, out); err != nil {
		return fmt.Errorf("HTTP %s: not an answer of Pi-hole's API, which is of its version 6 and later: %w", resp.Status, err)
	}
	return nil
}

// Domain is the name as the records have it: in lower case, without the final dot.
func (p *PiHole) Domain(hostname string) string {
	return lowerASCII(FQDN(hostname, p.Zone))
}
