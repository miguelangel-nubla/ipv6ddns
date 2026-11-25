package ddns

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/miguelangel-nubla/ipv6disc"
)

type DuckDNS struct {
	APIToken string `json:"api_token"`

	// The update address, for tests: empty is DuckDNS's.
	updateURL string
}

func init() {
	RegisterProvider("duckdns", NewDuckDNS)
	RegisterTXT("duckdns")
}

func NewDuckDNS(settings json.RawMessage) (Service, error) {
	var service DuckDNS
	if err := decodeSettings(settings, "duckdns", &service); err != nil {
		return nil, err
	}
	return &service, nil
}

// Update sets the name's A and AAAA records to the first address of each family. DuckDNS takes
// one of each, and fills in an IPv4 left out with the requester's, the machine running this,
// unless an IPv6 is given: it never sees an empty address, and a record of a family without
// addresses is cleared.
func (d *DuckDNS) Update(hostname string, addrCollection *ipv6disc.AddrCollection) error {
	var ipv4, ipv6 string
	if v4 := addrCollection.Filter4().Get(); len(v4) > 0 {
		ipv4 = v4[0].WithZone("").String()
	}
	if v6 := addrCollection.Filter6().Get(); len(v6) > 0 {
		ipv6 = v6[0].WithZone("").String()
	}

	clear := url.Values{"clear": {"true"}}
	if ipv4 == "" && ipv6 == "" {
		_, err := d.request(hostname, clear)
		return err
	}

	params := url.Values{}
	if ipv4 != "" {
		params.Set("ip", ipv4)
	}
	if ipv6 != "" {
		params.Set("ipv6", ipv6)
	}
	current, err := d.request(hostname, params)
	if err != nil {
		return err
	}

	// DuckDNS keeps the record of a family left out. It can only clear both: clear them, and
	// set the addresses again.
	if ipv4 == "" && current.ipv4 != "" || ipv6 == "" && current.ipv6 != "" {
		if _, err := d.request(hostname, clear); err != nil {
			return err
		}
		if _, err := d.request(hostname, params); err != nil {
			return err
		}
	}
	return nil
}

// duckDNSRecords are the addresses DuckDNS has for a name after an update.
type duckDNSRecords struct {
	ipv4, ipv6 string
}

// request runs an update with params, and returns the addresses DuckDNS has after it, from its
// verbose answer: OK, the IPv4, the IPv6, and UPDATED or NOCHANGE, a line each.
func (d *DuckDNS) request(hostname string, params url.Values) (duckDNSRecords, error) {
	baseURL := "https://www.duckdns.org/update"
	if d.updateURL != "" {
		baseURL = d.updateURL
	}
	params.Set("token", d.APIToken)
	// The name within duckdns.org, which is what DuckDNS takes: nas for nas.duckdns.org too.
	params.Set("domains", RelativeName(hostname, "duckdns.org"))
	params.Set("verbose", "true")

	resp, err := newHTTPClient(nil).Get(baseURL + "?" + params.Encode())
	if err != nil {
		return duckDNSRecords{}, fmt.Errorf("failed to update record: %w", withoutURL(err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return duckDNSRecords{}, fmt.Errorf("received non-200 status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return duckDNSRecords{}, fmt.Errorf("failed to read response body: %w", err)
	}

	lines := strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n")
	if lines[0] != "OK" {
		return duckDNSRecords{}, fmt.Errorf("update refused: %s", strings.TrimSpace(string(body)))
	}
	var records duckDNSRecords
	if len(lines) > 1 {
		records.ipv4 = strings.TrimSpace(lines[1])
	}
	if len(lines) > 2 {
		records.ipv6 = strings.TrimSpace(lines[2])
	}
	return records, nil
}

func (d *DuckDNS) Domain(hostname string) string {
	return FQDN(hostname, "duckdns.org")
}

// SetTXT keeps the TXT record of a DuckDNS name: DuckDNS has one, of the name itself, which it
// answers for every name under it too, as _acme-challenge.nas.duckdns.org. So the name given can
// be that, and one value at most is kept.
func (d *DuckDNS) SetTXT(hostname string, values []string) error {
	name := strings.TrimPrefix(RelativeName(hostname, "duckdns.org"), "_acme-challenge.")
	if i := strings.LastIndex(name, "."); i >= 0 {
		name = name[i+1:]
	}
	switch len(values) {
	case 0:
		_, err := d.request(name, url.Values{"txt": {"removed"}, "clear": {"true"}})
		return err
	case 1:
		_, err := d.request(name, url.Values{"txt": {values[0]}})
		return err
	}
	return fmt.Errorf("DuckDNS keeps one TXT record of a name, and %s would need %d", name, len(values))
}

// FullName is the name under duckdns.org.
func (d *DuckDNS) FullName(hostname string) (string, error) { return d.Domain(hostname), nil }
