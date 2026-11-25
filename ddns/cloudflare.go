package ddns

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/cloudflare/cloudflare-go"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/duration"
	"github.com/miguelangel-nubla/ipv6disc"
	"golang.org/x/net/idna"
)

type Cloudflare struct {
	APIToken string            `json:"api_token"`
	Zone     string            `json:"zone"`
	TTL      duration.Duration `json:"ttl"`
	Proxied  bool              `json:"proxied"`

	// The API's address, for tests: empty is Cloudflare's.
	apiBaseURL string
}

func init() {
	RegisterProvider("cloudflare", NewCloudflare)
	RegisterTXT("cloudflare")
}

func NewCloudflare(settings json.RawMessage) (Service, error) {
	var service Cloudflare
	if err := decodeSettings(settings, "cloudflare", &service); err != nil {
		return nil, err
	}
	return &service, nil
}

// session is the API, and the zone, for the requests of one update: they have updateTimeout
// together, which ctx ends.
func (c *Cloudflare) session(ctx context.Context) (*cloudflare.API, *cloudflare.ResourceContainer, error) {
	// Its own client has no timeout: with this one, a request without an answer fails the update
	// at httpTimeout, as the client doesn't try one that timed out again.
	options := []cloudflare.Option{cloudflare.HTTPClient(newHTTPClient(nil))}
	if c.apiBaseURL != "" {
		options = append(options, cloudflare.BaseURL(c.apiBaseURL))
	}
	api, err := cloudflare.NewWithAPIToken(c.APIToken, options...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize: %w", err)
	}
	// Get Zone ID: as the client's ZoneIDByName, which has no context.
	zoneName := c.Zone
	if unicode, err := idna.ToUnicode(zoneName); err == nil {
		zoneName = unicode
	}
	zones, err := api.ListZonesContext(ctx, cloudflare.WithZoneFilters(zoneName, "", ""))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read zone ID: %w", err)
	}
	if len(zones.Result) != 1 {
		return nil, nil, fmt.Errorf("failed to read zone ID: %d zones of the name %s", len(zones.Result), c.Zone)
	}
	return api, cloudflare.ZoneIdentifier(zones.Result[0].ID), nil
}

func (c *Cloudflare) Update(hostname string, addrCollection *ipv6disc.AddrCollection) error {
	// The update has this one, for all its requests: the client tries one answered with an
	// error of the server again, three times, waiting longer before each.
	ctx, cancel := context.WithTimeout(context.Background(), updateTimeout)
	defer cancel()
	api, rc, err := c.session(ctx)
	if err != nil {
		return err
	}

	fqdn := FQDN(hostname, c.Zone)
	params := cloudflare.ListDNSRecordsParams{
		Name: fqdn,
	}
	currentRecords, _, err := api.ListDNSRecords(ctx, rc, params)
	if err != nil {
		return fmt.Errorf("failed to list DNS records for %s: %w", hostname, err)
	}

	ttl := int(c.TTL.Seconds())
	desiredIPs := desiredRecords(addrCollection)

	// The address of each A and AAAA record.
	recordIPs := make(map[string]string)
	currentIPs := make(map[string]bool)
	for _, record := range currentRecords {
		if record.Type != "AAAA" && record.Type != "A" {
			continue
		}
		ip, ok := canonicalIP(record.Content)
		if !ok {
			return fmt.Errorf("invalid existing record found: %s", record.Content)
		}
		recordIPs[record.ID] = ip
		currentIPs[ip] = true
	}

	// Create the missing records first, so the name always has some.
	for ip, recordType := range desiredIPs {
		if currentIPs[ip] {
			continue
		}
		newRecord := cloudflare.CreateDNSRecordParams{
			Type:    recordType,
			Name:    fqdn,
			Content: ip,
			TTL:     ttl,
			Proxied: &c.Proxied,
		}
		if _, err := api.CreateDNSRecord(ctx, rc, newRecord); err != nil {
			return fmt.Errorf("failed to create %s DNS record for %s: %w", hostname, ip, err)
		}
	}

	// Delete the records of other addresses and duplicates, and fix the TTL and proxying of the
	// others.
	kept := make(map[string]bool)
	for _, record := range currentRecords {
		ip, ok := recordIPs[record.ID]
		if !ok {
			continue
		}
		if _, desired := desiredIPs[ip]; !desired || kept[ip] {
			if err := api.DeleteDNSRecord(ctx, rc, record.ID); err != nil {
				return fmt.Errorf("failed to delete %s DNS record for %s: %w", hostname, ip, err)
			}
			continue
		}
		kept[ip] = true

		// Cloudflare sets the TTL of a proxied record to auto, 1, itself.
		ttlDiffers := !c.Proxied && record.TTL != ttl
		if ttlDiffers || record.Proxied == nil || *record.Proxied != c.Proxied {
			updateRecord := cloudflare.UpdateDNSRecordParams{
				ID:      record.ID,
				TTL:     ttl,
				Proxied: &c.Proxied,
			}
			if _, err := api.UpdateDNSRecord(ctx, rc, updateRecord); err != nil {
				return fmt.Errorf("failed to update %s DNS record for %s: %w", hostname, ip, err)
			}
		}
	}

	return nil
}

func (c *Cloudflare) Domain(hostname string) string {
	return FQDN(hostname, c.Zone)
}

// SetTXT makes the TXT records of hostname the values: it adds the missing ones and removes the
// others. Cloudflare's API answers once its servers have them.
func (c *Cloudflare) SetTXT(hostname string, values []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), updateTimeout)
	defer cancel()
	api, rc, err := c.session(ctx)
	if err != nil {
		return err
	}
	fqdn := FQDN(hostname, c.Zone)
	current, _, err := api.ListDNSRecords(ctx, rc, cloudflare.ListDNSRecordsParams{Name: fqdn, Type: "TXT"})
	if err != nil {
		return fmt.Errorf("failed to list the TXT records of %s: %w", fqdn, err)
	}
	// Cloudflare gives a TXT record's content in quotes, or not, by the record.
	have := make(map[string]bool)
	for _, record := range current {
		if record.Type != "TXT" {
			continue
		}
		content := strings.Trim(record.Content, `"`)
		if slices.Contains(values, content) && !have[content] {
			have[content] = true
			continue
		}
		if err := api.DeleteDNSRecord(ctx, rc, record.ID); err != nil {
			return fmt.Errorf("failed to delete a TXT record of %s: %w", fqdn, err)
		}
	}
	for _, v := range values {
		if have[v] {
			continue
		}
		if _, err := api.CreateDNSRecord(ctx, rc, cloudflare.CreateDNSRecordParams{Type: "TXT", Name: fqdn, Content: v, TTL: txtTTL}); err != nil {
			return fmt.Errorf("failed to create a TXT record of %s: %w", fqdn, err)
		}
		have[v] = true
	}
	return nil
}

// FullName is Domain: the zone is known.
func (c *Cloudflare) FullName(hostname string) (string, error) { return c.Domain(hostname), nil }
