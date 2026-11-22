package ddns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/miguelangel-nubla/ipv6ddns/ddns/gravity"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/duration"
	"github.com/miguelangel-nubla/ipv6disc"
)

type Gravity struct {
	Server string `json:"server"`
	APIKey string `json:"api_key"`
	Zone   string `json:"zone"`
	// The TTL of the records: gravityDefaultTTL without one. Gravity has it per record since
	// v0.32, and needs it there.
	TTL duration.Duration `json:"ttl"`
}

// gravityDefaultTTL is the TTL of the records when the settings have none: they could, before
// Gravity had one per record.
const gravityDefaultTTL = 5 * time.Minute

// gravityRecordName is the name of hostname's records within the zone, as Gravity keeps them: in
// lower case, and "@" for the zone itself. Gravity puts a record under its name in lower case and
// lists those of the name as given: under another case it would find none, update after update,
// and add them all again. Without a name, it lists the records of the whole zone.
func gravityRecordName(hostname, zone string) string {
	if name := RelativeName(hostname, zone); name != "" {
		return strings.ToLower(name)
	}
	return "@"
}

func init() {
	RegisterProvider("gravity", NewGravity)
}

func NewGravity(settings json.RawMessage) (Service, error) {
	var service Gravity
	if err := decodeSettings(settings, "gravity", &service); err != nil {
		return nil, err
	}
	return &service, nil
}

func (g *Gravity) Update(hostname string, addrCollection *ipv6disc.AddrCollection) error {
	requestEditors := []gravity.RequestEditorFn{
		func(ctx context.Context, req *http.Request) error {
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", g.APIKey))
			return nil
		},
	}
	apiClient, err := gravity.NewClientWithResponses(g.Server, gravity.WithHTTPClient(newHTTPClient(nil)))
	if err != nil {
		return fmt.Errorf("failed to create gravity client: %v", err)
	}

	name := gravityRecordName(hostname, g.Zone)
	ttl := int64(g.TTL.Seconds())
	if ttl <= 0 {
		ttl = int64(gravityDefaultTTL.Seconds())
	}

	params := gravity.DnsGetRecordsParams{
		Zone:     &g.Zone,
		Hostname: &name,
	}
	currentRecords, err := apiClient.DnsGetRecordsWithResponse(context.Background(), &params, requestEditors...)
	if err != nil {
		return fmt.Errorf("failed to call current records: %v", err)
	}

	if currentRecords.JSON200 == nil {
		return fmt.Errorf("failed to get current records: %v", currentRecords.Status())
	}

	// The A and AAAA records of the name: a listing with those of other names, as that of the
	// whole zone, is not taken as its own.
	var records []gravity.DnsAPIRecord
	if currentRecords.JSON200.Records != nil {
		for _, record := range *currentRecords.JSON200.Records {
			if strings.EqualFold(record.Hostname, name) && (record.Type == gravity.A || record.Type == gravity.AAAA) {
				records = append(records, record)
			}
		}
	}
	// A Gravity before v0.32 tells no TTL, and has none to fix.
	tellsTTL := bytes.Contains(currentRecords.Body, []byte(`"ttl"`))

	put := func(uid string, recordType gravity.TypesDNSRecordType, ip string) error {
		response, err := apiClient.DnsPutRecordsWithResponse(
			context.Background(),
			&gravity.DnsPutRecordsParams{
				Zone:     g.Zone,
				Hostname: name,
				Uid:      &uid,
			},
			gravity.DnsPutRecordsJSONRequestBody{
				Type: recordType,
				Data: ip,
				Ttl:  ttl,
			},
			requestEditors...,
		)
		if err != nil {
			return fmt.Errorf("failed to call create DNS record: %v", err)
		}
		if response.StatusCode() < 200 || response.StatusCode() >= 300 {
			return fmt.Errorf("failed to create DNS record: %v", response.Status())
		}
		return nil
	}

	// Build a set of current IP addresses
	currentIPs := make(map[string]bool)
	for _, record := range records {
		ip, ok := canonicalIP(record.Data)
		if !ok {
			return fmt.Errorf("invalid existing record found: %s", record.Data)
		}
		currentIPs[ip] = true
	}

	// Build a set of desired IP addresses
	desiredIPs := desiredRecords(addrCollection)

	// Create records as necessary
	for ip, recordType := range desiredIPs {
		if !currentIPs[ip] {
			if err := put(uuid.New().String(), gravity.TypesDNSRecordType(recordType), ip); err != nil {
				return err
			}
		}
	}

	// Update or delete records as necessary: of an address wanted, the first record is kept, and
	// its duplicates deleted.
	kept := make(map[string]bool)
	for _, record := range records {
		ip, _ := canonicalIP(record.Data)
		if _, exists := desiredIPs[ip]; exists && !kept[ip] {
			kept[ip] = true
			// Put again, a record with another TTL is replaced.
			if tellsTTL && record.Ttl != ttl {
				if err := put(record.Uid, record.Type, record.Data); err != nil {
					return err
				}
			}
			continue
		}

		// Delete the DNS record
		response, err := apiClient.DnsDeleteRecordsWithResponse(
			context.Background(),
			&gravity.DnsDeleteRecordsParams{
				Zone:     g.Zone,
				Hostname: name,
				Type:     record.Type,
				Uid:      record.Uid,
			},
			requestEditors...,
		)
		if err != nil {
			return fmt.Errorf("failed to call delete DNS record: %v", err)
		}

		if response.StatusCode() < 200 || response.StatusCode() >= 300 {
			return fmt.Errorf("failed to delete DNS record: %v", response.Status())
		}
	}

	return nil
}

func (g *Gravity) Domain(hostname string) string {
	return FQDN(hostname, g.Zone)
}
