package ddns

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/duration"
	"github.com/miguelangel-nubla/ipv6disc"
)

type Route53 struct {
	AccessKeyID     string            `json:"access_key_id"`
	SecretAccessKey string            `json:"secret_access_key"`
	Region          string            `json:"region"`
	HostedZoneID    string            `json:"hosted_zone_id"`
	TTL             duration.Duration `json:"ttl"`

	// The name of the hosted zone, known after the first update.
	zone      string
	zoneMutex sync.Mutex

	// The API's address, for tests: empty is AWS's.
	endpoint string
}

// route53Name compares as the names Route53 returns: in lower case, with a wildcard escaped as
// \052, and ending in a dot.
func route53Name(name string) string {
	name = strings.ToLower(strings.ReplaceAll(name, `\052`, "*"))
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

func init() {
	RegisterProvider("route53", NewRoute53)
}

func NewRoute53(settings json.RawMessage) (Service, error) {
	var service Route53
	if err := decodeSettings(settings, "route53", &service); err != nil {
		return nil, err
	}

	return &service, nil
}

// client connects, and finds the name of the hosted zone the first time.
func (r *Route53) client(ctx context.Context) (*route53.Client, string, error) {
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(r.Region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(r.AccessKeyID, r.SecretAccessKey, "")),
		// The SDK's own client waits for an answer without a limit. With this one, a request
		// without an answer ends at httpTimeout, and the SDK tries it again.
		config.WithHTTPClient(newHTTPClient(nil)),
	)
	if err != nil {
		return nil, "", fmt.Errorf("unable to load SDK config: %w", err)
	}
	client := route53.NewFromConfig(cfg, func(o *route53.Options) {
		if r.endpoint != "" {
			o.BaseEndpoint = aws.String(r.endpoint)
		}
	})

	// The lock is not held while asking: Domain, which the status page calls, would wait for
	// the answer.
	r.zoneMutex.Lock()
	zone := r.zone
	r.zoneMutex.Unlock()
	if zone == "" {
		out, err := client.GetHostedZone(ctx, &route53.GetHostedZoneInput{
			Id: aws.String(r.HostedZoneID),
		})
		if err != nil {
			return nil, "", fmt.Errorf("failed to fetch hosted zone %s: %w", r.HostedZoneID, err)
		}
		zone = aws.ToString(out.HostedZone.Name)
		r.zoneMutex.Lock()
		r.zone = zone
		r.zoneMutex.Unlock()
	}
	return client, zone, nil
}

func (r *Route53) Update(hostname string, addrCollection *ipv6disc.AddrCollection) error {
	// The requests have their timeout each, and the update this one: the SDK tries a request that
	// fails or times out again.
	ctx, cancel := context.WithTimeout(context.Background(), updateTimeout)
	defer cancel()

	client, zone, err := r.client(ctx)
	if err != nil {
		return err
	}

	// Route53 expects trailing dot for FQDNs
	dnsName := FQDN(hostname, zone)
	if !strings.HasSuffix(dnsName, ".") {
		dnsName += "."
	}

	ttl := int64(r.TTL.Seconds())

	// The record sets of the name, by type. The listing starts at the name, and ten sets are
	// enough for one with a set per type, of the few types a name has. A name with weighted or
	// latency sets, several per type, is not one to update here.
	output, err := client.ListResourceRecordSets(ctx, &route53.ListResourceRecordSetsInput{
		HostedZoneId:    aws.String(r.HostedZoneID),
		StartRecordName: aws.String(dnsName),
		MaxItems:        aws.Int32(10),
	})
	if err != nil {
		return fmt.Errorf("failed to list record sets: %w", err)
	}
	current := make(map[types.RRType]types.ResourceRecordSet)
	for _, rs := range output.ResourceRecordSets {
		if route53Name(aws.ToString(rs.Name)) == route53Name(dnsName) && (rs.Type == types.RRTypeA || rs.Type == types.RRTypeAaaa) {
			current[rs.Type] = rs
		}
	}

	desired := map[types.RRType][]string{}
	for ip, recordType := range desiredRecords(addrCollection) {
		desired[types.RRType(recordType)] = append(desired[types.RRType(recordType)], ip)
	}

	var changes []types.Change
	for _, rrType := range []types.RRType{types.RRTypeA, types.RRTypeAaaa} {
		ips := desired[rrType]
		slices.Sort(ips)
		existing, exists := current[rrType]

		if len(ips) == 0 {
			if exists {
				changes = append(changes, types.Change{Action: types.ChangeActionDelete, ResourceRecordSet: &existing})
			}
			continue
		}

		var existingIPs []string
		for _, rr := range existing.ResourceRecords {
			if ip, ok := canonicalIP(aws.ToString(rr.Value)); ok {
				existingIPs = append(existingIPs, ip)
			}
		}
		slices.Sort(existingIPs)
		if exists && slices.Equal(ips, existingIPs) && aws.ToInt64(existing.TTL) == ttl {
			continue
		}

		var records []types.ResourceRecord
		for _, ip := range ips {
			records = append(records, types.ResourceRecord{Value: aws.String(ip)})
		}
		changes = append(changes, types.Change{
			Action: types.ChangeActionUpsert,
			ResourceRecordSet: &types.ResourceRecordSet{
				Name:            aws.String(dnsName),
				Type:            rrType,
				TTL:             aws.Int64(ttl),
				ResourceRecords: records,
			},
		})
	}

	if len(changes) == 0 {
		return nil
	}

	input := &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(r.HostedZoneID),
		ChangeBatch: &types.ChangeBatch{
			Changes: changes,
		},
	}

	_, err = client.ChangeResourceRecordSets(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to change record sets: %w", err)
	}

	return nil
}

func (r *Route53) Domain(hostname string) string {
	r.zoneMutex.Lock()
	defer r.zoneMutex.Unlock()
	return FQDN(hostname, r.zone)
}

// SetTXT makes the TXT records of hostname the values, in one change, and returns once Route 53
// says its servers have it, as it does within a minute or so.
func (r *Route53) SetTXT(hostname string, values []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), updateTimeout)
	defer cancel()
	client, zone, err := r.client(ctx)
	if err != nil {
		return err
	}
	dnsName := route53Name(FQDN(hostname, zone))
	output, err := client.ListResourceRecordSets(ctx, &route53.ListResourceRecordSetsInput{
		HostedZoneId:    aws.String(r.HostedZoneID),
		StartRecordName: aws.String(dnsName),
		StartRecordType: types.RRTypeTxt,
		MaxItems:        aws.Int32(1),
	})
	if err != nil {
		return fmt.Errorf("failed to list record sets: %w", err)
	}
	var existing *types.ResourceRecordSet
	for _, rs := range output.ResourceRecordSets {
		if route53Name(aws.ToString(rs.Name)) == dnsName && rs.Type == types.RRTypeTxt {
			existing = &rs
		}
	}
	var change types.Change
	switch {
	case len(values) == 0 && existing == nil:
		return nil
	case len(values) == 0:
		change = types.Change{Action: types.ChangeActionDelete, ResourceRecordSet: existing}
	default:
		var records []types.ResourceRecord
		for _, v := range values {
			records = append(records, types.ResourceRecord{Value: aws.String(`"` + v + `"`)})
		}
		change = types.Change{Action: types.ChangeActionUpsert, ResourceRecordSet: &types.ResourceRecordSet{
			Name: aws.String(dnsName), Type: types.RRTypeTxt, TTL: aws.Int64(txtTTL), ResourceRecords: records,
		}}
	}
	out, err := client.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(r.HostedZoneID),
		ChangeBatch:  &types.ChangeBatch{Changes: []types.Change{change}},
	})
	if err != nil {
		return fmt.Errorf("failed to change the TXT records of %s: %w", dnsName, err)
	}
	if out.ChangeInfo == nil || out.ChangeInfo.Status == types.ChangeStatusInsync {
		return nil
	}
	deadline, _ := ctx.Deadline()
	waiter := route53.NewResourceRecordSetsChangedWaiter(client)
	if err := waiter.Wait(ctx, &route53.GetChangeInput{Id: out.ChangeInfo.Id}, time.Until(deadline)); err != nil {
		return fmt.Errorf("the TXT records of %s were changed, but Route 53 doesn't say its servers have them: %w", dnsName, err)
	}
	return nil
}

// FullName is the name in the hosted zone, whose name AWS is asked for if it isn't known yet.
func (r *Route53) FullName(hostname string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), updateTimeout)
	defer cancel()
	if _, _, err := r.client(ctx); err != nil {
		return "", err
	}
	return strings.TrimSuffix(r.Domain(hostname), "."), nil
}
