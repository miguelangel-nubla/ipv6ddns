package ddns

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

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
}

func init() {
	RegisterProvider("route53", NewRoute53)
}

func NewRoute53(settings json.RawMessage) (Service, error) {
	var service Route53
	if err := decodeSettings(settings, route53SettingsSchema, &service); err != nil {
		return nil, err
	}

	return &service, nil
}

// client connects, and finds the name of the hosted zone the first time.
func (r *Route53) client(ctx context.Context) (*route53.Client, string, error) {
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(r.Region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(r.AccessKeyID, r.SecretAccessKey, "")),
	)
	if err != nil {
		return nil, "", fmt.Errorf("unable to load SDK config: %w", err)
	}
	client := route53.NewFromConfig(cfg)

	r.zoneMutex.Lock()
	defer r.zoneMutex.Unlock()
	if r.zone == "" {
		out, err := client.GetHostedZone(ctx, &route53.GetHostedZoneInput{
			Id: aws.String(r.HostedZoneID),
		})
		if err != nil {
			return nil, "", fmt.Errorf("failed to fetch hosted zone %s: %w", r.HostedZoneID, err)
		}
		r.zone = aws.ToString(out.HostedZone.Name)
	}
	return client, r.zone, nil
}

const route53SettingsSchema = `
	{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "object",
		"properties": {
			"access_key_id": {
				"type": "string",
				"minLength": 1
			},
			"secret_access_key": {
				"type": "string",
				"minLength": 1
			},
			"region": {
				"type": "string",
				"minLength": 1
			},
			"hosted_zone_id": {
				"type": "string",
				"minLength": 1
			},
			"ttl": {
				"type": "string",
				"pattern": "^([0-9]+(\\.[0-9]+)?(ns|us|µs|ms|s|m|h))+$"
			}
		},
		"required": [
			"access_key_id",
			"secret_access_key",
			"region",
			"hosted_zone_id",
			"ttl"
		]
	}
	`

func (r *Route53) Update(hostname string, addrCollection *ipv6disc.AddrCollection) error {
	ctx := context.Background()

	client, zone, err := r.client(ctx)
	if err != nil {
		return err
	}

	// Route53 expects trailing dot for FQDNs
	dnsName := FQDN(hostname, zone)
	if !strings.HasSuffix(dnsName, ".") {
		dnsName += "."
	}

	// Separate desired IPs by type
	desiredA := []string{}
	desiredAAAA := []string{}
	for _, addr := range addrCollection.Get() {
		ip := addr.WithZone("").String()
		if addr.Addr.Is4() {
			desiredA = append(desiredA, ip)
		} else {
			desiredAAAA = append(desiredAAAA, ip)
		}
	}

	changes := []types.Change{}

	// Helper to create ResourceRecord list
	toRR := func(ips []string) []types.ResourceRecord {
		rrs := []types.ResourceRecord{}
		for _, ip := range ips {
			rrs = append(rrs, types.ResourceRecord{Value: aws.String(ip)})
		}
		return rrs
	}

	// Process A records
	if len(desiredA) > 0 {
		changes = append(changes, types.Change{
			Action: types.ChangeActionUpsert,
			ResourceRecordSet: &types.ResourceRecordSet{
				Name:            aws.String(dnsName),
				Type:            types.RRTypeA,
				TTL:             aws.Int64(int64(r.TTL.Seconds())),
				ResourceRecords: toRR(desiredA),
			},
		})
	}

	// Process AAAA records
	if len(desiredAAAA) > 0 {
		changes = append(changes, types.Change{
			Action: types.ChangeActionUpsert,
			ResourceRecordSet: &types.ResourceRecordSet{
				Name:            aws.String(dnsName),
				Type:            types.RRTypeAaaa,
				TTL:             aws.Int64(int64(r.TTL.Seconds())),
				ResourceRecords: toRR(desiredAAAA),
			},
		})
	}

	// To handle deletion of records that are no longer needed, we need to list existing records for this name.
	listInput := &route53.ListResourceRecordSetsInput{
		HostedZoneId:    aws.String(r.HostedZoneID),
		StartRecordName: aws.String(dnsName),
		MaxItems:        aws.Int32(10),
	}

	output, err := client.ListResourceRecordSets(ctx, listInput)
	if err != nil {
		return fmt.Errorf("failed to list record sets: %v", err)
	}

	for _, rs := range output.ResourceRecordSets {
		if aws.ToString(rs.Name) != dnsName {
			continue
		}

		if rs.Type == types.RRTypeA && len(desiredA) == 0 {
			changes = append(changes, types.Change{
				Action:            types.ChangeActionDelete,
				ResourceRecordSet: &rs,
			})
		}
		if rs.Type == types.RRTypeAaaa && len(desiredAAAA) == 0 {
			changes = append(changes, types.Change{
				Action:            types.ChangeActionDelete,
				ResourceRecordSet: &rs,
			})
		}
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
		return fmt.Errorf("failed to change record sets: %v", err)
	}

	return nil
}

func (r *Route53) Domain(hostname string) string {
	r.zoneMutex.Lock()
	defer r.zoneMutex.Unlock()
	return FQDN(hostname, r.zone)
}
