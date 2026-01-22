package ddns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/xeipuuv/gojsonschema"
)

type Route53 struct {
	AccessKeyID     string        `json:"access_key_id"`
	SecretAccessKey string        `json:"secret_access_key"`
	Region          string        `json:"region"`
	HostedZoneID    string        `json:"hosted_zone_id"`
	TTL             time.Duration `json:"ttl"`
	zone            string
}

func init() {
	RegisterProvider("route53", NewRoute53)
}

func NewRoute53(settings ProviderSettings) Service {
	var service Route53
	route53ValidateConfig(settings.(json.RawMessage))
	json.Unmarshal(settings.(json.RawMessage), &service)

	ctx := context.TODO()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(service.Region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(service.AccessKeyID, service.SecretAccessKey, "")),
	)
	if err != nil {
		fmt.Printf("Error loading AWS config: %v\n", err)
		os.Exit(1)
	}

	client := route53.NewFromConfig(cfg)
	out, err := client.GetHostedZone(ctx, &route53.GetHostedZoneInput{
		Id: aws.String(service.HostedZoneID),
	})
	if err != nil {
		fmt.Printf("Error fetching Hosted Zone info for ID %s: %v\n", service.HostedZoneID, err)
		os.Exit(1)
	}

	service.zone = aws.ToString(out.HostedZone.Name)

	return &service
}

func route53ValidateConfig(config json.RawMessage) {
	var configSchema = []byte(`
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
	`)

	schemaLoader := gojsonschema.NewBytesLoader(configSchema)
	dataLoader := gojsonschema.NewBytesLoader([]byte(config))

	result, err := gojsonschema.Validate(schemaLoader, dataLoader)
	if err != nil {
		panic(err.Error())
	}

	if !result.Valid() {
		fmt.Printf("Route53 configuration is not valid.\nErrors:\n")
		for _, desc := range result.Errors() {
			fmt.Printf("- %s\n", desc)
		}
		os.Exit(1)
	}
}

func (r *Route53) Update(hostname string, addrCollection *ipv6disc.AddrCollection) error {
	ctx := context.Background()

	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(r.Region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(r.AccessKeyID, r.SecretAccessKey, "")),
	)
	if err != nil {
		return fmt.Errorf("unable to load SDK config, %v", err)
	}

	client := route53.NewFromConfig(cfg)

	// Route53 expects trailing dot for FQDNs
	dnsName := FQDN(hostname, r.zone)
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

func (r *Route53) PrettyPrint(prefix string) ([]byte, error) {
	return json.MarshalIndent(r, prefix, "    ")
}

func (r *Route53) UnmarshalJSON(b []byte) error {
	type Alias Route53
	aux := &struct {
		TTL interface{} `json:"ttl"`
		*Alias
	}{
		Alias: (*Alias)(r),
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}

	switch value := aux.TTL.(type) {
	case float64:
		r.TTL = time.Duration(value) * time.Second
		return nil
	case string:
		var err error
		r.TTL, err = time.ParseDuration(value)
		if err != nil {
			return err
		}
		return nil
	default:
		return errors.New("ttl invalid duration")
	}
}

func (r *Route53) MarshalJSON() ([]byte, error) {
	type Alias Route53
	return json.Marshal(&struct {
		TTL int64 `json:"ttl"`
		*Alias
	}{
		TTL:   int64(r.TTL.Seconds()),
		Alias: (*Alias)(r),
	})
}

func (r *Route53) Domain(hostname string) string {
	return FQDN(hostname, r.zone)
}
