package ddns

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"

	"github.com/xeipuuv/gojsonschema"
)

type Route53 struct {
	Region string `json:"region"`
	ZoneId string `json:"zone_id"`
	TTL    int64  `json:"ttl"`
}

func init() {
	RegisterProvider("route53", NewRoute53)
}

func NewRoute53(settings ProviderSettings) Service {
	var service Route53
	route53ValidateConfig(settings.(json.RawMessage))
	json.Unmarshal(settings.(json.RawMessage), &service)
	return &service
}

func route53ValidateConfig(config json.RawMessage) {
	var configSchema = []byte(`
	{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "object",
		"properties": {
			"region": {
				"type": "string",
				"minLength": 1
			},
			"zone_id": {
				"type": "string",
				"minLength": 1
			},
			"ttl": {
				"type": "integer",
				"default": 300
			}
		},
		"required": [
			"region",
			"zone_id",
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

func (d *Route53) Update(domain string, hosts []string) error {
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(d.Region))
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	svc := route53.NewFromConfig(cfg)
	input := &route53.ChangeResourceRecordSetsInput{
		ChangeBatch: &types.ChangeBatch{
			Changes: []types.Change{
				{
					Action: types.ChangeActionUpsert,
					ResourceRecordSet: &types.ResourceRecordSet{
						Name: aws.String(domain),
						ResourceRecords: []types.ResourceRecord{
							{
								Value: aws.String(hosts[0]),
							},
						},
						TTL:  aws.Int64(d.TTL),
						Type: types.RRTypeAaaa,
					},
				},
			},
			Comment: aws.String("AAAA record for " + domain + " updated by ddns"),
		},
		HostedZoneId: aws.String(d.ZoneId),
	}
	_, err = svc.ChangeResourceRecordSets(context.TODO(), input)
	if err != nil {
		log.Fatalf("unable to update resource record sets, %v", err)
	}
	return nil
}

func (d *Route53) PrettyPrint(prefix string) ([]byte, error) {
	return json.MarshalIndent(d, prefix, "    ")
}
