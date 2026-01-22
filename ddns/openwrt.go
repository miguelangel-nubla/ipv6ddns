package ddns

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/xeipuuv/gojsonschema"
	"golang.org/x/crypto/ssh"
)

type OpenWrt struct {
	Address  string        `json:"address"`
	Username string        `json:"username"`
	Password string        `json:"password"`
	SSHKey   string        `json:"ssh_key"`
	Zone     string        `json:"zone"`
	TTL      time.Duration `json:"ttl"`
}

func init() {
	RegisterProvider("openwrt", NewOpenWrt)
}

func NewOpenWrt(settings ProviderSettings) Service {
	var service OpenWrt
	openwrtValidateConfig(settings.(json.RawMessage))
	json.Unmarshal(settings.(json.RawMessage), &service)
	return &service
}

func openwrtValidateConfig(config json.RawMessage) {
	var configSchema = []byte(`
	{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "object",
		"properties": {
			"address": {
				"type": "string",
				"minLength": 1
			},
			"username": {
				"type": "string",
				"minLength": 1
			},
			"password": {
				"type": "string"
			},
			"ssh_key": {
				"type": "string"
			},
			"zone": {
				"type": "string"
			},
			"ttl": {
				"type": "string",
				"pattern": "^([0-9]+(\\.[0-9]+)?(ns|us|µs|ms|s|m|h))+$"
			}
		},
		"required": [
			"address",
			"username",
			"zone",
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
		fmt.Printf("OpenWrt configuration is not valid.\nErrors:\n")
		for _, desc := range result.Errors() {
			fmt.Printf("- %s\n", desc)
		}
		os.Exit(1)
	}
}

func (o *OpenWrt) Update(hostname string, addrCollection *ipv6disc.AddrCollection) error {
	// 1. Establish SSH connection
	config := &ssh.ClientConfig{
		User:            o.Username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Use with caution; maybe add strict checking later if requested
		Timeout:         10 * time.Second,
	}

	if o.SSHKey != "" {
		key, err := os.ReadFile(o.SSHKey)
		if err != nil {
			return fmt.Errorf("unable to read private key: %v", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return fmt.Errorf("unable to parse private key: %v", err)
		}
		config.Auth = []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		}
	} else if o.Password != "" {
		config.Auth = []ssh.AuthMethod{
			ssh.Password(o.Password),
		}
	} else {
		return fmt.Errorf("no authentication method provided for OpenWrt")
	}

	// Default port 22 if not specified
	address := o.Address
	if !strings.Contains(address, ":") {
		address = address + ":22"
	}

	client, err := ssh.Dial("tcp", address, config)
	if err != nil {
		return fmt.Errorf("failed to dial: %v", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	// 2. Fetch current configuration
	output, err := session.CombinedOutput("uci show dhcp")
	if err != nil {
		return fmt.Errorf("failed to run uci show dhcp: %v", err)
	}
	uciOutput := string(output)

	// 3. Parse existing records
	type uciRecord struct {
		id   string
		name string
		ip   string
	}

	// Map of ID -> Record
	records := make(map[string]*uciRecord)

	fqdn := FQDN(hostname, o.Zone)

	lines := strings.Split(uciOutput, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Format: dhcp.@domain[0].option='value'
		// or dhcp.cfg123456.option='value'
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		value := strings.Trim(parts[1], "'")

		// Check if it belongs to a domain section
		if strings.HasPrefix(key, "dhcp.@domain[") || strings.Contains(key, ".name") || strings.Contains(key, ".ip") {
			// Extract ID.
			// dhcp.@domain[0]=domain  (ignore)
			// dhcp.@domain[0].name
			// dhcp.cfg123456.name

			pathParts := strings.Split(key, ".")
			if len(pathParts) < 2 {
				continue
			}
			// pathParts[0] is 'dhcp'
			// pathParts[1] is ID (e.g. @domain[0] or cfg...)
			id := pathParts[1]

			if _, ok := records[id]; !ok {
				records[id] = &uciRecord{id: id}
			}

			if len(pathParts) == 3 {
				// dhcp.ID.field
				field := pathParts[2]
				switch field {
				case "name":
					records[id].name = value
				case "ip":
					records[id].ip = value
				}
			}
		}
	}

	// Filter records that match our hostname
	existingIPs := make(map[string]string) // IP -> ID
	var idsToDelete []string

	for id, rec := range records {
		if rec.name == fqdn && rec.ip != "" {
			if _, err := netip.ParseAddr(rec.ip); err == nil {
				existingIPs[rec.ip] = id
			}
		}
	}

	desiredIPs := make(map[string]bool)
	for _, addr := range addrCollection.Get() {
		ip := addr.WithZone("").String()
		desiredIPs[ip] = true
	}

	// 4. Calculate diff
	// IPs to delete
	for ip, id := range existingIPs {
		if !desiredIPs[ip] {
			idsToDelete = append(idsToDelete, id)
		}
	}

	// IPs to add
	var ipsToAdd []string
	for ip := range desiredIPs {
		if _, exists := existingIPs[ip]; !exists {
			ipsToAdd = append(ipsToAdd, ip)
		}
	}

	if len(idsToDelete) == 0 && len(ipsToAdd) == 0 {
		return nil // No changes needed
	}

	// 5. Apply changes
	// We execute commands sequentially to ensure reliability and capture proper IDs from uci add.
	// Helper to run a command and return output
	runCmd := func(cmd string) (string, error) {
		session, err := client.NewSession()
		if err != nil {
			return "", fmt.Errorf("failed to create session: %v", err)
		}
		defer session.Close()

		output, err := session.CombinedOutput(cmd)
		if err != nil {
			return string(output), fmt.Errorf("command %s failed: %v, output: %s", cmd, err, string(output))
		}
		return string(output), nil
	}

	for _, id := range idsToDelete {
		if _, err := runCmd(fmt.Sprintf("uci delete dhcp.%s", id)); err != nil {
			return err
		}
	}

	for _, ip := range ipsToAdd {
		// Create deterministic ID
		hash := sha256.Sum256([]byte(fqdn + ip))
		id := "ipv6ddns_" + hex.EncodeToString(hash[:])[:8]

		// Add new section (named)
		if _, err := runCmd(fmt.Sprintf("uci set dhcp.%s=domain", id)); err != nil {
			return err
		}
		if _, err := runCmd(fmt.Sprintf("uci set dhcp.%s.name='%s'", id, fqdn)); err != nil {
			return err
		}
		if _, err := runCmd(fmt.Sprintf("uci set dhcp.%s.ip='%s'", id, ip)); err != nil {
			return err
		}
	}

	if _, err := runCmd("uci commit dhcp"); err != nil {
		return err
	}
	if _, err := runCmd("/etc/init.d/dnsmasq reload"); err != nil {
		return err
	}

	return nil
}

func (o *OpenWrt) PrettyPrint(prefix string) ([]byte, error) {
	return json.MarshalIndent(o, prefix, "    ")
}

func (o *OpenWrt) UnmarshalJSON(b []byte) error {
	type Alias OpenWrt
	aux := &struct {
		TTL interface{} `json:"ttl"`
		*Alias
	}{
		Alias: (*Alias)(o),
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}

	switch value := aux.TTL.(type) {
	case float64:
		o.TTL = time.Duration(value) * time.Second
		return nil
	case string:
		var err error
		o.TTL, err = time.ParseDuration(value)
		if err != nil {
			return err
		}
		return nil
	default:
		return errors.New("ttl invalid duration")
	}
}

func (o *OpenWrt) MarshalJSON() ([]byte, error) {
	type Alias OpenWrt
	return json.Marshal(&struct {
		TTL int64 `json:"ttl"`
		*Alias
	}{
		TTL:   int64(o.TTL.Seconds()),
		Alias: (*Alias)(o),
	})
}

func (o *OpenWrt) Domain(hostname string) string {
	return FQDN(hostname, o.Zone)
}
