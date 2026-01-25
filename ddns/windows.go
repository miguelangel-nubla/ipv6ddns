package ddns

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/xeipuuv/gojsonschema"
	"golang.org/x/crypto/ssh"
)

type WindowsDNS struct {
	Zone     string        `json:"zone"`
	Address  string        `json:"address"` // Optional: if set, use SSH
	Username string        `json:"username"`
	Password string        `json:"password"`
	SSHKey   string        `json:"ssh_key"`
	TTL      time.Duration `json:"ttl"`
}

func init() {
	RegisterProvider("windows", NewWindowsDNS)
}

func NewWindowsDNS(settings ProviderSettings) Service {
	var service WindowsDNS
	windowsValidateConfig(settings.(json.RawMessage))
	json.Unmarshal(settings.(json.RawMessage), &service)
	return &service
}

func windowsValidateConfig(config json.RawMessage) {
	var configSchema = []byte(`
	{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "object",
		"properties": {
			"zone": { "type": "string", "minLength": 1 },
			"address": { "type": "string" },
			"username": { "type": "string" },
			"password": { "type": "string" },
			"ssh_key": { "type": "string" },
			"ttl": {
				"type": "string",
				"pattern": "^([0-9]+(\\.[0-9]+)?(ns|us|µs|ms|s|m|h))+$"
			}
		},
		"required": [ "zone" ]
	}
	`)

	schemaLoader := gojsonschema.NewBytesLoader(configSchema)
	dataLoader := gojsonschema.NewBytesLoader([]byte(config))

	result, err := gojsonschema.Validate(schemaLoader, dataLoader)
	if err != nil {
		panic(err.Error())
	}

	if !result.Valid() {
		fmt.Printf("Windows configuration is not valid.\nErrors:\n")
		for _, desc := range result.Errors() {
			fmt.Printf("- %s\n", desc)
		}
		os.Exit(1)
	}
}

func (w *WindowsDNS) Update(hostname string, addrCollection *ipv6disc.AddrCollection) error {
	var runner WindowsRunner
	var err error

	if w.Address != "" {
		runner, err = NewSSHRunner(w.Address, w.Username, w.Password, w.SSHKey)
	} else {
		runner = &LocalRunner{}
	}
	if err != nil {
		return err
	}
	defer runner.Close()

	// 1. Get current IPs (both A and AAAA)
	psScript := fmt.Sprintf(`
try {
    $output = @()
    $rA = Get-DnsServerResourceRecord -ZoneName '%s' -Name '%s' -RRType A -ErrorAction SilentlyContinue 
    if ($rA) { $output += $rA | Select-Object -ExpandProperty RecordData | Select-Object -ExpandProperty IPv4Address | ForEach-Object { "$_" } }
    
    $rAAAA = Get-DnsServerResourceRecord -ZoneName '%s' -Name '%s' -RRType AAAA -ErrorAction SilentlyContinue 
    if ($rAAAA) { $output += $rAAAA | Select-Object -ExpandProperty RecordData | Select-Object -ExpandProperty IPv6Address | ForEach-Object { "$_" } }

    if ($output.Count -gt 0) {
        $output | ConvertTo-Json -Compress
    } else {
        Write-Output "[]"
    }
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
`, w.Zone, hostname, w.Zone, hostname)

	output, err := runner.RunPS(psScript)
	if err != nil {
		return fmt.Errorf("failed to get records: %v, output: %s", err, string(output))
	}

	var currentIPs []string
	trimmedOutput := strings.TrimSpace(string(output))
	if trimmedOutput != "" && trimmedOutput != "null" {
		// Can be string or array of strings
		if strings.HasPrefix(trimmedOutput, "[") {
			if err := json.Unmarshal([]byte(trimmedOutput), &currentIPs); err != nil {
				return fmt.Errorf("failed to parse array json: %v, output: %s", err, trimmedOutput)
			}
		} else {
			var ip string
			if err := json.Unmarshal([]byte(trimmedOutput), &ip); err != nil {
				return fmt.Errorf("failed to parse string json: %v, output: %s", err, trimmedOutput)
			}
			currentIPs = append(currentIPs, ip)
		}
	}

	// 2. Calculate Diff
	desiredIPs := make(map[string]bool)
	for _, addr := range addrCollection.Get() {
		desiredIPs[addr.WithZone("").String()] = true
	}

	existingMap := make(map[string]bool)
	for _, ip := range currentIPs {
		existingMap[ip] = true
	}

	var toAdd []string
	var toDelete []string

	for ip := range desiredIPs {
		if !existingMap[ip] {
			toAdd = append(toAdd, ip)
		}
	}

	for ip := range existingMap {
		if !desiredIPs[ip] {
			toDelete = append(toDelete, ip)
		}
	}

	if len(toAdd) == 0 && len(toDelete) == 0 {
		return nil
	}

	// 3. Apply Changes
	for _, ip := range toDelete {
		ipAddr, err := netip.ParseAddr(ip)
		if err != nil {
			return fmt.Errorf("failed to parse IP %s for deletion: %v", ip, err)
		}

		var rrType string
		if ipAddr.Is4() {
			rrType = "A"
		} else {
			rrType = "AAAA"
		}

		cmd := fmt.Sprintf("Remove-DnsServerResourceRecord -ZoneName '%s' -Name '%s' -RRType %s -RecordData '%s' -Force", w.Zone, hostname, rrType, ip)
		if out, err := runner.RunPS(cmd); err != nil {
			return fmt.Errorf("failed to delete record %s: %v, output: %s", ip, err, string(out))
		}
	}

	for _, ip := range toAdd {
		ipAddr, err := netip.ParseAddr(ip)
		if err != nil {
			return fmt.Errorf("failed to parse IP %s for addition: %v", ip, err)
		}

		var typeSwitch string
		var ipParam string

		if ipAddr.Is4() {
			typeSwitch = "-A"
			ipParam = "-IPv4Address"
		} else {
			typeSwitch = "-Aaaa"
			ipParam = "-IPv6Address"
		}

		cmd := fmt.Sprintf("Add-DnsServerResourceRecord -ZoneName '%s' -Name '%s' %s %s '%s'", w.Zone, hostname, typeSwitch, ipParam, ip)

		if w.TTL > 0 {
			ttlStr := fmt.Sprintf("%02d:%02d:%02d", int(w.TTL.Hours()), int(w.TTL.Minutes())%60, int(w.TTL.Seconds())%60)
			cmd += fmt.Sprintf(" -TimeToLive '%s'", ttlStr)
		}
		if out, err := runner.RunPS(cmd); err != nil {
			return fmt.Errorf("failed to add record %s: %v, output: %s", ip, err, string(out))
		}
	}

	return nil
}

func (w *WindowsDNS) PrettyPrint(prefix string) ([]byte, error) {
	return json.MarshalIndent(w, prefix, "    ")
}

func (w *WindowsDNS) Domain(hostname string) string {
	return FQDN(hostname, w.Zone)
}

func (w *WindowsDNS) UnmarshalJSON(b []byte) error {
	type Alias WindowsDNS
	aux := &struct {
		TTL interface{} `json:"ttl"`
		*Alias
	}{
		Alias: (*Alias)(w),
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}

	switch value := aux.TTL.(type) {
	case float64:
		w.TTL = time.Duration(value) * time.Second
		return nil
	case string:
		var err error
		w.TTL, err = time.ParseDuration(value)
		if err != nil {
			return err
		}
		return nil
	default:
		// If TTL is missing (nil), it defaults to 0 duration, which is fine
		if value == nil {
			return nil
		}
		return fmt.Errorf("ttl invalid type")
	}
}

func (w *WindowsDNS) MarshalJSON() ([]byte, error) {
	type Alias WindowsDNS
	return json.Marshal(&struct {
		TTL int64 `json:"ttl"`
		*Alias
	}{
		TTL:   int64(w.TTL.Seconds()),
		Alias: (*Alias)(w),
	})
}

type WindowsRunner interface {
	RunPS(psScript string) ([]byte, error)
	Close() error
}

func preparePowerShellCommand(psScript string) (string, error) {
	// Disable progress bars and other noisy streams
	fullScript := "$ProgressPreference = 'SilentlyContinue'; $InformationPreference = 'SilentlyContinue'; " + psScript

	// PowerShell expects UTF-16LE encoding for -EncodedCommand
	runes := []rune(fullScript)
	utf16Encoded := utf16.Encode(runes)

	// Convert uint16 slice to byte slice (Little Endian)
	bytes := make([]byte, len(utf16Encoded)*2)
	for i, v := range utf16Encoded {
		bytes[i*2] = byte(v)
		bytes[i*2+1] = byte(v >> 8)
	}

	return base64.StdEncoding.EncodeToString(bytes), nil
}

type LocalRunner struct{}

func (l *LocalRunner) RunPS(psScript string) ([]byte, error) {
	encoded, err := preparePowerShellCommand(psScript)
	if err != nil {
		return nil, fmt.Errorf("failed to encode powershell command: %v", err)
	}

	// Try pwsh (Powershell Core) first, then powershell
	bin := "powershell"
	if _, err := exec.LookPath("pwsh"); err == nil {
		bin = "pwsh"
	}

	command := exec.Command(bin, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded)
	// Capture stderr independently
	var stderr bytes.Buffer
	command.Stderr = &stderr

	stdout, err := command.Output()
	if err != nil {
		// ExitError often contains no message, so we add stderr
		return stdout, fmt.Errorf("command failed: %v, stderr: %s", err, stderr.String())
	}
	return stdout, nil
}

func (l *LocalRunner) Close() error {
	return nil
}

type SSHRunner struct {
	client *ssh.Client
}

func NewSSHRunner(address, username, password, keyPath string) (*SSHRunner, error) {
	config := &ssh.ClientConfig{
		User:            username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	if keyPath != "" {
		key, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("unable to read private key: %v", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("unable to parse private key: %v", err)
		}
		config.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	} else if password != "" {
		config.Auth = []ssh.AuthMethod{ssh.Password(password)}
	} else {
		return nil, fmt.Errorf("no authentication method provided for SSH")
	}

	// Default port 22
	if !strings.Contains(address, ":") {
		address = address + ":22"
	}

	client, err := ssh.Dial("tcp", address, config)
	if err != nil {
		return nil, fmt.Errorf("failed to dial ssh: %v", err)
	}

	return &SSHRunner{client: client}, nil
}

func (s *SSHRunner) RunPS(psScript string) ([]byte, error) {
	session, err := s.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	encoded, err := preparePowerShellCommand(psScript)
	if err != nil {
		return nil, fmt.Errorf("failed to encode powershell command: %v", err)
	}

	cmd := fmt.Sprintf("powershell -NoProfile -NonInteractive -EncodedCommand %s", encoded)

	// Separate stdout/stderr
	var stderr bytes.Buffer
	session.Stderr = &stderr

	stdout, err := session.Output(cmd)
	if err != nil {
		return stdout, fmt.Errorf("ssh command failed: %v, stderr: %s", err, stderr.String())
	}
	return stdout, nil
}

func (s *SSHRunner) Close() error {
	return s.client.Close()
}
