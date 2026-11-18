package ddns

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/duration"
	"github.com/miguelangel-nubla/ipv6disc"
	"golang.org/x/crypto/ssh"
)

type WindowsDNS struct {
	Zone     string            `json:"zone"`
	Address  string            `json:"address"` // Optional: if set, use SSH
	Username string            `json:"username"`
	Password string            `json:"password"`
	SSHKey   string            `json:"ssh_key"`
	TTL      duration.Duration `json:"ttl"`
}

func init() {
	RegisterProvider("windows", NewWindowsDNS)
}

func NewWindowsDNS(settings json.RawMessage) (Service, error) {
	var service WindowsDNS
	if err := decodeSettings(settings, windowsSettingsSchema, &service); err != nil {
		return nil, err
	}
	return &service, nil
}

const windowsSettingsSchema = `
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
	`

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

	zone := psQuote(w.Zone)
	name := psQuote(windowsRecordName(hostname))

	// 1. Get current IPs (both A and AAAA)
	psScript := fmt.Sprintf(`
try {
    $output = @()
    $rA = Get-DnsServerResourceRecord -ZoneName %s -Name %s -RRType A -ErrorAction SilentlyContinue 
    if ($rA) { $output += $rA | Select-Object -ExpandProperty RecordData | Select-Object -ExpandProperty IPv4Address | ForEach-Object { "$_" } }
    
    $rAAAA = Get-DnsServerResourceRecord -ZoneName %s -Name %s -RRType AAAA -ErrorAction SilentlyContinue 
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
`, zone, name, zone, name)

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
	desiredIPs := desiredRecords(addrCollection)

	existingMap := make(map[string]bool)
	for _, ip := range currentIPs {
		if ip, ok := canonicalIP(ip); ok {
			existingMap[ip] = true
		}
	}

	var toAdd []string
	var toDelete []string

	for ip := range desiredIPs {
		if !existingMap[ip] {
			toAdd = append(toAdd, ip)
		}
	}

	for ip := range existingMap {
		if _, ok := desiredIPs[ip]; !ok {
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

		cmd := fmt.Sprintf("Remove-DnsServerResourceRecord -ZoneName %s -Name %s -RRType %s -RecordData '%s' -Force", zone, name, rrType, ip)
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

		cmd := fmt.Sprintf("Add-DnsServerResourceRecord -ZoneName %s -Name %s %s %s '%s'", zone, name, typeSwitch, ipParam, ip)

		if w.TTL.Duration > 0 {
			cmd += fmt.Sprintf(" -TimeToLive '%s'", timeSpan(w.TTL.Duration))
		}
		if out, err := runner.RunPS(cmd); err != nil {
			return fmt.Errorf("failed to add record %s: %v, output: %s", ip, err, string(out))
		}
	}

	return nil
}

func (w *WindowsDNS) Domain(hostname string) string {
	return FQDN(hostname, w.Zone)
}

// windowsRecordName is the name of hostname's records in the zone: "@" for the zone itself.
func windowsRecordName(hostname string) string {
	if hostname == "" {
		return "@"
	}
	return hostname
}

// psQuote makes s a PowerShell string literal.
func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// timeSpan formats d as a PowerShell TimeSpan, [d.]hh:mm:ss: the hours of one can't reach 24.
func timeSpan(d time.Duration) string {
	seconds := int64(d.Seconds())
	days, seconds := seconds/86400, seconds%86400
	result := fmt.Sprintf("%02d:%02d:%02d", seconds/3600, seconds/60%60, seconds%60)
	if days > 0 {
		result = fmt.Sprintf("%d.%s", days, result)
	}
	return result
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
	client, err := dialSSH(address, username, password, keyPath)
	if err != nil {
		return nil, err
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
