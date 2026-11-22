package ddns

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
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
	HostKey  string            `json:"host_key"`
	TTL      duration.Duration `json:"ttl"`

	// Runs the PowerShell commands, for tests: nil is over SSH, or locally without an address.
	newRunner func() (WindowsRunner, error)

	unverified unverifiedHostKeys
}

func (w *WindowsDNS) Warnings() []string {
	return w.unverified.Warnings()
}

func init() {
	RegisterProvider("windows", NewWindowsDNS)
}

func NewWindowsDNS(settings json.RawMessage) (Service, error) {
	var service WindowsDNS
	if err := decodeSettings(settings, "windows", &service); err != nil {
		return nil, err
	}
	return &service, nil
}

func (w *WindowsDNS) Update(hostname string, addrCollection *ipv6disc.AddrCollection) error {
	var runner WindowsRunner
	var err error

	switch {
	case w.newRunner != nil:
		runner, err = w.newRunner()
	case w.Address != "":
		var hostKey string
		runner, hostKey, err = newSSHRunner(sshTarget{w.Address, w.Username, w.Password, w.SSHKey, w.HostKey})
		if err == nil && w.HostKey == "" {
			w.unverified.note(w.Address, hostKey)
		}
	default:
		runner = newLocalRunner()
	}
	if err != nil {
		return err
	}
	defer runner.Close()

	zone := psQuote(w.Zone)
	name := psQuote(windowsRecordName(hostname, w.Zone))

	// 1. Get the current records (both A and AAAA), each as its address and its TTL in seconds.
	// -Node is for the records of the name alone: without it, those of the names under it come
	// too, as *.nas with nas, and the whole zone with @.
	psScript := fmt.Sprintf(`
try {
    $output = @()
    $rA = Get-DnsServerResourceRecord -ZoneName %s -Name %s -RRType A -Node -ErrorAction SilentlyContinue
    if ($rA) { $output += $rA | ForEach-Object { "$($_.RecordData.IPv4Address) $([int]$_.TimeToLive.TotalSeconds)" } }

    $rAAAA = Get-DnsServerResourceRecord -ZoneName %s -Name %s -RRType AAAA -Node -ErrorAction SilentlyContinue
    if ($rAAAA) { $output += $rAAAA | ForEach-Object { "$($_.RecordData.IPv6Address) $([int]$_.TimeToLive.TotalSeconds)" } }

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
		return fmt.Errorf("failed to get records: %w, output: %s", err, string(output))
	}

	var currentRecords []string
	trimmedOutput := strings.TrimSpace(string(output))
	if trimmedOutput != "" && trimmedOutput != "null" {
		// Can be string or array of strings
		if strings.HasPrefix(trimmedOutput, "[") {
			if err := json.Unmarshal([]byte(trimmedOutput), &currentRecords); err != nil {
				return fmt.Errorf("failed to parse array json: %w, output: %s", err, trimmedOutput)
			}
		} else {
			var record string
			if err := json.Unmarshal([]byte(trimmedOutput), &record); err != nil {
				return fmt.Errorf("failed to parse string json: %w, output: %s", err, trimmedOutput)
			}
			currentRecords = append(currentRecords, record)
		}
	}

	// 2. Calculate Diff
	desiredIPs := desiredRecords(addrCollection)
	// Without a TTL the records have the zone's, whatever it is.
	ttl := int(w.TTL.Seconds())

	existingMap := make(map[string]bool)
	var toAdd []string
	var toDelete []string

	for _, record := range currentRecords {
		fields := strings.Fields(record)
		if len(fields) == 0 {
			continue
		}
		ip, ok := canonicalIP(fields[0])
		if !ok || existingMap[ip] {
			continue
		}
		existingMap[ip] = true
		if _, desired := desiredIPs[ip]; !desired {
			toDelete = append(toDelete, ip)
		} else if ttl > 0 && len(fields) > 1 && fields[1] != strconv.Itoa(ttl) {
			// Another TTL than the one set: the record is made again with it.
			toDelete = append(toDelete, ip)
			toAdd = append(toAdd, ip)
		}
	}

	for ip := range desiredIPs {
		if !existingMap[ip] {
			toAdd = append(toAdd, ip)
		}
	}

	if len(toAdd) == 0 && len(toDelete) == 0 {
		return nil
	}

	// 3. Apply Changes
	for _, ip := range toDelete {
		ipAddr, err := netip.ParseAddr(ip)
		if err != nil {
			return fmt.Errorf("failed to parse IP %s for deletion: %w", ip, err)
		}

		var rrType string
		if ipAddr.Is4() {
			rrType = "A"
		} else {
			rrType = "AAAA"
		}

		cmd := fmt.Sprintf("Remove-DnsServerResourceRecord -ZoneName %s -Name %s -RRType %s -RecordData '%s' -Force", zone, name, rrType, ip)
		if out, err := runner.RunPS(cmd); err != nil {
			return fmt.Errorf("failed to delete record %s: %w, output: %s", ip, err, string(out))
		}
	}

	for _, ip := range toAdd {
		ipAddr, err := netip.ParseAddr(ip)
		if err != nil {
			return fmt.Errorf("failed to parse IP %s for addition: %w", ip, err)
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

		if ttl > 0 {
			cmd += fmt.Sprintf(" -TimeToLive '%s'", timeSpan(w.TTL.Duration))
		}
		if out, err := runner.RunPS(cmd); err != nil {
			return fmt.Errorf("failed to add record %s: %w, output: %s", ip, err, string(out))
		}
	}

	return nil
}

func (w *WindowsDNS) Domain(hostname string) string {
	return FQDN(hostname, w.Zone)
}

// windowsRecordName is the name of hostname's records within the zone, as the DNS server commands
// take it: "@" for the zone itself. A hostname given with its zone is the same name: taken as it
// is, nas.example.com would be nas.example.com.example.com.
func windowsRecordName(hostname, zone string) string {
	if name := RelativeName(hostname, zone); name != "" {
		return name
	}
	return "@"
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

// LocalRunner runs the commands of one update in a local PowerShell, within updateTimeout from
// when it is made, together: a PowerShell that hangs is killed then.
type LocalRunner struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func newLocalRunner() *LocalRunner {
	ctx, cancel := context.WithTimeout(context.Background(), updateTimeout)
	return &LocalRunner{ctx: ctx, cancel: cancel}
}

func (l *LocalRunner) RunPS(psScript string) ([]byte, error) {
	encoded, err := preparePowerShellCommand(psScript)
	if err != nil {
		return nil, fmt.Errorf("failed to encode powershell command: %w", err)
	}

	// Try pwsh (Powershell Core) first, then powershell
	bin := "powershell"
	if _, err := exec.LookPath("pwsh"); err == nil {
		bin = "pwsh"
	}

	// A PowerShell that hangs is killed, and what it started doesn't keep this waiting for its
	// output.
	ctx := l.ctx
	if ctx == nil {
		// A LocalRunner made as a literal: each command has the time.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), updateTimeout)
		defer cancel()
	}
	command := exec.CommandContext(ctx, bin, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded)
	command.WaitDelay = 5 * time.Second
	// Capture stderr independently
	var stderr bytes.Buffer
	command.Stderr = &stderr

	stdout, err := command.Output()
	if err != nil {
		if ctx.Err() != nil {
			err = fmt.Errorf("timed out after %s: %w", updateTimeout, err)
		}
		// ExitError often contains no message, so we add stderr
		return stdout, fmt.Errorf("command failed: %w, stderr: %s", err, stderr.String())
	}
	return stdout, nil
}

func (l *LocalRunner) Close() error {
	if l.cancel != nil {
		l.cancel()
	}
	return nil
}

// SSHRunner runs the commands of one update over an SSH connection, within updateTimeout.
type SSHRunner struct {
	client   *ssh.Client
	deadline *sshDeadline
}

// newSSHRunner connects to the target, and returns the fingerprint of its key.
func newSSHRunner(target sshTarget) (*SSHRunner, string, error) {
	client, hostKey, err := dialSSH(target)
	if err != nil {
		return nil, hostKey, err
	}
	return &SSHRunner{client: client, deadline: closeAfterTimeout(client)}, hostKey, nil
}

func (s *SSHRunner) RunPS(psScript string) ([]byte, error) {
	session, err := s.client.NewSession()
	if err != nil {
		return nil, s.deadline.wrap(fmt.Errorf("failed to create session: %w", err))
	}
	defer session.Close()

	encoded, err := preparePowerShellCommand(psScript)
	if err != nil {
		return nil, fmt.Errorf("failed to encode powershell command: %w", err)
	}

	cmd := fmt.Sprintf("powershell -NoProfile -NonInteractive -EncodedCommand %s", encoded)

	// Separate stdout/stderr
	var stderr bytes.Buffer
	session.Stderr = &stderr

	stdout, err := session.Output(cmd)
	if err != nil {
		return stdout, s.deadline.wrap(fmt.Errorf("ssh command failed: %w, stderr: %s", err, stderr.String()))
	}
	return stdout, nil
}

func (s *SSHRunner) Close() error {
	s.deadline.stop()
	return s.client.Close()
}
