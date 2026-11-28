package ddns

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// leafFingerprint is the SHA-256 of the server's own certificate, in hex.
func leafFingerprint(cs tls.ConnectionState) (string, error) {
	if len(cs.PeerCertificates) == 0 {
		return "", errors.New("no certificates presented")
	}
	hash := sha256.Sum256(cs.PeerCertificates[0].Raw)
	return hex.EncodeToString(hash[:]), nil
}

// systemRoots replaces the system's certificates in tests: nil is the system's.
var systemRoots *x509.CertPool

// serverTLSConfig is the TLS of a device or a server of a provider at host: with a fingerprint, the
// certificate that has it alone, valid or not, as self-signed certificates are common on routers;
// without one, a certificate the system trusts for host.
func serverTLSConfig(host, fingerprint string) *tls.Config {
	if fingerprint != "" {
		return pinnedTLSConfig(fingerprint)
	}
	return verifiedTLSConfig(host)
}

// verifiedTLSConfig accepts a server certificate the system trusts for host. A failure tells the
// certificate's fingerprint, to configure.
func verifiedTLSConfig(host string) *tls.Config {
	return &tls.Config{
		// VerifyConnection does the verification, to tell the fingerprint of a failure.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			fp, err := leafFingerprint(cs)
			if err != nil {
				return fmt.Errorf("certificate verification failed: %w", err)
			}

			// No SNI is sent to an IP address, so the server name can be empty: an empty name
			// would skip the name check.
			name := cs.ServerName
			if name == "" {
				name = host
			}
			if name == "" {
				return errors.New("certificate verification failed: no server name to verify")
			}
			opts := x509.VerifyOptions{
				DNSName:       name,
				Roots:         systemRoots,
				Intermediates: x509.NewCertPool(),
			}
			for _, cert := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}
			if _, err = cs.PeerCertificates[0].Verify(opts); err == nil {
				return nil
			}
			return fmt.Errorf("certificate verification failed: %w (fingerprint: %s)", err, fp)
		},
	}
}

// pinnedTLSConfig accepts only the server certificate with the given fingerprint, whoever signed
// it and whatever names it has: one the system trusts with another fingerprint is refused too.
func pinnedTLSConfig(fingerprint string) *tls.Config {
	fingerprint = strings.ToLower(strings.ReplaceAll(fingerprint, ":", ""))
	return &tls.Config{
		// VerifyConnection checks the fingerprint instead.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			fp, err := leafFingerprint(cs)
			if err != nil {
				return err
			}
			if fp != fingerprint {
				return fmt.Errorf("certificate fingerprint mismatch: expected %s, got %s", fingerprint, fp)
			}
			return nil
		},
	}
}

// fingerprintNeedsTLS refuses a tls_fingerprint beside an address that is not https://. It would
// connect without TLS, and send the password or the key in the clear with nothing checked, to
// someone who believes the device pinned.
func fingerprintNeedsTLS(address, fingerprint string) error {
	if fingerprint == "" {
		return nil
	}
	if u, err := url.Parse(address); err == nil && u.Scheme == "https" {
		return nil
	}
	return errors.New("invalid settings: tls_fingerprint needs an address that starts with https://: without TLS there is no certificate to check")
}

// urlHost is the host of a URL, for certificate verification.
func urlHost(address string) string {
	u, err := url.Parse(address)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// The most read of an answer: of one request, and of a listing of every record of a device. More
// is none of the API's, and is not read: an answer without end would fill the memory.
const (
	answerLimit  = 1 << 20
	listingLimit = 16 << 20
)

// readAnswer reads the answer of a request, up to answerLimit.
func readAnswer(body io.Reader) []byte {
	data, _ := io.ReadAll(io.LimitReader(body, answerLimit))
	return data
}

// brief is the start of an answer, for an error: the page of a proxy, or of a wrong address, is
// not for the log whole.
func brief(answer []byte) string {
	const most = 500
	said := strings.TrimSpace(string(answer))
	if len(said) > most {
		return strings.ToValidUTF8(said[:most], "") + "..."
	}
	return said
}

// withoutURL drops the URL from an HTTP client error: the providers that take their token in the
// query would have it in their errors, and the logs.
func withoutURL(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return fmt.Errorf("%s request: %w", urlErr.Op, urlErr.Err)
	}
	return err
}

// No update goes on for ever: one that didn't return would keep its name, and the others of its
// endpoint, from being updated or tried again. Variables, for the tests to shorten.
var (
	// httpTimeout is the time a request of an update has, and a RouterOS session.
	httpTimeout = 30 * time.Second
	// updateTimeout is the time the requests of an update have together, where the provider's
	// client makes several of its own or tries again, and the commands of one, over SSH or in a
	// local PowerShell.
	updateTimeout = 2 * time.Minute
	// sshDialTimeout is the time to connect and for the SSH handshake.
	sshDialTimeout = 10 * time.Second
)

// newHTTPClient makes the client of one update. It doesn't keep connections open: nothing would
// use them again or close them, and each would stay, with its goroutines, until the server closed
// it, which the web interface of a router with few connections to give may not do soon.
func newHTTPClient(tlsConfig *tls.Config) *http.Client {
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig, DisableKeepAlives: true},
		Timeout:   httpTimeout,
	}
}

// deviceLocks has a lock for each device whose provider reads its records and then changes them
// by what it read, as a position in a list: two updates at once would change each other's.
var deviceLocks sync.Map

// lockDevice waits for the other updates of the device at address, of any credential, and returns
// what ends this one.
func lockDevice(provider, address string) (unlock func()) {
	key := provider + " " + strings.ToLower(strings.TrimRight(strings.TrimSpace(address), "/"))
	lock, _ := deviceLocks.LoadOrStore(key, &sync.Mutex{})
	mutex := lock.(*sync.Mutex)
	mutex.Lock()
	return mutex.Unlock
}

// withDefaultPort adds port to an address that has none. The address can be an IPv6 one, bracketed
// or not.
func withDefaultPort(address, port string) string {
	if _, _, err := net.SplitHostPort(address); err == nil {
		return address
	}
	return net.JoinHostPort(strings.TrimSuffix(strings.TrimPrefix(address, "["), "]"), port)
}

// sshTarget is a host to run commands on over SSH.
type sshTarget struct {
	Address  string
	Username string
	Password string
	// The path of the private key to log in with.
	KeyPath string
	// The fingerprint of a key of the host, any of them, SHA256:... as ssh-keygen -l shows it.
	// Empty accepts any.
	HostKey string
}

// errHostKeyMismatch is the error of a host that shows another key than the one expected.
var errHostKeyMismatch = errors.New("host key mismatch")

type hostKeyFamily struct {
	keyTypes   []string
	algorithms []string
}

// hostKeyFamilies are the kinds of host key, with the algorithms that make a host show its key of
// that kind.
var hostKeyFamilies = []hostKeyFamily{
	{[]string{ssh.KeyAlgoED25519}, []string{ssh.KeyAlgoED25519}},
	{[]string{ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521}, []string{ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521}},
	{[]string{ssh.KeyAlgoRSA}, []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512}},
}

// pinnedAlgorithms remembers, by address and host key, the algorithms that made the host show the
// key pinned, so that the next updates connect once.
var pinnedAlgorithms sync.Map

// dialSSH connects to the target, port 22 unless it says, with the private key and the password,
// whichever are given. It returns the fingerprint of the key the host showed, which must be the
// target's when it has one.
//
// A host with several keys shows one only, the one of the algorithm the client prefers, and a
// fingerprint doesn't tell of which kind its key is. So, as OpenSSH with its known_hosts and as
// the discovery plugins, the target's host key can be any of the host's: when the host shows
// another key, it is asked for its key of each other kind. Nothing but the handshake reaches a
// host that showed another key: neither the password nor a command.
func dialSSH(target sshTarget) (*ssh.Client, string, error) {
	var auth []ssh.AuthMethod
	if target.KeyPath != "" {
		key, err := os.ReadFile(target.KeyPath)
		if err != nil {
			return nil, "", fmt.Errorf("unable to read private key: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, "", fmt.Errorf("unable to parse private key: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if target.Password != "" {
		auth = append(auth, ssh.Password(target.Password))
	}
	if len(auth) == 0 {
		return nil, "", errors.New("no SSH authentication method: set a password or a key")
	}

	address := withDefaultPort(target.Address, "22")
	// The fingerprints of the keys shown, the one the host shows by default first, and their kinds.
	var seen, keyTypes []string
	dial := func(algorithms []string) (*ssh.Client, error) {
		return dialSSHConn(address, &ssh.ClientConfig{
			User: target.Username,
			Auth: auth,
			HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
				fingerprint := ssh.FingerprintSHA256(key)
				keyTypes = append(keyTypes, key.Type())
				if !slices.Contains(seen, fingerprint) {
					seen = append(seen, fingerprint)
				}
				if target.HostKey != "" && fingerprint != target.HostKey {
					return fmt.Errorf("%w: the host shows %s, expected %s", errHostKeyMismatch, fingerprint, target.HostKey)
				}
				return nil
			},
			HostKeyAlgorithms: algorithms,
			Timeout:           sshDialTimeout,
		})
	}
	shown := func() string {
		if len(seen) == 0 {
			return ""
		}
		return seen[0]
	}
	failed := func(err error) error {
		return fmt.Errorf("failed to dial %s: %w", target.Address, err)
	}

	if target.HostKey == "" {
		// Any key: the one the host shows by default, always the same.
		client, err := dial(nil)
		if err != nil {
			return nil, shown(), failed(err)
		}
		return client, shown(), nil
	}

	cacheKey := address + " " + target.HostKey
	// The default first: a key pinned from the warning, the one shown by default, takes one
	// connection.
	attempts := []hostKeyFamily{{}}
	if remembered, ok := pinnedAlgorithms.Load(cacheKey); ok {
		attempts = []hostKeyFamily{{algorithms: remembered.([]string)}, {}}
	}
	attempts = append(attempts, hostKeyFamilies...)

	var lastErr error
	for _, attempt := range attempts {
		if slices.ContainsFunc(attempt.keyTypes, func(keyType string) bool { return slices.Contains(keyTypes, keyType) }) {
			continue // its key of this kind was already shown
		}
		client, err := dial(attempt.algorithms)
		if err == nil {
			if attempt.algorithms != nil {
				pinnedAlgorithms.Store(cacheKey, attempt.algorithms)
			} else {
				pinnedAlgorithms.Delete(cacheKey)
			}
			return client, target.HostKey, nil
		}
		var noAlgorithm *ssh.AlgorithmNegotiationError
		switch {
		case errors.Is(err, errHostKeyMismatch):
			lastErr = err
		case attempt.algorithms != nil && errors.As(err, &noAlgorithm):
			// It has no key of this kind.
			if lastErr == nil {
				lastErr = err
			}
		default:
			// Unreachable, or past the host key, as a password refused: not to be tried again
			// with another key.
			if slices.Contains(seen, target.HostKey) {
				return nil, target.HostKey, failed(err)
			}
			return nil, shown(), failed(err)
		}
	}
	if len(seen) > 1 {
		lastErr = fmt.Errorf("%w: the host shows %s, expected %s", errHostKeyMismatch, strings.Join(seen, ", "), target.HostKey)
	}
	return nil, shown(), failed(lastErr)
}

// dialSSHConn connects as ssh.Dial does, with the timeout of the configuration for the handshake
// too: ssh.Dial has it for the connection only, and waits for ever for a host that accepts it and
// says nothing.
func dialSSHConn(address string, config *ssh.ClientConfig) (*ssh.Client, error) {
	conn, err := net.DialTimeout("tcp", address, config.Timeout)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(config.Timeout)); err != nil {
		conn.Close()
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		conn.Close()
		return nil, err
	}
	// Past the handshake, the commands have the update's time, which closes the connection.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		c.Close()
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// sshDeadline closes an SSH connection once the commands of an update had their time, which ends
// the one that hangs with an error: a session has no deadline of its own.
type sshDeadline struct {
	timer   *time.Timer
	expired atomic.Bool
}

// closeAfterTimeout gives the commands on client updateTimeout, from now.
func closeAfterTimeout(client *ssh.Client) *sshDeadline {
	d := &sshDeadline{}
	timeout := updateTimeout
	d.timer = time.AfterFunc(timeout, func() {
		d.expired.Store(true)
		client.Close()
	})
	return d
}

// stop is for when the connection closes.
func (d *sshDeadline) stop() {
	d.timer.Stop()
}

// wrap tells of the timeout in the error of a command it ended.
func (d *sshDeadline) wrap(err error) error {
	if err != nil && d.expired.Load() {
		return fmt.Errorf("timed out after %s: %w", updateTimeout, err)
	}
	return err
}

// unverifiedHostKeys keeps the warnings about the hosts a provider connected to without checking
// their key, for Warnings, once each.
type unverifiedHostKeys struct {
	mutex   sync.Mutex
	warned  map[string]bool
	pending []string
}

// note records that the key of address was not checked, unless it was already.
func (u *unverifiedHostKeys) note(address, hostKey string) {
	u.mutex.Lock()
	defer u.mutex.Unlock()
	if u.warned == nil {
		u.warned = make(map[string]bool)
	}
	if !u.warned[address] {
		u.warned[address] = true
		u.pending = append(u.pending, fmt.Sprintf("the SSH host key of %s isn't verified, so anyone in between could impersonate it: set host_key to its fingerprint, %s", address, hostKey))
	}
}

// Warnings returns the warnings not returned yet.
func (u *unverifiedHostKeys) Warnings() []string {
	u.mutex.Lock()
	defer u.mutex.Unlock()
	pending := u.pending
	u.pending = nil
	return pending
}

// commandRunner runs shell commands on a host.
type commandRunner interface {
	Run(command string) ([]byte, error)
	Close() error
}

// sshCommandRunner runs the commands of one update over an SSH connection, within updateTimeout.
type sshCommandRunner struct {
	client   *ssh.Client
	deadline *sshDeadline
}

func newSSHCommandRunner(client *ssh.Client) sshCommandRunner {
	return sshCommandRunner{client: client, deadline: closeAfterTimeout(client)}
}

func (r sshCommandRunner) Run(command string) ([]byte, error) {
	output, err := runSSH(r.client, command)
	return output, r.deadline.wrap(err)
}

func (r sshCommandRunner) Close() error {
	r.deadline.stop()
	return r.client.Close()
}

// runSSH runs command in a new session on client, and returns its output.
func runSSH(client *ssh.Client, command string) ([]byte, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(command)
	if err != nil {
		return output, fmt.Errorf("command %q failed: %w, output: %s", command, err, output)
	}
	return output, nil
}
