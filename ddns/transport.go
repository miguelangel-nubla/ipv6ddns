package ddns

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
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

// verifiedOrPinnedTLSConfig accepts a server certificate the system trusts for host, or else one
// whose fingerprint is the given one, when there is one: self-signed certificates are common on
// routers. A failure tells the fingerprint, to configure.
func verifiedOrPinnedTLSConfig(host, fingerprint string) *tls.Config {
	fingerprint = strings.ToLower(strings.ReplaceAll(fingerprint, ":", ""))
	return &tls.Config{
		// VerifyConnection does the verification, the system's then the fingerprint.
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
			_, err = cs.PeerCertificates[0].Verify(opts)
			if err == nil || (fingerprint != "" && fp == fingerprint) {
				return nil
			}
			if fingerprint != "" {
				return fmt.Errorf("certificate verification failed: %w, and its fingerprint %s is not the expected %s", err, fp, fingerprint)
			}
			return fmt.Errorf("certificate verification failed: %w (fingerprint: %s)", err, fp)
		},
	}
}

// pinnedTLSConfig accepts only the server certificate with the given fingerprint.
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

// urlHost is the host of a URL, for certificate verification.
func urlHost(address string) string {
	u, err := url.Parse(address)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

const httpTimeout = 30 * time.Second

func newHTTPClient(tlsConfig *tls.Config) *http.Client {
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
		Timeout:   httpTimeout,
	}
}

// withDefaultPort adds port to an address that has none. The address can be an IPv6 one, bracketed
// or not.
func withDefaultPort(address, port string) string {
	if _, _, err := net.SplitHostPort(address); err == nil {
		return address
	}
	return net.JoinHostPort(strings.TrimSuffix(strings.TrimPrefix(address, "["), "]"), port)
}

// dialSSH connects to address, port 22 unless it says, with the private key in keyPath and the
// password, whichever are given.
func dialSSH(address, username, password, keyPath string) (*ssh.Client, error) {
	var auth []ssh.AuthMethod
	if keyPath != "" {
		key, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("unable to read private key: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("unable to parse private key: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if password != "" {
		auth = append(auth, ssh.Password(password))
	}
	if len(auth) == 0 {
		return nil, errors.New("no SSH authentication method: set a password or a key")
	}

	config := &ssh.ClientConfig{
		User:            username,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	client, err := ssh.Dial("tcp", withDefaultPort(address, "22"), config)
	if err != nil {
		return nil, fmt.Errorf("failed to dial %s: %w", address, err)
	}
	return client, nil
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
