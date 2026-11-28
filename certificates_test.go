package ipv6ddns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/ddns"
	"github.com/miguelangel-nubla/ipv6disc"
	"go.uber.org/zap"
)

// txtService is a provider of the tests' that writes TXT records, as the DNS challenge needs: of
// the zone txt.test, or failing to tell the names in full, with fail_names.
type txtService struct{ failNames bool }

func (s *txtService) Update(string, *ipv6disc.AddrCollection) error { return nil }
func (s *txtService) Domain(hostname string) string                 { return hostname + ".txt.test" }
func (s *txtService) SetTXT(string, []string) error                 { return nil }
func (s *txtService) FullName(hostname string) (string, error) {
	if s.failNames {
		return "", errors.New("the zone isn't known yet")
	}
	return s.Domain(hostname), nil
}

func init() {
	ddns.RegisterProvider("txt", func(settings json.RawMessage) (ddns.Service, error) {
		var s struct {
			FailNames bool `json:"fail_names"`
		}
		_ = json.Unmarshal(settings, &s)
		return &txtService{failNames: s.FailNames}, nil
	})
}

// selfSigned writes a certificate signed by itself, for names, and its key, in dir.
func selfSigned(t *testing.T, dir string, names ...string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	certFile, keyFile = filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	return certFile, keyFile
}

// certificateConfig is a configuration of a resolver over TLS and of the web server over HTTPS,
// both of the certificate home, which certificates gives; with the credentials given too.
func certificateConfig(t *testing.T, home, credentials string) config.Config {
	t.Helper()
	text := fmt.Sprintf(`
listeners:
  web:
    listen:
      - "https://127.0.0.1:%d"
    tls: home
  lan:
    listen:
      - "tls://127.0.0.1:%d"
    tls: home
webservers:
  main:
    listeners:
      - web
resolvers:
  lan:
    listeners:
      - lan
    upstream: 192.0.2.1
certificates:
  home:%s
credentials:
  zone:
    provider: resolver
    settings:
      zone: home.arpa
      records:
        - printer A 192.0.2.20%s
tasks: {}
discovery:
  ipv6:
    enabled: false
`, freePort(t), freePort(t), home, credentials)
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.NewConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// shown is the names of the certificate that tlsConfig shows a client.
func shown(t *testing.T, tlsConfig *tls.Config) []string {
	t.Helper()
	l, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		if c, err := l.Accept(); err == nil {
			_ = c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	conn, err := tls.Dial("tcp", l.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0].DNSNames
}

// A certificate of files that a resolver and the web server both give: loaded once, the same for
// both, shown with its servers in the report and the status, and named under the resolver.
func TestCertificateShared(t *testing.T) {
	certFile, keyFile := selfSigned(t, t.TempDir(), "dns.lan.example.com", "status.lan.example.com")
	cfg := certificateConfig(t, "\n    certificate: "+certFile+"\n    key: "+keyFile, "")
	w, err := NewWorker(zap.NewNop().Sugar(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.discWorker.State.Close)
	if len(w.certs) != 1 || w.resolvers[0].Status().Certificate != "home" {
		t.Fatalf("the certificates: %d, the resolver's: %q", len(w.certs), w.resolvers[0].Status().Certificate)
	}
	if got := shown(t, w.TLS("home", "http/1.1")); !slices.Equal(got, []string{"dns.lan.example.com", "status.lan.example.com"}) {
		t.Errorf("the web server shows %v", got)
	}

	st := w.Status(false).Certificates
	if len(st) != 1 || st[0].Name != "home" || !slices.Equal(st[0].UsedBy, []string{"listeners.lan", "listeners.web"}) || st[0].Managed || st[0].Renewal != "" {
		t.Fatalf("the status: %+v", st)
	}
	data, err := json.Marshal(st[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"name":"home"`, `"used_by":["listeners.lan","listeners.web"]`, `"names":["dns.lan.example.com","status.lan.example.com"]`, `"not_after":`} {
		if !strings.Contains(string(data), key) {
			t.Errorf("the status's JSON has no %s: %s", key, data)
		}
	}
	page := w.Page("", false).String()
	for _, has := range []string{"        Certificate: home\n", "Certificates:\n    home (listener lan, listener web): dns.lan.example.com, status.lan.example.com, until "} {
		if !strings.Contains(page, has) {
			t.Errorf("the report has no %q:\n%s", has, page)
		}
	}
}

// Of acme, a credential whose provider can't write TXT records stops the start.
func TestCertificateACMENoTXT(t *testing.T) {
	cfg := certificateConfig(t, `
    acme:
      names: dns
      credential: public`, `
  public:
    provider: fake
    settings:
      id: notxt`)
	_, err := NewWorker(zap.NewNop().Sugar(), cfg)
	if want := "certificates.home.acme.credential: the provider of public, fake, can't write the TXT records of the DNS challenge"; err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("got %v\nwant %s", err, want)
	}
}

// Of acme, before any certificate: the servers start, and the status and the report say why
// there is none yet, when the provider can't tell the names in full, and when the authority can't
// be reached, with the next attempt. The manager stops with the worker.
func TestCertificateACMEFailing(t *testing.T) {
	saved := namesRetry
	namesRetry = 10 * time.Millisecond
	t.Cleanup(func() { namesRetry = saved })
	// An address of no authority: the connection is refused at once.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	directory := "http://" + l.Addr().String() + "/directory"
	l.Close()

	for _, c := range []struct{ name, failNames, want string }{
		{"the names", "true", "dns: the zone isn't known yet"},
		{"the authority", "false", "directory"},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg := certificateConfig(t, `
    acme:
      names: dns
      credential: public
      directory: `+directory, `
  public:
    provider: txt
    settings:
      fail_names: `+c.failNames)
			w, err := NewWorker(zap.NewNop().Sugar(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			if err := w.Start(ctx); err != nil {
				cancel()
				t.Fatal(err)
			}
			defer func() {
				cancel()
				if err := w.Shutdown(context.Background()); err != nil {
					t.Error(err)
				}
			}()
			var st CertificateStatus
			for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
				st = w.certificateStatuses(false)[0]
				if strings.Contains(st.Renewal, c.want) {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("the status: %+v, %+v", st, st.Status)
				}
			}
			if !st.Managed || len(st.Names) != 0 {
				t.Errorf("the status: %+v", st.Status)
			}
			if c.failNames == "false" && st.NextAttempt.Before(time.Now()) {
				t.Errorf("no next attempt: %+v", st.Status)
			}
			if page := w.Page("", false).String(); !strings.Contains(page, "home (listener lan, listener web): none yet (getting it failed: ") {
				t.Errorf("the report:\n%s", page)
			}
		})
	}
}

// secretTXT is a provider whose error tells a secret, as a provider's may: its token.
type secretTXT struct{}

func (secretTXT) Update(string, *ipv6disc.AddrCollection) error { return nil }
func (secretTXT) Domain(hostname string) string                 { return hostname + ".txt.test" }
func (secretTXT) SetTXT(string, []string) error                 { return nil }
func (secretTXT) FullName(string) (string, error) {
	return "", errors.New("denied for token SECRET-7f3a")
}

func init() {
	ddns.RegisterProvider("secrettxt", func(json.RawMessage) (ddns.Service, error) { return secretTXT{}, nil })
	ddns.RegisterTXT("secrettxt")
}

// With the sensible data hidden, why getting a certificate failed is hidden, in the status and on
// the page: it is the error of the credential's provider, or the authority's. The report with
// everything has it.
func TestCertificateErrorHidden(t *testing.T) {
	saved := namesRetry
	namesRetry = 10 * time.Millisecond
	t.Cleanup(func() { namesRetry = saved })
	cfg := certificateConfig(t, `
    acme:
      names: dns
      credential: public
      directory: http://127.0.0.1:1/directory`, `
  public:
    provider: secrettxt
    settings: {}`)
	w, err := NewWorker(zap.NewNop().Sugar(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := w.Start(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	defer func() {
		cancel()
		if err := w.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if strings.Contains(w.certificateStatuses(false)[0].Renewal, "SECRET-7f3a") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no error of the names")
		}
	}
	body, _ := json.Marshal(w.Status(true))
	if strings.Contains(string(body), "SECRET-7f3a") {
		t.Errorf("the provider's error is in the status with the sensible data hidden, as /status.json serves it: %s", body)
	}
	if st := w.Status(true).Certificates[0]; st.Renewal != "<sensible data hidden>" {
		t.Errorf("the status with the sensible data hidden says of the renewal %q", st.Renewal)
	}
	page := w.Page("", true).String()
	if strings.Contains(page, "SECRET-7f3a") || !strings.Contains(page, "none yet (getting it failed: <sensible data hidden>)") {
		t.Errorf("the page with the sensible data hidden, as the web server serves it:\n%s", page)
	}
	if page := w.Page("", false).String(); !strings.Contains(page, "(getting it failed: dns: denied for token SECRET-7f3a)") {
		t.Errorf("the page with everything:\n%s", page)
	}
	// The metric tells the failure all the same.
	var metrics strings.Builder
	if err := w.Status(true).WriteMetrics(&metrics); err != nil || !strings.Contains(metrics.String(), `ipv6ddns_certificate_last_renewal_failed{certificate="home"} 1`) {
		t.Errorf("the metrics: %v\n%s", err, metrics.String())
	}
}
