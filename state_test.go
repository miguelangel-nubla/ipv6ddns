package ipv6ddns

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/miguelangel-nubla/ipv6ddns/config"
	"go.uber.org/zap"
)

// With state_dir, everything ipv6ddns writes is there, made at start, and nothing beside the
// configuration, which is read-only, as a mounted secret is: a push source's addresses, the
// dynamic updates' challenges and names, and where ACME writes its certificate.
func TestStateDir(t *testing.T) {
	configDir, stateDir := t.TempDir(), filepath.Join(t.TempDir(), "state", "of", "ipv6ddns")
	path := filepath.Join(configDir, "config.yaml")
	text := fmt.Sprintf(`
state_dir: %s
credentials:
  public:
    provider: txtrec
    settings:
      id: state
listeners:
  lan:
    listen:
      - dns://127.0.0.1:%s
    tls: dns
resolvers:
  lan:
    listeners:
      - lan
    upstream: 127.0.0.1:%s
    updates:
      keys:
        nas:
          secret: %s
          permissions:
            - challenges:
                credential: public
                names:
                  - nas
            - addresses:
                source: vps
                zone: example.com
            - names:
                zone: lan.example.com
sources:
  vps:
    type: push
certificates:
  dns:
    acme:
      names:
        - dns
      credential: public
tasks:
  vps:
    sources:
      - vps
    endpoints:
      public:
        - vps
discovery:
  ipv6:
    enabled: false
`, stateDir, freeDNSPort(t), freeDNSPort(t), updatesTestSecret)
	// The resolver has an encrypted entry, for its certificate to be used.
	text = strings.Replace(text, "      - dns://127.0.0.1:", "      - tls://127.0.0.1:"+freeDNSPort(t)+"\n      - dns://127.0.0.1:", 1)
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(configDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(configDir, 0o700) })
	cfg, err := config.NewConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cert := cfg.Certificates["dns"]; !strings.HasPrefix(cert.CertFile, stateDir+"/") || !strings.HasPrefix(cert.AccountKeyFile, stateDir+"/") {
		t.Errorf("ACME's files: %s, %s", cert.CertFile, cert.AccountKeyFile)
	}
	w, err := NewWorker(zap.NewNop().Sugar(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(stateDir); err != nil || !info.IsDir() {
		t.Fatalf("the state folder wasn't made: %v", err)
	}

	// Each grant writes its file, as an update would have it.
	if _, err := w.sources["vps"].Replace([]netip.Addr{netip.MustParseAddr("192.0.2.7")}); err != nil {
		t.Errorf("the push source: %v", err)
	}
	for _, g := range w.grantsToStart {
		switch g := g.(type) {
		case *challengeGrant:
			name := "_acme-challenge.nas.rec.test."
			if err := g.Apply(map[string][]dns.RR{name: {txtRR(t, name, "token")}}); err != nil {
				t.Errorf("the challenges: %v", err)
			}
		case *namesGrant:
			rr, _ := dns.NewRR("printer.lan.example.com. 60 IN A 192.0.2.20")
			if err := g.Apply(map[string][]dns.RR{"printer.lan.example.com.": {rr}}); err != nil {
				t.Errorf("the names: %v", err)
			}
		}
	}
	for _, file := range []string{"push-vps.json", "challenges-nas-public.json", "names-lan.example.com.json"} {
		if _, err := os.Stat(filepath.Join(stateDir, file)); err != nil {
			t.Errorf("%s: %v", file, err)
		}
	}
	entries, _ := os.ReadDir(configDir)
	if len(entries) != 1 {
		t.Errorf("beside the configuration: %v", entries)
	}
}
