package ipv6ddns

import (
	"net/netip"
	"testing"
	"time"

	"go.uber.org/zap"
)

// A task whose filter has prefix_source: when the router sends the new prefix of the LAN, the
// addresses of the old one leave the name at once, though discovery keeps them for their
// lifetime; before any prefix, the name has both.
func TestPrefixSourceFollowsTheRouter(t *testing.T) {
	cfg := loadConfig(t, `
webserver:
  listen: 127.0.0.1:8053
sources:
  wan:
    type: push
    password: secret
credentials:
  fake:
    provider: fake
    debounce: 1ms
    settings:
      id: prefix
tasks:
  nas:
    filter:
      - mac:
          address: "00:00:00:00:00:0a"
        ip:
          prefix_source: wan
    endpoints:
      fake:
        - nas
`)
	w, err := NewWorker(zap.NewNop().Sugar(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.discWorker.State.Close)
	fake := fakeServices["prefix"]
	register(t, w, macA, "2001:db8:1:1::a", time.Hour)
	register(t, w, macA, "2001:db8:2:1::a", time.Hour)
	w.lookForChanges()
	fake.waitFor(t, "nas", "2001:db8:1:1::a", "2001:db8:2:1::a")

	wan, _ := w.PushSource("wan")
	if _, err := wan.Push(nil, netip.MustParsePrefix("2001:db8:2:1::/64")); err != nil {
		t.Fatal(err)
	}
	w.lookForChanges()
	fake.waitFor(t, "nas", "2001:db8:2:1::a")
}
