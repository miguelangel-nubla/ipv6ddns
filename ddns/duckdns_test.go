package ddns

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const duckToken = "01234567-89ab-cdef-0123-456789abcdef"

func TestDuckDNSUpdate(t *testing.T) {
	var got url.Values
	reply := "OK"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query()
		w.Write([]byte(reply))
	}))
	defer server.Close()
	service := &DuckDNS{APIToken: duckToken, updateURL: server.URL}

	// DuckDNS takes one address of each family: the first.
	if err := service.Update("nas", collectionWith("2001:db8::10", "192.0.2.9", "2001:db8::9", "192.0.2.10")); err != nil {
		t.Fatal(err)
	}
	want := url.Values{"token": {duckToken}, "domains": {"nas"}, "ip": {"192.0.2.9"}, "ipv6": {"2001:db8::9"}}
	if got.Encode() != want.Encode() {
		t.Errorf("got %v, want %v", got, want)
	}

	reply = "KO"
	if err := service.Update("nas", collectionWith("2001:db8::9")); err == nil {
		t.Error("a KO answer: want an error")
	}
	if service.Domain("nas") != "nas.duckdns.org" {
		t.Errorf("domain: %s", service.Domain("nas"))
	}
}

// The providers that send their token in the URL must not have it in their errors, which are
// logged.
func TestTokenNotInErrors(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	server.Close() // nothing listens there

	for name, update := range map[string]func() error{
		"duckdns": func() error { return (&DuckDNS{APIToken: duckToken, updateURL: server.URL}).Update("nas", desired()) },
		"technitium": func() error {
			return (&Technitium{Address: server.URL, Token: duckToken, Zone: "lan"}).Update("nas", desired())
		},
	} {
		err := update()
		if err == nil {
			t.Errorf("%s: want an error", name)
		} else if strings.Contains(err.Error(), duckToken) {
			t.Errorf("%s: the token is in the error: %v", name, err)
		}
	}
}
