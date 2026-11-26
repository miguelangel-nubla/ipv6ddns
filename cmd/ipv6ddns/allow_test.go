package main

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

// A link-local client comes with its zone, which a prefix never has: it is in fe80::/10 all the
// same, as the resolver's allow takes it.
func TestAllowOnlyLinkLocal(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	h := allowOnly(ok, []netip.Prefix{netip.MustParsePrefix("fe80::/10")})
	for remote, want := range map[string]int{
		"[fe80::1%eth0]:8080": http.StatusOK,
		"[fe80::1]:8080":      http.StatusOK,
		"[2001:db8::1]:8080":  http.StatusForbidden,
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("%s: %d, want %d", remote, w.Code, want)
		}
	}
}
