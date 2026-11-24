package ddns

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

// fakePiHole is the API of Pi-hole 6 for its local DNS records: sessions by password, and the
// entries of dns.hosts, which are unique.
type fakePiHole struct {
	t      *testing.T
	mutex  sync.Mutex
	hosts  []string
	sid    string
	logins int
	writes int
}

func (f *fakePiHole) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	refuse := func(status int, message string) {
		w.WriteHeader(status)
		writeJSON(w, map[string]any{"error": map[string]any{"key": "bad_request", "message": message, "hint": nil}})
	}
	if r.URL.Path == "/api/auth" && r.Method == http.MethodPost {
		var body struct {
			Password string `json:"password"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		f.logins++
		if body.Password != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			writeJSON(w, map[string]any{"session": map[string]any{"valid": false, "sid": nil}})
			return
		}
		f.sid = "sid-" + strings.Repeat("x", f.logins)
		writeJSON(w, map[string]any{"session": map[string]any{"valid": true, "sid": f.sid, "validity": 1800}})
		return
	}
	if f.sid == "" || r.Header.Get("X-FTL-SID") != f.sid {
		refuse(http.StatusUnauthorized, "Unauthorized")
		return
	}
	const prefix = "/api/config/dns/hosts"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		f.t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		return
	}
	entry := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, prefix), "/")
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]any{"config": map[string]any{"dns": map[string]any{"hosts": f.hosts}}})
	case http.MethodPut:
		if strings.Contains(r.URL.EscapedPath(), " ") || !strings.Contains(r.URL.EscapedPath(), "%20") {
			f.t.Errorf("the entry is not escaped in %q", r.URL.EscapedPath())
		}
		if slices.Contains(f.hosts, entry) {
			refuse(http.StatusBadRequest, "Item already present")
			return
		}
		f.hosts = append(f.hosts, entry)
		f.writes++
		w.WriteHeader(http.StatusCreated)
	case http.MethodDelete:
		i := slices.Index(f.hosts, entry)
		if i < 0 {
			refuse(http.StatusNotFound, "Item not found")
			return
		}
		f.hosts = slices.Delete(f.hosts, i, i+1)
		f.writes++
		w.WriteHeader(http.StatusNoContent)
	}
}

func (f *fakePiHole) entries() []string {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	entries := slices.Clone(f.hosts)
	slices.Sort(entries)
	return entries
}

func TestPiHoleUpdate(t *testing.T) {
	fake := &fakePiHole{t: t, hosts: []string{
		wantedAsSet + " nas.example.com",
		obsoleteIP + " NAS.example.com",
		"192.0.2.50 nas.example.com nas", // two names: the user's own
		obsoleteIP + " other.example.com",
	}}
	server := httptest.NewServer(fake)
	defer server.Close()
	service := &PiHole{Address: server.URL + "/", Password: "secret", Zone: "example.com"}

	if err := service.Update("NAS", desired()); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"192.0.2.50 nas.example.com nas",
		newIPv4 + " nas.example.com",
		wantedAsSet + " nas.example.com",
		newIP + " nas.example.com",
		obsoleteIP + " other.example.com",
	}
	slices.Sort(want)
	if got := fake.entries(); !slices.Equal(got, want) {
		t.Errorf("entries:\n%v\nwant\n%v", got, want)
	}

	before := fake.writes
	if err := service.Update("nas.example.com.", desired()); err != nil {
		t.Fatal(err)
	}
	if fake.writes != before {
		t.Errorf("the update again asked for %d changes, want none", fake.writes-before)
	}
	if fake.logins != 1 {
		t.Errorf("%d logins, want 1: the session is kept", fake.logins)
	}

	// Pi-hole forgot the session, as after its restart: it is asked for again.
	fake.mutex.Lock()
	fake.sid = ""
	fake.mutex.Unlock()
	if err := service.Update("nas", collectionWith()); err != nil {
		t.Fatal(err)
	}
	if fake.logins != 2 {
		t.Errorf("%d logins, want 2", fake.logins)
	}
	want = []string{"192.0.2.50 nas.example.com nas", obsoleteIP + " other.example.com"}
	slices.Sort(want)
	if got := fake.entries(); !slices.Equal(got, want) {
		t.Errorf("entries without addresses: %v, want %v", got, want)
	}
	if got := service.Domain("NAS"); got != "nas.example.com" {
		t.Errorf("Domain: %q", got)
	}
}

func TestPiHoleErrors(t *testing.T) {
	fake := &fakePiHole{t: t}
	server := httptest.NewServer(fake)
	defer server.Close()

	err := (&PiHole{Address: server.URL, Password: "wrong-password", Zone: "example.com"}).Update("nas", desired())
	if err == nil || !strings.Contains(err.Error(), "the password is refused") || !strings.Contains(err.Error(), "application password") {
		t.Errorf("wrong password: %v", err)
	}
	if err != nil && strings.Contains(err.Error(), "wrong-password") {
		t.Errorf("the error has the password: %v", err)
	}
	err = (&PiHole{Address: server.URL, Zone: "example.com"}).Update("nas", desired())
	if err == nil || !strings.Contains(err.Error(), "a password is needed") {
		t.Errorf("no password: %v", err)
	}

	// Pi-hole 5, or something else: no API of version 6.
	old := httptest.NewServer(http.NotFoundHandler())
	defer old.Close()
	err = (&PiHole{Address: old.URL, Zone: "example.com"}).Update("nas", desired())
	if err == nil || !strings.Contains(err.Error(), "HTTP 404") || !strings.Contains(err.Error(), "version 6") {
		t.Errorf("not the API: %v", err)
	}
}
