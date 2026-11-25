package ddns

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/miguelangel-nubla/ipv6disc"
)

// newTestUniFi is the UniFi provider of the settings, as a credential makes it.
func newTestUniFi(t *testing.T, settings string) Service {
	t.Helper()
	service, err := NewUniFi(json.RawMessage(settings))
	if err != nil {
		t.Fatal(err)
	}
	return service
}

// fakeUniFi is a UniFi Network API of the DNS records, as the real ones answer: UniFi OS, with an
// API key or a login whose CSRF token every change must send, under /proxy/network; or a
// self-hosted Network Application, with a login of its own and no prefix. It refuses fields it
// doesn't know and values that aren't addresses, as they do.
type fakeUniFi struct {
	t        *testing.T
	unifiOS  bool
	apiKey   string
	password string

	mutex    sync.Mutex
	records  []unifiRecord
	nextID   int
	sessions map[string]string // cookie: its CSRF token
	logins   int
	// Changes, as "POST key value", "PUT ...", "DELETE id".
	changes []string
	// After a login, how many requests the session lasts: 0, for ever.
	sessionLife int
	used        int
}

func newFakeUniFi(t *testing.T, unifiOS bool) (*fakeUniFi, *httptest.Server) {
	f := &fakeUniFi{t: t, unifiOS: unifiOS, apiKey: "the-key", password: "secret", sessions: map[string]string{}}
	server := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	return f, server
}

func (f *fakeUniFi) add(key, rtype, value string, enabled bool, ttl int) {
	f.nextID++
	f.records = append(f.records, unifiRecord{ID: fmt.Sprintf("id%d", f.nextID), Enabled: enabled, Key: key, RecordType: rtype, Value: value, TTL: ttl})
}

// of are the enabled A and AAAA records of key, as "TYPE value ttl", in order.
func (f *fakeUniFi) of(key string) []string {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	var out []string
	for _, r := range f.records {
		if r.Key == key && r.Enabled && (r.RecordType == "A" || r.RecordType == "AAAA") {
			out = append(out, fmt.Sprintf("%s %s %d", r.RecordType, r.Value, r.TTL))
		}
	}
	slices.Sort(out)
	return out
}

func (f *fakeUniFi) fail(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprint(w, body)
}

func (f *fakeUniFi) serve(w http.ResponseWriter, r *http.Request) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	prefix := ""
	if f.unifiOS {
		prefix = "/proxy/network"
	}
	switch {
	// A self-hosted one answers UniFi OS's login as any call of its API without a session.
	case r.Method == http.MethodPost && r.URL.Path == "/api/auth/login" && !f.unifiOS:
		f.fail(w, http.StatusUnauthorized, `{"meta":{"rc":"error","msg":"api.err.LoginRequired"},"data":[]}`)
		return
	case r.Method == http.MethodPost && r.URL.Path == "/api/auth/login" && f.unifiOS,
		r.Method == http.MethodPost && r.URL.Path == "/api/login" && !f.unifiOS:
		var body struct{ Username, Password string }
		json.NewDecoder(r.Body).Decode(&body)
		if body.Username != "admin" || body.Password != f.password {
			if f.unifiOS {
				f.fail(w, http.StatusForbidden, `{"message":"Invalid username or password","code":"AUTHENTICATION_FAILED_INVALID_CREDENTIALS","level":"debug"}`)
			} else {
				f.fail(w, http.StatusBadRequest, `{"meta":{"rc":"error","msg":"api.err.Invalid"},"data":[]}`)
			}
			return
		}
		f.logins++
		f.used = 0
		cookie, csrf := fmt.Sprintf("session%d", f.logins), fmt.Sprintf("csrf%d", f.logins)
		f.sessions[cookie] = csrf
		http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: cookie, Path: "/"})
		if f.unifiOS {
			w.Header().Set("X-Csrf-Token", csrf)
		}
		fmt.Fprint(w, `{"username":"admin"}`)
		return
	case !strings.HasPrefix(r.URL.Path, prefix+"/v2/api/site/"):
		f.fail(w, http.StatusNotFound, `{"error":{"code":404,"message":"Not Found"}}`)
		return
	}

	// Who asks: the API key, or a session that hasn't ended.
	switch key := r.Header.Get("X-API-KEY"); {
	case key != "":
		if !f.unifiOS || key != f.apiKey {
			f.fail(w, http.StatusUnauthorized, `{"error":{"code":401,"message":"Unauthorized"}}`)
			return
		}
	default:
		cookie, err := r.Cookie("TOKEN")
		csrf, ok := "", false
		if err == nil {
			csrf, ok = f.sessions[cookie.Value]
		}
		f.used++
		if !ok || (f.sessionLife > 0 && f.used > f.sessionLife) {
			delete(f.sessions, cookieValue(r))
			f.fail(w, http.StatusUnauthorized, `{"code":"api.err.UserNotAuthenticated","errorCode":401,"message":"User not authenticated"}`)
			return
		}
		// UniFi OS: a change needs the session's token, which it then renews.
		if f.unifiOS && r.Method != http.MethodGet {
			if r.Header.Get("X-Csrf-Token") != csrf {
				f.fail(w, http.StatusForbidden, `{"message":"Invalid CSRF token"}`)
				return
			}
			renewed := csrf + "+"
			f.sessions[cookieValue(r)] = renewed
			w.Header().Set("X-Updated-Csrf-Token", renewed)
		}
	}

	rest, _ := strings.CutPrefix(r.URL.Path, prefix+"/v2/api/site/")
	site, path, _ := strings.Cut(rest, "/")
	if site != "default" || !strings.HasPrefix(path, "static-dns") {
		f.fail(w, http.StatusNotFound, `{"code":"api.err.NotFound","errorCode":404,"message":"Not Found"}`)
		return
	}
	id, _ := strings.CutPrefix(strings.TrimPrefix(path, "static-dns"), "/")
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && id == "":
		json.NewEncoder(w).Encode(f.records)
	case (r.Method == http.MethodPost && id == "") || (r.Method == http.MethodPut && id != ""):
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		var record unifiRecord
		if err := dec.Decode(&record); err != nil {
			f.fail(w, http.StatusBadRequest, `{"errorCode":400,"message":"JSON parse error: Unrecognized field"}`)
			return
		}
		if addr, err := netip.ParseAddr(record.Value); err != nil || (record.RecordType == "AAAA") != addr.Is6() {
			f.fail(w, http.StatusBadRequest, `{"code":"api.err.StaticDnsRecordInvalidParameters","details":{"invalid_fields":["value"]},"errorCode":400,"message":"Invalid IPv6 Address"}`)
			return
		}
		if r.Method == http.MethodPost {
			f.add(record.Key, record.RecordType, record.Value, record.Enabled, record.TTL)
			f.changes = append(f.changes, "POST "+record.Key+" "+record.Value)
			json.NewEncoder(w).Encode(f.records[len(f.records)-1])
			return
		}
		for i := range f.records {
			if f.records[i].ID == id {
				record.ID = id
				f.records[i] = record
				f.changes = append(f.changes, "PUT "+id)
				json.NewEncoder(w).Encode(record)
				return
			}
		}
		f.fail(w, http.StatusNotFound, `{"errorCode":404,"message":"Not Found"}`)
	case r.Method == http.MethodDelete && id != "":
		f.records = slices.DeleteFunc(f.records, func(rec unifiRecord) bool { return rec.ID == id })
		f.changes = append(f.changes, "DELETE "+id)
	default:
		f.fail(w, http.StatusMethodNotAllowed, `<html>405</html>`)
	}
}

// fingerprintOf is the SHA-256 fingerprint of the server's certificate, in hex, as
// tls_fingerprint takes it.
func fingerprintOf(t *testing.T, server *httptest.Server) string {
	t.Helper()
	sum := sha256.Sum256(server.Certificate().Raw)
	return hex.EncodeToString(sum[:])
}

func cookieValue(r *http.Request) string {
	if c, err := r.Cookie("TOKEN"); err == nil {
		return c.Value
	}
	return ""
}

func unifiAddrs(ips ...string) *ipv6disc.AddrCollection {
	c := ipv6disc.NewAddrCollection()
	for _, ip := range ips {
		c.Seen(ipv6disc.NewAddr(nil, netip.MustParseAddr(ip), "test", 0, nil), "test")
	}
	return c
}

// With an API key: a name gets a record for each address, its old ones go, and one written twice
// is written once; a record of the name you disabled, or of another type, stays, and so do those
// of other names; and an update with nothing to change changes nothing.
func TestUniFiAPIKey(t *testing.T) {
	f, server := newFakeUniFi(t, true)
	f.add("nas.lan.example.com", "AAAA", "2001:db8::1", true, 0) // gone from the addresses
	f.add("nas.lan.example.com", "A", "192.168.1.5", true, 0)    // stays, but written twice
	f.add("NAS.lan.example.com.", "A", "192.168.1.5", true, 0)
	f.add("nas.lan.example.com", "AAAA", "2001:db8::9", false, 0) // disabled: the user's
	f.add("nas.lan.example.com", "CNAME", "other.lan", true, 0)   // another type: the user's
	f.add("printer.lan.example.com", "A", "192.168.1.6", true, 0)
	u := newTestUniFi(t, `{"address": "`+server.URL+`", "api_key": "the-key", "zone": "lan.example.com", "tls_fingerprint": "`+fingerprintOf(t, server)+`"}`)

	if err := u.Update("nas", unifiAddrs("192.168.1.5", "2001:db8::5", "2001:db8::9")); err != nil {
		t.Fatal(err)
	}
	if got := f.of("nas.lan.example.com"); !slices.Equal(got, []string{"A 192.168.1.5 0", "AAAA 2001:db8::5 0"}) {
		t.Errorf("the records: %v", got)
	}
	if got := f.of("printer.lan.example.com"); len(got) != 1 {
		t.Errorf("another name's records: %v", got)
	}
	f.mutex.Lock()
	var cname, disabled bool
	for _, r := range f.records {
		cname = cname || r.RecordType == "CNAME"
		disabled = disabled || (!r.Enabled && r.Value == "2001:db8::9")
	}
	f.changes = nil
	f.mutex.Unlock()
	if !cname || !disabled {
		t.Errorf("the user's records: the CNAME %v, the disabled one %v", cname, disabled)
	}

	if err := u.Update("nas", unifiAddrs("192.168.1.5", "2001:db8::5", "2001:db8::9")); err != nil {
		t.Fatal(err)
	}
	if len(f.changes) != 0 {
		t.Errorf("an update with nothing to change: %v", f.changes)
	}
}

// A TTL given is the records': one of another TTL is changed in place, not made again.
func TestUniFiTTL(t *testing.T) {
	f, server := newFakeUniFi(t, true)
	f.add("nas.lan", "A", "192.168.1.5", true, 0)
	u := newTestUniFi(t, `{"address": "`+server.URL+`", "api_key": "the-key", "zone": "lan", "ttl": "5m", "tls_fingerprint": "`+fingerprintOf(t, server)+`"}`)
	if err := u.Update("nas", unifiAddrs("192.168.1.5", "2001:db8::5")); err != nil {
		t.Fatal(err)
	}
	if got := f.of("nas.lan"); !slices.Equal(got, []string{"A 192.168.1.5 300", "AAAA 2001:db8::5 300"}) {
		t.Errorf("the records: %v", got)
	}
	if !slices.Contains(f.changes, "PUT id1") {
		t.Errorf("the changes: %v", f.changes)
	}
}

// A user, of UniFi OS: it logs in once, sends the CSRF token with each change, takes the one
// UniFi OS renews, and logs in again, once, when the session ends.
func TestUniFiLoginUniFiOS(t *testing.T) {
	f, server := newFakeUniFi(t, true)
	u := newTestUniFi(t, `{"address": "`+server.URL+`", "username": "admin", "password": "secret", "zone": "lan", "tls_fingerprint": "`+fingerprintOf(t, server)+`"}`)
	if err := u.Update("nas", unifiAddrs("192.168.1.5", "2001:db8::5")); err != nil {
		t.Fatal(err)
	}
	if err := u.Update("nas", unifiAddrs("192.168.1.6")); err != nil {
		t.Fatal(err)
	}
	if got := f.of("nas.lan"); !slices.Equal(got, []string{"A 192.168.1.6 0"}) || f.logins != 1 {
		t.Errorf("the records: %v, after %d logins", got, f.logins)
	}
	f.mutex.Lock()
	f.sessionLife = 1
	f.used = 1
	f.mutex.Unlock()
	if err := u.Update("nas", unifiAddrs("192.168.1.7")); err != nil {
		t.Fatal(err)
	}
	if got := f.of("nas.lan"); !slices.Equal(got, []string{"A 192.168.1.7 0"}) || f.logins < 2 {
		t.Errorf("after the session ended: %v, after %d logins", got, f.logins)
	}
}

// A user of a self-hosted Network Application: no UniFi OS login, so its own, and no prefix.
func TestUniFiLoginSelfHosted(t *testing.T) {
	f, server := newFakeUniFi(t, false)
	u := newTestUniFi(t, `{"address": "`+server.URL+`", "username": "admin", "password": "secret", "zone": "lan", "tls_fingerprint": "`+fingerprintOf(t, server)+`"}`)
	if err := u.Update("nas", unifiAddrs("192.168.1.5")); err != nil {
		t.Fatal(err)
	}
	if got := f.of("nas.lan"); !slices.Equal(got, []string{"A 192.168.1.5 0"}) {
		t.Errorf("the records: %v", got)
	}
}

// Each refusal says why, and what to do.
func TestUniFiErrors(t *testing.T) {
	_, server := newFakeUniFi(t, true)
	fp := fingerprintOf(t, server)
	for _, c := range []struct{ name, settings, want string }{
		{"a wrong key", `"api_key": "wrong"`, "HTTP 401: the API key is refused: create one in UniFi OS"},
		{"a wrong password", `"username": "admin", "password": "wrong"`, "logging in: HTTP 403: the username or the password is refused"},
		{"a wrong password, self-hosted", `"username": "admin", "password": "wrong", "address": "SELF"`, "logging in: HTTP 400: the username or the password is refused"},
		{"another site", `"api_key": "the-key", "site": "other"`, `HTTP 404: no DNS records of site "other" here`},
		{"an API key on a self-hosted one", `"api_key": "the-key", "address": "SELF"`, "a self-hosted Network Application needs username and password"},
	} {
		t.Run(c.name, func(t *testing.T) {
			settings := `{"address": "` + server.URL + `", "zone": "lan", "tls_fingerprint": "` + fp + `", ` + c.settings + `}`
			if strings.Contains(c.settings, `"SELF"`) {
				_, self := newFakeUniFi(t, false)
				settings = `{"zone": "lan", "tls_fingerprint": "` + fingerprintOf(t, self) + `", ` + strings.Replace(c.settings, `"SELF"`, `"`+self.URL+`"`, 1) + `}`
			}
			err := newTestUniFi(t, settings).Update("nas", unifiAddrs("192.168.1.5"))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("got %v\nwant %s", err, c.want)
			}
		})
	}
	// What UniFi says of a record it refuses, with the field.
	u := &UniFi{}
	if err := u.refused(http.StatusBadRequest, []byte(`{"code":"api.err.StaticDnsRecordInvalidParameters","details":{"invalid_fields":["value"]},"errorCode":400,"message":"Invalid IPv6 Address"}`)); err.Error() != "HTTP 400: Invalid IPv6 Address (value)" {
		t.Errorf("a refused record: %v", err)
	}
}

// The settings: a key or a user, not both nor neither, and a TTL of a day at most.
func TestUniFiSettings(t *testing.T) {
	for settings, want := range map[string]string{
		`{"address": "https://u", "zone": "lan", "api_key": "k", "username": "a", "password": "p"}`: "not both",
		`{"address": "https://u", "zone": "lan"}`:                                                   "give api_key",
		`{"address": "https://u", "zone": "lan", "username": "a"}`:                                  "give api_key",
		`{"address": "https://u", "zone": "lan", "api_key": "k", "ttl": "25h"}`:                     "longer than UniFi takes",
	} {
		if _, err := NewUniFi(json.RawMessage(settings)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %s", settings, err, want)
		}
	}
	u := newTestUniFi(t, `{"address": "https://u", "zone": "Lan.Example.com.", "api_key": "k"}`).(*UniFi)
	if u.Site != "default" || u.Domain("NAS") != "nas.lan.example.com" {
		t.Errorf("site %q, domain %q", u.Site, u.Domain("NAS"))
	}
}

// A disabled record is the user's: of an address the name has or not, through an update with
// addresses and one with none, it stays as it is, disabled and of its TTL, though the settings
// have another, and no record is added beside it.
func TestUniFiDisabled(t *testing.T) {
	f, server := newFakeUniFi(t, true)
	f.add("nas.lan", "AAAA", "2001:db8::9", false, 120)   // an address the name has
	f.add("nas.lan", "AAAA", "2001:db8::bad", false, 120) // one it hasn't
	u := newTestUniFi(t, `{"address": "`+server.URL+`", "api_key": "the-key", "zone": "lan", "ttl": "5m", "tls_fingerprint": "`+fingerprintOf(t, server)+`"}`)
	for i, ips := range [][]string{{"2001:db8::9", "192.168.1.5"}, nil} {
		if err := u.Update("nas", unifiAddrs(ips...)); err != nil {
			t.Fatal(err)
		}
		f.mutex.Lock()
		var disabled, beside []string
		for _, r := range f.records {
			if r.Key != "nas.lan" {
				continue
			}
			if !r.Enabled {
				disabled = append(disabled, fmt.Sprintf("%s %d", r.Value, r.TTL))
			} else if r.Value == "2001:db8::9" {
				beside = append(beside, r.ID)
			}
		}
		f.mutex.Unlock()
		slices.Sort(disabled)
		if !slices.Equal(disabled, []string{"2001:db8::9 120", "2001:db8::bad 120"}) || len(beside) != 0 {
			t.Errorf("update %d: disabled %v, records beside one %v", i+1, disabled, beside)
		}
	}
	if got := f.of("nas.lan"); len(got) != 0 {
		t.Errorf("after an update with none: %v", got)
	}
}
