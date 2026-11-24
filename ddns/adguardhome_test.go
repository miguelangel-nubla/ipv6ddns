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

// fakeAdGuard is the rewrites API of AdGuard Home: a list of domain and answer, where a delete
// takes every rewrite with both as written.
type fakeAdGuard struct {
	t        *testing.T
	mutex    sync.Mutex
	rewrites []adGuardRewrite
	writes   int
	status   int
	body     string
}

func (f *fakeAdGuard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if f.status != 0 {
		w.WriteHeader(f.status)
		w.Write([]byte(f.body))
		return
	}
	if user, password, ok := r.BasicAuth(); !ok || user != "admin" || password != "secret" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var entry adGuardRewrite
	if r.Method == http.MethodPost {
		if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
			f.t.Errorf("%s: %v", r.URL.Path, err)
		}
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /control/rewrite/list":
		writeJSON(w, f.rewrites)
	case "POST /control/rewrite/add":
		enabled := true
		entry.Enabled = &enabled
		f.rewrites = append(f.rewrites, entry)
		f.writes++
	case "POST /control/rewrite/delete":
		n := len(f.rewrites)
		f.rewrites = slices.DeleteFunc(f.rewrites, func(e adGuardRewrite) bool {
			return e.Domain == entry.Domain && e.Answer == entry.Answer
		})
		if len(f.rewrites) == n {
			f.t.Errorf("delete of a rewrite that isn't there: %+v", entry)
		}
		f.writes++
	default:
		f.t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
	}
}

// answers are the answers of the enabled rewrites of domain, sorted.
func (f *fakeAdGuard) answers(domain string) []string {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	var answers []string
	for _, e := range f.rewrites {
		if e.Domain == domain && (e.Enabled == nil || *e.Enabled) {
			answers = append(answers, e.Answer)
		}
	}
	slices.Sort(answers)
	return answers
}

func TestAdGuardHomeUpdate(t *testing.T) {
	off := false
	fake := &fakeAdGuard{t: t, rewrites: []adGuardRewrite{
		{Domain: "nas.example.com", Answer: wantedAsSet},
		{Domain: "nas.example.com", Answer: obsoleteIP},
		{Domain: "nas.example.com", Answer: obsoleteIP}, // said twice
		{Domain: "nas.example.com", Answer: "files.example.com"},
		{Domain: "nas.example.com", Answer: "192.0.2.77", Enabled: &off},
		{Domain: "other.example.com", Answer: obsoleteIP},
		{Domain: "*.example.com", Answer: obsoleteIP},
	}}
	server := httptest.NewServer(fake)
	defer server.Close()
	service := &AdGuardHome{Address: server.URL, Username: "admin", Password: "secret", Zone: "example.com"}

	if err := service.Update("NAS", desired()); err != nil {
		t.Fatal(err)
	}
	// The address it had stays as written, the alias stays, and the disabled one is not answered.
	want := []string{newIPv4, wantedAsSet, newIP, "files.example.com"}
	slices.Sort(want)
	if got := fake.answers("nas.example.com"); !slices.Equal(got, want) {
		t.Errorf("rewrites of nas: %v, want %v", got, want)
	}
	for _, domain := range []string{"other.example.com", "*.example.com"} {
		if got := fake.answers(domain); !slices.Equal(got, []string{obsoleteIP}) {
			t.Errorf("rewrites of %s: %v, want its own untouched", domain, got)
		}
	}
	if len(fake.rewrites) != 7 {
		t.Errorf("%d rewrites, want 7: the disabled one stays", len(fake.rewrites))
	}

	before := fake.writes
	if err := service.Update("nas.example.com.", desired()); err != nil {
		t.Fatal(err)
	}
	if fake.writes != before {
		t.Errorf("the update again asked for %d changes, want none", fake.writes-before)
	}

	// An address that is disabled gets no rewrite beside it.
	if err := service.Update("nas", collectionWith("192.0.2.77")); err != nil {
		t.Fatal(err)
	}
	if got := fake.answers("nas.example.com"); !slices.Equal(got, []string{"files.example.com"}) {
		t.Errorf("rewrites of nas: %v, want the alias alone", got)
	}

	// An address written twice is left written once.
	fake.rewrites = append(fake.rewrites, adGuardRewrite{Domain: "nas.example.com", Answer: wantedIP}, adGuardRewrite{Domain: "nas.example.com", Answer: wantedAsSet})
	if err := service.Update("nas", collectionWith(wantedIP)); err != nil {
		t.Fatal(err)
	}
	if got := fake.answers("nas.example.com"); !slices.Equal(got, []string{wantedIP, "files.example.com"}) {
		t.Errorf("rewrites of nas: %v, want the address once", got)
	}

	if got := service.Domain("NAS"); got != "nas.example.com" {
		t.Errorf("Domain: %q", got)
	}
}

func TestAdGuardHomeErrors(t *testing.T) {
	for _, tc := range []struct {
		name, user, body string
		status           int
		want             []string
	}{
		{"wrong password", "admin", "", 0, []string{"HTTP 401", "the username or the password is refused", "15 minutes"}},
		{"no user given", "", "", 0, []string{"HTTP 401", "give username and password"}},
		{"blocked", "admin", "auth: blocked for 14m55s\n", http.StatusTooManyRequests, []string{"HTTP 429", "blocked for 14m55s"}},
		{"not the API", "admin", "<html>Bad Gateway</html>", http.StatusBadGateway, []string{"HTTP 502 Bad Gateway", "not an answer of AdGuard Home's API"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeAdGuard{t: t, status: tc.status, body: tc.body}
			server := httptest.NewServer(fake)
			defer server.Close()
			service := &AdGuardHome{Address: server.URL, Username: tc.user, Zone: "example.com"}
			if tc.user != "" {
				service.Password = "wrong-password"
			}
			err := service.Update("nas", desired())
			if err == nil {
				t.Fatal("no error")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q, without %q", err, want)
				}
			}
			if strings.Contains(err.Error(), "wrong-password") {
				t.Errorf("error %q has the password", err)
			}
		})
	}
}
