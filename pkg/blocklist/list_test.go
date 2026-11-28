package blocklist

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// server is a list's server of the test's: it sends body, with an ETag, and 304 to a client that
// has it; or the code given.
type server struct {
	mutex sync.Mutex
	body  string
	etag  string
	code  int
	// The If-None-Match of each request.
	asked []string
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.asked = append(s.asked, r.Header.Get("If-None-Match"))
	if s.code != 0 {
		w.WriteHeader(s.code)
		return
	}
	if s.etag != "" && r.Header.Get("If-None-Match") == s.etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", s.etag)
	w.Header().Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")
	_, _ = w.Write([]byte(s.body))
}

func (s *server) set(body, etag string, code int) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.body, s.etag, s.code = body, etag, code
}

func newList(t *testing.T, url, folder string) *List {
	t.Helper()
	return New(Config{Name: "pro", URL: url, Folder: folder, Warnf: t.Logf, Infof: t.Logf})
}

func TestRefresh(t *testing.T) {
	srv := &server{}
	srv.set("ads.example.com\nbad line here\n", `"1"`, 0)
	ts := httptest.NewServer(srv)
	defer ts.Close()
	folder := t.TempDir()
	l := newList(t, ts.URL, folder)
	ctx := context.Background()

	if err := l.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := l.Match("x.ads.example.com."); !ok {
		t.Error("x.ads.example.com isn't blocked")
	}
	s := l.Status()
	if s.Names != 1 || s.Unreadable != 1 || s.LastSuccess == nil || s.LastError != "" {
		t.Errorf("status %+v", s)
	}
	first := *s.LastSuccess

	// Unchanged: 304, with the copy kept, and its success later.
	time.Sleep(10 * time.Millisecond)
	if err := l.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if got := srv.asked[len(srv.asked)-1]; got != `"1"` {
		t.Errorf("If-None-Match %q, want the ETag", got)
	}
	if s := l.Status(); s.Names != 1 || !s.LastSuccess.After(first) {
		t.Errorf("after 304: %+v", s)
	}

	// A failure keeps the list.
	srv.set("", "", http.StatusInternalServerError)
	if err := l.Refresh(ctx); err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("error %v, want of 500", err)
	}
	if s := l.Status(); s.Names != 1 || s.LastError == "" {
		t.Errorf("after a failure: %+v", s)
	}
	if _, ok := l.Match("ads.example.com"); !ok {
		t.Error("the list was lost of a failure")
	}

	// A list of nothing readable is a failure too.
	srv.set("<html>not a list</html>\n", `"2"`, 0)
	if err := l.Refresh(ctx); err == nil {
		t.Error("a list of no name was taken")
	}
	if _, ok := l.Match("ads.example.com"); !ok {
		t.Error("the list was lost of one of no name")
	}

	// A change replaces it.
	srv.set("tracker.example.net\n", `"3"`, 0)
	if err := l.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := l.Match("ads.example.com"); ok {
		t.Error("the old list is still blocked")
	}
	if _, ok := l.Match("tracker.example.net"); !ok {
		t.Error("the new list isn't")
	}
	if s := l.Status(); s.LastError != "" || s.Unreadable != 0 {
		t.Errorf("after the change: %+v", s)
	}
	if b, _ := os.ReadFile(filepath.Join(folder, "pro.txt")); string(b) != "tracker.example.net\n" {
		t.Errorf("copy %q", b)
	}
	if matches, _ := filepath.Glob(filepath.Join(folder, "*.tmp")); len(matches) > 0 {
		t.Errorf("files left: %q", matches)
	}
}

func TestRefreshTooLarge(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		line := []byte(strings.Repeat("a", 60) + ".example\n")
		for written := 0; written <= MaxSize; written += len(line) {
			if _, err := w.Write(line); err != nil {
				return
			}
		}
	}))
	defer ts.Close()
	l := newList(t, ts.URL, t.TempDir())
	if err := l.Refresh(context.Background()); err == nil || !strings.Contains(err.Error(), "64 MiB") {
		t.Errorf("error %v, want of the size", err)
	}
	if l.Status().Names != 0 {
		t.Error("a list too large was taken")
	}
}

// A start reads the copy, offline, and asks the server whether it changed; one of another URL is
// not read.
func TestLoad(t *testing.T) {
	srv := &server{}
	srv.set("ads.example.com\n", `"1"`, 0)
	ts := httptest.NewServer(srv)
	folder := t.TempDir()
	if err := newList(t, ts.URL, folder).Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	ts.Close()

	l := newList(t, ts.URL, folder)
	if err := l.Load(); err != nil {
		t.Fatal(err)
	}
	if _, ok := l.Match("ads.example.com"); !ok {
		t.Error("the copy wasn't read")
	}
	// Offline: the copy stays.
	if err := l.Refresh(context.Background()); err == nil {
		t.Error("a server closed answered")
	}
	if s := l.Status(); s.Names != 1 || s.LastSuccess == nil || s.LastError == "" {
		t.Errorf("status %+v", s)
	}

	other := newList(t, "https://lists.example/other.txt", folder)
	if err := other.Load(); err != nil {
		t.Fatal(err)
	}
	if other.Status().Names != 0 {
		t.Error("the copy of another URL was read")
	}

	// Without a copy, and offline, it has no names, and says so.
	none := newList(t, ts.URL, t.TempDir())
	if err := none.Load(); err != nil {
		t.Fatal(err)
	}
	_ = none.Refresh(context.Background())
	if s := none.Status(); s.Names != 0 || s.LastSuccess != nil || s.LastError == "" {
		t.Errorf("status %+v", s)
	}
}

// Run downloads at once without a copy, then at the interval; a copy of within the interval is
// not downloaded at start.
func TestRunSchedule(t *testing.T) {
	srv := &server{}
	srv.set("ads.example.com\n", `"1"`, 0)
	ts := httptest.NewServer(srv)
	defer ts.Close()
	folder := t.TempDir()
	l := newList(t, ts.URL, folder)
	if next := l.schedule(); !next.IsZero() {
		t.Errorf("without a copy, next %s, want now", next)
	}
	if err := l.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if next := l.schedule(); next.Sub(*l.Status().LastSuccess) != DefaultInterval {
		t.Errorf("next %s, want an interval after the success", next)
	}

	reloaded := newList(t, ts.URL, folder)
	if err := reloaded.Load(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		reloaded.Run(ctx)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	srv.mutex.Lock()
	asked := len(srv.asked)
	srv.mutex.Unlock()
	if asked != 1 {
		t.Errorf("asked %d times, want once: the copy is of within the interval", asked)
	}
	if s := reloaded.Status(); s.NextRefresh == nil || s.NextRefresh.Before(time.Now().Add(DefaultInterval-time.Minute)) {
		t.Errorf("next refresh %v", s.NextRefresh)
	}

	// After a failure, RetryWait.
	srv.set("", "", http.StatusNotFound)
	_ = l.Refresh(context.Background())
	if next := l.schedule(); next.Sub(l.Status().LastRefresh.UTC()) != RetryWait {
		t.Errorf("after a failure, next %s", next)
	}
}

func TestRedacted(t *testing.T) {
	for in, want := range map[string]string{
		"https://lists.example/pro.txt":           "https://lists.example/pro.txt",
		"https://lists.example/pro.txt?token=abc": "https://lists.example/pro.txt?X",
		"https://user:pw@lists.example/pro.txt":   "https://X@lists.example/pro.txt",
	} {
		if got := Redacted(in, "X"); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}

func TestRedirectToPlainText(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ads.example.com\n"))
	}))
	defer plain.Close()
	tls := httptest.NewTLSServer(http.RedirectHandler(plain.URL+"/pro.txt", http.StatusFound))
	defer tls.Close()
	l := newList(t, tls.URL, t.TempDir())
	l.client.Transport = tls.Client().Transport
	err := l.Refresh(context.Background())
	if err == nil || !strings.Contains(err.Error(), "redirected from https:// to http://") {
		t.Errorf("redirect to http://: %v", err)
	}
	if _, ok := l.Match("ads.example.com"); ok {
		t.Error("the list of plain text was taken")
	}
}

func TestErrorHidesQuery(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	ts.Close()
	l := newList(t, ts.URL+"/pro.txt?token=secret", t.TempDir())
	err := l.Refresh(context.Background())
	if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(l.Status().LastError, "secret") {
		t.Errorf("error %v, status %q: the token is told", err, l.Status().LastError)
	}
}

// The line of a download that succeeded hides the URL's user and query too, as its errors do.
func TestInfoHidesToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ads.example.com") }))
	defer ts.Close()
	var mutex sync.Mutex
	var logged []string
	logf := func(f string, args ...any) {
		mutex.Lock()
		defer mutex.Unlock()
		logged = append(logged, fmt.Sprintf(f, args...))
	}
	l := New(Config{Name: "pro", URL: strings.Replace(ts.URL, "http://", "http://user:hunter2@", 1) + "/list.txt?token=s3cret", Folder: t.TempDir(), Infof: logf, Warnf: logf})
	if err := l.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "1 names") || !strings.Contains(logged[0], "/list.txt") {
		t.Errorf("logged %q, want the download", logged)
	}
	for _, line := range logged {
		if strings.Contains(line, "s3cret") || strings.Contains(line, "hunter2") {
			t.Errorf("the log tells the URL's secret: %s", line)
		}
	}
}

// A copy with no names, as one emptied by hand to have it downloaded again, is not the list: the
// start says so, and the server is asked the list whole, at once, not whether it changed.
func TestLoadEmptyCopy(t *testing.T) {
	for name, copy := range map[string]string{"empty": "", "of comments": "# pro\n\n", "unreadable": "<html>\n"} {
		t.Run(name, func(t *testing.T) {
			srv := &server{}
			srv.set("ads.example.com\n", `"1"`, 0)
			ts := httptest.NewServer(srv)
			defer ts.Close()
			folder := t.TempDir()
			if err := newList(t, ts.URL, folder).Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(folder, "pro.txt"), []byte(copy), 0o600); err != nil {
				t.Fatal(err)
			}
			l := newList(t, ts.URL, folder)
			if err := l.Load(); err == nil || !strings.Contains(err.Error(), "pro.txt: it has no name it could read") {
				t.Errorf("Load: %v, want that the copy has no name", err)
			}
			if s := l.Status(); s.LastSuccess != nil || s.Names != 0 {
				t.Errorf("status %+v, want no list", s)
			}
			if next := l.schedule(); next.After(time.Now()) {
				t.Errorf("the next download is at %s, want now", next.Format(time.DateTime))
			}
			if err := l.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			if got := srv.asked[len(srv.asked)-1]; got != "" {
				t.Errorf("the server was asked If-None-Match %q, of a copy with no names", got)
			}
			if _, ok := l.Match("ads.example.com"); !ok {
				t.Error("after a download, the list still has no names")
			}
		})
	}
}

// A server, a proxy or a captive portal that answers 200 with a page of its own in the list's
// place replaces nothing: the copy stays, and the download failed.
func TestRefreshPageInTheListsPlace(t *testing.T) {
	srv := &server{}
	srv.set("ads.example.com\ntrack.example.net\ntv.example.org\n", `"1"`, 0)
	ts := httptest.NewServer(srv)
	defer ts.Close()
	folder := t.TempDir()
	l := newList(t, ts.URL, folder)
	if err := l.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A page with a line that reads as a name, which alone would make it a list of one.
	srv.set("<!DOCTYPE html>\n<html>\n<head><title>403 Forbidden</title></head>\n<body>\n<h1>Forbidden</h1>\n<p>You don't have permission to access this resource.</p>\nnginx\n</body>\n</html>\n", `"2"`, 0)
	err := l.Refresh(context.Background())
	if err == nil || !strings.Contains(err.Error(), "it has 8 lines unreadable and 1 names, where the copy has 3") {
		t.Errorf("a page in the list's place: %v, want it refused", err)
	}
	if s := l.Status(); s.Names != 3 || s.LastError == "" {
		t.Errorf("status %+v, want the list of before, and the error", s)
	}
	if b, _ := os.ReadFile(filepath.Join(folder, "pro.txt")); !strings.HasPrefix(string(b), "ads.example.com\n") {
		t.Errorf("the copy was replaced: %q", b)
	}
	// A page with no name at all: refused as ever, with a copy or without.
	srv.set("<html>\n<body>Not Found</body>\n</html>\n", `"4"`, 0)
	none := newList(t, ts.URL, t.TempDir())
	for name, list := range map[string]*List{"with a copy": l, "without one": none} {
		if err := list.Refresh(context.Background()); err == nil || !strings.Contains(err.Error(), "it has no name it could read") {
			t.Errorf("a page of no name, %s: %v", name, err)
		}
	}
	if l.Status().Names != 3 || none.Status().Names != 0 {
		t.Errorf("after a page of no name: %d names, and %d without a copy", l.Status().Names, none.Status().Names)
	}
}

// A list of rules for a browser, as EasyList, has more lines unreadable than names, at every
// download: its names are taken the first time, and at each update, as they always were. Only one
// that loses more than half its names with it is taken for a page.
func TestRefreshBrowserList(t *testing.T) {
	easyList := func(domains int) string {
		var b strings.Builder
		b.WriteString("[Adblock Plus 2.0]\n! Title: EasyList\n! Homepage: https://easylist.to/\n")
		for i := range 40 {
			fmt.Fprintf(&b, "&ad_box_%d=\n/ads/banner%d.\nexample.com##.ad-%d\n||ads%d.example.net^$third-party\n@@||good%d.example.org^$script\n", i, i, i, i, i)
		}
		for i := range domains {
			fmt.Fprintf(&b, "||ads%d.example.com^\n", i)
		}
		return b.String()
	}
	srv := &server{}
	srv.set(easyList(20), `"1"`, 0)
	ts := httptest.NewServer(srv)
	defer ts.Close()
	folder := t.TempDir()
	l := newList(t, ts.URL, folder)
	if err := l.Refresh(context.Background()); err != nil {
		t.Fatalf("the first download: %v", err)
	}
	if s := l.Status(); s.Names != 20 || s.Unreadable != 200 {
		t.Fatalf("the first download: %d names, %d unreadable; want 20, 200", s.Names, s.Unreadable)
	}
	// An update of about its size, larger or smaller: taken.
	for _, domains := range []int{25, 18, 10} {
		srv.set(easyList(domains), fmt.Sprintf(`"%d"`, domains), 0)
		if err := l.Refresh(context.Background()); err != nil {
			t.Errorf("an update of %d domains: %v", domains, err)
		}
		if s := l.Status(); s.Names != domains {
			t.Errorf("an update of %d domains: %d names", domains, s.Names)
		}
	}
	// And a start reads its copy.
	reloaded := newList(t, ts.URL, folder)
	if err := reloaded.Load(); err != nil || reloaded.Status().Names != 10 {
		t.Errorf("its copy: %v, %d names", err, reloaded.Status().Names)
	}
	// One of under half the names, and still more lines unreadable, is not taken.
	srv.set(easyList(4), `"4"`, 0)
	if err := l.Refresh(context.Background()); err == nil || l.Status().Names != 10 {
		t.Errorf("a download of 4 names where the copy has 10, and 200 lines unreadable: %v, %d names", err, l.Status().Names)
	}
}

// The lists made for DNS, in each format the documentation gives, with their headers and comments,
// are never taken for a page: nor is an adblock list for DNS with some rules of options among its
// names.
func TestRealListsTaken(t *testing.T) {
	for name, c := range map[string]struct {
		list              string
		names, unreadable int
	}{
		"hagezi, wildcard onlydomains": {`# Title: HaGeZi's Pro DNS Blocklist
# Description: Big broom - Cleans the Internet and protects your privacy!
# Homepage: https://github.com/hagezi/dns-blocklists
# License: https://github.com/hagezi/dns-blocklists/blob/main/LICENSE
# Last modified: 27 Nov 2026 05:12 UTC
# Version: 2026.1127.0512.31
# Syntax: Domains (including possible subdomains)
# Number of entries: 3
#
0-0.fr
000free.us
ads.example.com
`, 3, 0},
		"hagezi, wildcard": {"# Title: HaGeZi's Light DNS Blocklist\n# Syntax: Wildcard Domains (including subdomains)\n#\n*.0-0.fr\n*.ads.example.com\n", 2, 0},
		"a hosts file, StevenBlack's": {`# Title: StevenBlack/hosts
#
# This hosts file is a merged collection of hosts from reputable sources,
# with a dash of crowd sourcing via GitHub
#
# Date: 27 November 2026 05:00:11 (UTC)
# ===============================================================

127.0.0.1 localhost
127.0.0.1 localhost.localdomain
127.0.0.1 local
255.255.255.255 broadcasthost
::1 localhost
::1 ip6-localhost
::1 ip6-loopback
fe80::1%lo0 localhost
ff00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts
0.0.0.0 0.0.0.0

# Start StevenBlack

#=====================================
# Title: Hosts contributed by Steven Black
0.0.0.0 ck.getcookiestxt.com
0.0.0.0 eu1.clevertap-prod.com # a comment
0.0.0.0 wizhumpgyros.com
`, 3, 0},
		"an adblock list for DNS, AdGuard's": {`[Adblock Plus]
! Title: AdGuard DNS filter
! Description: Filter composed of several other filters
! Homepage: https://github.com/AdguardTeam/AdguardSDNSFilter
! Last modified: 2026-11-27T05:00:11.000Z
!
! Section contains rules for advertising networks
||ads.example.com^
||track.example.net^
||tv.example.org^
||metrics.example.com^$important
@@||good.example.com^
||ads.example.net^
`, 4, 2},
		"with a byte order mark and Windows' line ends": {"\xef\xbb\xbf# Title: a list\r\nads.example.com\r\n0.0.0.0\ttrack.example.net\r\n", 2, 0},
	} {
		p, err := Parse(strings.NewReader(c.list))
		if err != nil {
			t.Fatal(err)
		}
		if p.Set.Len() != c.names || p.Unreadable != c.unreadable {
			t.Errorf("%s: %d names, %d unreadable; want %d, %d", name, p.Set.Len(), p.Unreadable, c.names, c.unreadable)
		}
		// The first time, at an update of its size, and when the copy had many times its names:
		// a list with fewer lines unreadable than names is never a page.
		for _, copied := range []int{0, c.names, 1000 * c.names} {
			if err := p.check(copied); err != nil {
				t.Errorf("%s, with a copy of %d names: refused: %v", name, copied, err)
			}
		}
	}
	// What isn't a list, in the place of one of 1000 names; and with no copy, where only what has
	// no name is refused.
	for name, c := range map[string]struct {
		body  string
		first bool // taken at a first download
	}{
		"nothing":           {"", false},
		"a page of no name": {"<html>\n<body>Not Found</body>\n</html>\n", false},
		"a page":            {"<html>\n<body>\nNot Found\nnginx\n</body>\n</html>\n", true},
		"JSON":              {"{\n  \"error\": \"rate limited\",\n  \"retry\": 60\n}\n", false},
	} {
		p, err := Parse(strings.NewReader(c.body))
		if err != nil {
			t.Fatal(err)
		}
		if p.check(1000) == nil {
			t.Errorf("%s: taken for a list of 1000 names, of %d names and %d lines unreadable", name, p.Set.Len(), p.Unreadable)
		}
		if taken := p.check(0) == nil; taken != c.first {
			t.Errorf("%s, with no copy: taken %v, want %v", name, taken, c.first)
		}
	}
	// A list that lost more than half its names is taken, when its lines read.
	if p, _ := Parse(strings.NewReader("ads.example.com\n")); p.check(1000) != nil {
		t.Error("a list of one name, where the copy had 1000: refused, with no line unreadable")
	}
}

// A last success in the future, as of a clock that was set back since, postpones the next
// download no further than an interval from now.
func TestScheduleAfterClockSetBack(t *testing.T) {
	srv := &server{}
	srv.set("ads.example.com\n", `"1"`, 0)
	ts := httptest.NewServer(srv)
	defer ts.Close()
	l := newList(t, ts.URL, t.TempDir())
	now := time.Now()
	l.now = func() time.Time { return now.Add(30 * 24 * time.Hour) }
	if err := l.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	l.now = func() time.Time { return now }
	if next := l.schedule(); !next.Equal(now.Add(DefaultInterval)) {
		t.Errorf("after a success of 30 days from now, the next download is in %s, want in %s", next.Sub(now), DefaultInterval)
	}
	if next := l.Status().NextRefresh; next == nil || !next.Equal(now.Add(DefaultInterval)) {
		t.Errorf("the status has the next at %v", next)
	}
	// And after a failure then.
	l.now = func() time.Time { return now.Add(30 * 24 * time.Hour) }
	srv.set("", "", http.StatusNotFound)
	_ = l.Refresh(context.Background())
	l.now = func() time.Time { return now }
	if next := l.schedule(); next.After(now.Add(DefaultInterval)) {
		t.Errorf("after a failure of 30 days from now, the next download is in %s", next.Sub(now))
	}
}
