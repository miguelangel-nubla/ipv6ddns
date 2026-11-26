package blocklist

import (
	"context"
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
