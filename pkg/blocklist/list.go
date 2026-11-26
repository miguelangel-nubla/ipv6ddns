package blocklist

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultInterval is how often a list is downloaded again that gives no interval; MinInterval, the
// least it may give.
const (
	DefaultInterval = 24 * time.Hour
	MinInterval     = time.Hour
)

// MaxSize is the largest list downloaded: hagezi's largest is a tenth of it.
const MaxSize = 64 << 20

// Timeout is how long a download has, whole.
const Timeout = 2 * time.Minute

// RetryWait is how long after a download that failed it is tried again: the interval, when shorter.
const RetryWait = 10 * time.Minute

// Folder is the folder of the lists' copies, in the state folder.
const Folder = "blocklists"

// Config is a list, as the configuration gives it.
type Config struct {
	Name string
	URL  string
	// How often it is downloaded again.
	Interval time.Duration
	// Where its copy is kept: <name>.txt, with <name>.json of what the server said of it.
	Folder string
	// Where its downloads are logged, and those that fail: nowhere, for nil.
	Infof, Warnf func(string, ...any)
}

// List is a list at work: Load reads its copy, Run keeps it up to date, Match tells what it blocks.
// Safe for concurrent use.
type List struct {
	config Config
	client *http.Client
	now    func() time.Time
	set    atomic.Pointer[Set]

	mutex      sync.Mutex
	unreadable int
	meta       meta
	// Of the last download, whatever its end; and its error, of one that failed.
	lastRefresh time.Time
	lastError   string
	next        time.Time
}

// meta is what is kept of a copy beside it: where it came from, what the server said of it, to
// ask whether it changed, and when it last said so.
type meta struct {
	URL          string    `json:"url"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	LastSuccess  time.Time `json:"last_success"`
}

// New makes the list of cfg, with no names until Load or Run gives it some.
func New(cfg Config) *List {
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.Infof == nil {
		cfg.Infof = func(string, ...any) {}
	}
	if cfg.Warnf == nil {
		cfg.Warnf = func(string, ...any) {}
	}
	return &List{config: cfg, client: &http.Client{Timeout: Timeout, CheckRedirect: checkRedirect}, now: time.Now}
}

// MaxRedirects is the most redirects a download follows.
const MaxRedirects = 5

// checkRedirect follows a redirect of a list of https:// to https:// alone: one to http:// would
// have it in plain text, which anyone on the way could change.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= MaxRedirects {
		return fmt.Errorf("it was redirected more than %d times", MaxRedirects)
	}
	if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf("it was redirected from https:// to %s://, which would have it in plain text", req.URL.Scheme)
	}
	return nil
}

// Name is the list's name.
func (l *List) Name() string { return l.config.Name }

// Match tells the name of the list that blocks name: it, or a parent. None while it has no names.
func (l *List) Match(name string) (string, bool) {
	return l.set.Load().Match(name)
}

// path is the file of the copy; with ext .json, of what is kept of it.
func (l *List) path(ext string) string {
	return filepath.Join(l.config.Folder, l.config.Name+ext)
}

// Load reads the copy kept of the list, of its URL: none, or one of another URL, is no error, and
// the list waits for its download.
func (l *List) Load() error {
	b, err := os.ReadFile(l.path(".json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var m meta
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("%s: %w", l.path(".json"), err)
	}
	if m.URL != l.config.URL {
		return nil
	}
	f, err := os.Open(l.path(".txt"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	var size int64
	if info, err := f.Stat(); err == nil {
		size = info.Size()
	}
	parsed, err := parse(f, size)
	if err != nil {
		return fmt.Errorf("%s: %w", l.path(".txt"), err)
	}
	l.set.Store(parsed.Set)
	l.mutex.Lock()
	l.meta, l.unreadable = m, parsed.Unreadable
	l.mutex.Unlock()
	return nil
}

// Run downloads the list when its copy is older than the interval, or there is none, and again at
// every interval, until ctx is done; one that fails, after RetryWait.
func (l *List) Run(ctx context.Context) {
	for {
		next := l.schedule()
		if wait := next.Sub(l.now()); wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
		if ctx.Err() != nil {
			return
		}
		_ = l.Refresh(ctx)
	}
}

// schedule sets when the list is downloaded next, and tells it: an interval after its last
// success; at once without a copy; RetryWait after a download that failed, or the interval.
func (l *List) schedule() time.Time {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	var next time.Time
	if l.set.Load() != nil {
		next = l.meta.LastSuccess.Add(l.config.Interval)
	}
	if l.lastError != "" {
		next = l.lastRefresh.Add(min(RetryWait, l.config.Interval))
	}
	l.next = next
	return next
}

// Refresh downloads the list, asking the server whether it changed since the copy: a list that
// didn't is kept, and one that did replaces it, on disk and here. A download that fails, or of
// a list with no name, leaves the names as they were.
func (l *List) Refresh(ctx context.Context) error {
	err := l.download(ctx)
	// Of a URL, the error tells it whole, which may hold a token: it tells it as the report does.
	if urlErr := (*url.Error)(nil); errors.As(err, &urlErr) {
		redacted := *urlErr
		redacted.URL = Redacted(urlErr.URL, "<sensible data hidden>")
		err = &redacted
	}
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.lastRefresh = l.now()
	if err != nil {
		l.lastError = err.Error()
		if s := l.set.Load(); s != nil {
			l.config.Warnf("blocklist %s: %s: keeping the list of %s, of %d names", l.config.Name, err, l.meta.LastSuccess.Format(time.DateTime), s.Len())
		} else {
			l.config.Warnf("blocklist %s: %s: there's no copy of it, and the resolvers block nothing of it until a download succeeds", l.config.Name, err)
		}
		return err
	}
	l.lastError = ""
	return nil
}

// download asks the server the list, and takes it: of a server that says it didn't change, the
// copy, as it is.
func (l *List) download(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.config.URL, nil)
	if err != nil {
		return err
	}
	l.mutex.Lock()
	m := l.meta
	l.mutex.Unlock()
	if l.set.Load() != nil {
		if m.ETag != "" {
			req.Header.Set("If-None-Match", m.ETag)
		}
		if m.LastModified != "" {
			req.Header.Set("If-Modified-Since", m.LastModified)
		}
	}
	resp, err := l.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotModified && l.set.Load() != nil:
		m.LastSuccess = l.now()
		if err := l.writeMeta(m); err != nil {
			return err
		}
		l.mutex.Lock()
		l.meta = m
		l.mutex.Unlock()
		return nil
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("the server answered %s", resp.Status)
	}
	if err := os.MkdirAll(l.config.Folder, 0o700); err != nil {
		return err
	}
	// Into a file of its own, read once whole: a list half downloaded replaces nothing.
	tmp, err := os.CreateTemp(l.config.Folder, l.config.Name+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, MaxSize+1))
	if err != nil {
		return fmt.Errorf("reading it: %w", err)
	}
	if n > MaxSize {
		return fmt.Errorf("it is larger than %d MiB, the most a list may be", MaxSize>>20)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return err
	}
	parsed, err := parse(tmp, n)
	if err != nil {
		return err
	}
	if parsed.Set.Len() == 0 {
		return fmt.Errorf("it has no name it could read, of %d lines unreadable: is it a list of names, one per line?", parsed.Unreadable)
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// The copy and what is kept of it change together: the old meta goes first, so that a copy
	// left without its meta, of a failure between them, is read by none, and downloaded again.
	m = meta{URL: l.config.URL, ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified"), LastSuccess: l.now()}
	if err := os.Remove(l.path(".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(tmp.Name(), l.path(".txt")); err != nil {
		return err
	}
	if err := l.writeMeta(m); err != nil {
		return err
	}
	l.set.Store(parsed.Set)
	l.mutex.Lock()
	l.meta, l.unreadable = m, parsed.Unreadable
	l.mutex.Unlock()
	l.config.Infof("blocklist %s: %d names, %d lines unreadable, from %s", l.config.Name, parsed.Set.Len(), parsed.Unreadable, l.config.URL)
	return nil
}

// writeMeta writes what is kept of the copy, whole or not at all.
func (l *List) writeMeta(m meta) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(l.config.Folder, 0o700); err != nil {
		return err
	}
	tmp := l.path(".json.tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, l.path(".json"))
}

// Status is a list's, for the report, /status.json and the metrics.
type Status struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	// How often it is downloaded, in seconds.
	Interval int `json:"interval"`
	// The names it has now, and the memory they take, in bytes.
	Names int `json:"names"`
	Bytes int `json:"bytes"`
	// The lines of its last copy that weren't read.
	Unreadable int `json:"unreadable"`
	// The last download, whatever its end; the last that succeeded, or found the list unchanged;
	// and the next.
	LastRefresh *time.Time `json:"last_refresh,omitempty"`
	LastSuccess *time.Time `json:"last_success,omitempty"`
	NextRefresh *time.Time `json:"next_refresh,omitempty"`
	// Why the last download failed: none of one that didn't.
	LastError string `json:"last_error,omitempty"`
	// The resolvers that block its names.
	Resolvers []string `json:"resolvers"`
}

// Status is the list's.
func (l *List) Status() Status {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	set := l.set.Load()
	s := Status{Name: l.config.Name, URL: l.config.URL, Interval: int(l.config.Interval.Seconds()), Names: set.Len(), Bytes: set.Bytes(),
		LastError: l.lastError, Resolvers: []string{}}
	if set != nil {
		s.Unreadable = l.unreadable
	}
	at := func(t time.Time) *time.Time {
		if t.IsZero() {
			return nil
		}
		return &t
	}
	s.LastRefresh, s.NextRefresh = at(l.lastRefresh), at(l.next)
	if set != nil {
		s.LastSuccess = at(l.meta.LastSuccess)
	}
	return s
}

// Redacted is a list's URL with its user and its query hidden, which may hold a token: as it is,
// without them.
func Redacted(raw, hidden string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return hidden
	}
	if u.User == nil && u.RawQuery == "" && u.Fragment == "" {
		return raw
	}
	text := u.Scheme + "://"
	if u.User != nil {
		text += hidden + "@"
	}
	text += u.Host + u.EscapedPath()
	if u.RawQuery != "" {
		text += "?" + hidden
	}
	return text
}
