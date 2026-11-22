package ddns

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// timeouts gives a request and an update their time, for the test.
func timeouts(t *testing.T, request, update time.Duration) {
	t.Helper()
	oldRequest, oldUpdate := httpTimeout, updateTimeout
	httpTimeout, updateTimeout = request, update
	t.Cleanup(func() { httpTimeout, updateTimeout = oldRequest, oldUpdate })
}

// returnsWithin runs the update, which must return within limit, and returns the
// time it took and its error.
func returnsWithin(t *testing.T, limit time.Duration, update func() error) (time.Duration, error) {
	t.Helper()
	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- update() }()
	select {
	case err := <-done:
		return time.Since(start), err
	case <-time.After(limit):
		t.Fatalf("the update is still running after %s", limit)
		return 0, nil
	}
}

// The two timeouts of an update of Cloudflare and of Route 53 bound a thing each, which these tell
// apart by giving one a time far from the other's: httpTimeout a request, and updateTimeout the
// requests together, with the waits between.

// Route 53's SDK tries a request that timed out again, as long as the update has time: an API
// that didn't answer once is no failed update. With the update's timeout alone, the first request
// would take it all.
func TestRoute53RequestTimeoutLeavesTimeToTryAgain(t *testing.T) {
	timeouts(t, 300*time.Millisecond, 10*time.Second)
	fake := &fakeRoute53{t: t, sets: map[string]route53RecordSet{}}
	var requests atomic.Int32
	hang := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			select {
			case <-hang:
			case <-r.Context().Done():
			}
			return
		}
		fake.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(hang) })

	service := &Route53{AccessKeyID: "a", SecretAccessKey: "s", Region: "us-east-1", HostedZoneID: "Z1", endpoint: server.URL}
	service.TTL.Duration = 5 * time.Minute
	_, err := returnsWithin(t, 20*time.Second, func() error { return service.Update("nas", desired()) })
	if err != nil {
		t.Fatalf("the update failed, of one request without an answer: %v", err)
	}
	if got := len(fake.sets); got != 2 {
		t.Errorf("%d record sets, want the A and the AAAA: %v", got, fake.sets)
	}
}

// Cloudflare's client doesn't try a request that timed out again, so the update fails: at the
// request's timeout, not at the update's, four times later, with its name and the others of its
// endpoint waiting.
func TestCloudflareRequestTimeoutBeforeTheUpdates(t *testing.T) {
	timeouts(t, 300*time.Millisecond, 10*time.Second)
	service := &Cloudflare{APIToken: "token", Zone: "example.com", apiBaseURL: "http://" + silentListener(t)}
	took, err := returnsWithin(t, 20*time.Second, func() error { return service.Update("nas", desired()) })
	if err == nil {
		t.Error("the update succeeded")
	}
	if took > 5*time.Second {
		t.Errorf("the update took %s, of a request's timeout of %s: %v", took, httpTimeout, err)
	}
}

// And the update has updateTimeout, however many requests it takes, each within its own time:
// Cloudflare's client tries a request answered with an error of the server again, three times,
// waiting one, two and four seconds, which no timeout of a request ends. The zone's lookup first:
// the client's own ZoneIDByName takes no context, and would try for those seven seconds.
func TestCloudflareUpdateTimeoutEndsTheTriesAgain(t *testing.T) {
	timeouts(t, 30*time.Second, 500*time.Millisecond)
	for name, failing := range map[string]string{"the zone's lookup": "/zones", "the records": "/zones/z1/dns_records"} {
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == failing {
					requests.Add(1)
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				writeJSON(w, map[string]any{"success": true, "result": []map[string]string{{"id": "z1", "name": "example.com"}}})
			}))
			t.Cleanup(server.Close)

			service := &Cloudflare{APIToken: "token", Zone: "example.com", apiBaseURL: server.URL}
			took, err := returnsWithin(t, 20*time.Second, func() error { return service.Update("nas", desired()) })
			if err == nil {
				t.Error("the update succeeded")
			}
			if took > 3*time.Second {
				t.Errorf("the update took %s, of a timeout of %s: %v", took, updateTimeout, err)
			}
			if requests.Load() == 0 {
				t.Error("no request reached the part that fails")
			}
		})
	}
}

// Gravity's requests have updateTimeout together, as the other providers': each with its own
// only, an update of many would hold its endpoint for as many.
func TestGravityUpdateTimeout(t *testing.T) {
	timeouts(t, time.Second, time.Second)
	fake := newFakeDNS(t, "nas", "other")
	handler := gravityHandler(t, fake, true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(400 * time.Millisecond)
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)

	// Four requests and more: the listing, three puts, a delete.
	service := &Gravity{Server: server.URL, APIKey: "key", Zone: "example.com."}
	took, err := returnsWithin(t, 1800*time.Millisecond, func() error { return service.Update("nas", desired()) })
	if err == nil {
		t.Errorf("the update, after %s: done, want it timed out", took.Round(time.Millisecond))
	}
}
