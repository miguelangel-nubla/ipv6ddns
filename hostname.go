package ipv6ddns

import (
	"sync"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
)

// Hostname keeps the records of one name at one endpoint in step with its addresses: once they
// stop changing for the debounce time it updates the records, and after a failure it tries again
// at every retry interval.
//
// The two are layers, the retry above the debounce. The debounce is of the addresses: how long
// they must be still. The retry is of the endpoint: how long one that failed is left alone. So
// after a failure nothing is sent before the retry interval is over, whatever the addresses do
// meanwhile, and what is sent then is the addresses of then, once still for the debounce time. An
// update that succeeds ends the wait. Only ScheduleUpdate, which is somebody asking, goes past it.
//
// Nothing is updated before the first address: a start with nothing found yet leaves the records
// as they are. Once it had addresses and they are all gone, it updates with none, which removes
// the records. That holds for an update somebody asks for too: one of a name that never had an
// address sends nothing, as it would remove records it knows nothing of.
//
// An update is of a change, not of a timer: one that finds the addresses of now sent already, by
// an update that ran while it waited, sends nothing. Several changes during a slow update are one
// update after it, of the addresses of the end.
type Hostname struct {
	mutex sync.Mutex
	addrs *ipv6disc.AddrCollection
	// Counts the changes of addrs: an update that fails tells by it whether they changed while it
	// ran, and so have an update of their own scheduled.
	addrsChanges uint64
	// The count of addrs' changes that the last update that succeeded sent: with no error since,
	// the endpoint has the addresses of now when it is addrsChanges, and anything else is still to
	// send. Both zero: never an address, and nothing to send.
	updatedChanges uint64
	// It had an address once, since the start.
	hadAddrs bool
	// The endpoint is left alone until then, after a failure: zero after a success.
	retryNotBefore time.Time

	updatedTime     time.Time
	nextUpdateTime  time.Time
	nextUpdateTimer *time.Timer
	// Why the next update waits: the debounce, a retry after a failure, or one asked for.
	nextUpdateReason string
	// When the name lost its last address: zero while it has one, or never had.
	emptiedTime   time.Time
	updateRunning bool
	updateError   error
	updates       int
	failures      int
	// No more updates once stopped.
	stopped bool

	// One update at a time.
	updateMutex sync.Mutex
	// One update at a time at the endpoint too, with its other names, if set: taken before the
	// update starts, so that one waiting for another name's doesn't run once stopped.
	endpointMutex *sync.Mutex

	updateAction        func(*ipv6disc.AddrCollection) error
	updateDebounceTime  time.Duration
	updateRetryInterval time.Duration
}

// hostnameStatus is a snapshot of a Hostname, for display.
type hostnameStatus struct {
	addrs            *ipv6disc.AddrCollection
	updatedTime      time.Time
	nextUpdateTime   time.Time
	nextUpdateReason string
	debounce         time.Duration
	emptiedTime      time.Time
	updateRunning    bool
	updateError      error
	updates          int
	failures         int
}

// SetAddrCollection sets the addresses the name should have. The valid ones only count, and a
// change schedules an update.
func (h *Hostname) SetAddrCollection(addrCollection *ipv6disc.AddrCollection) {
	addrCollection = addrCollection.FilterValid()

	h.mutex.Lock()
	changed := !h.addrs.Equal(addrCollection)
	had, has := len(h.addrs.Get()) > 0, len(addrCollection.Get()) > 0
	h.addrs = addrCollection
	switch {
	case has:
		h.hadAddrs = true
		h.emptiedTime = time.Time{}
	case had:
		h.emptiedTime = time.Now()
	}
	if changed {
		h.addrsChanges++
		debounced := time.Now().Add(h.updateDebounceTime)
		reason := updateDebounce
		if h.retryNotBefore.After(debounced) {
			reason = updateRetry
		}
		h.scheduleUpdateAt(latest(debounced, h.retryNotBefore), reason)
	}
	h.mutex.Unlock()
}

// ScheduleUpdate runs an update after timeout, in place of the one scheduled already, and whatever
// the wait after a failure: it is for an update somebody asks for. It sends the addresses again
// even when nothing changed. A name that never had an address has none scheduled: it would remove
// the records, which a start with nothing found yet leaves as they are.
func (h *Hostname) ScheduleUpdate(timeout time.Duration) {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	if !h.hadAddrs {
		return
	}
	h.scheduleUpdateAt(time.Now().Add(timeout), updateAsked)
}

// Why an update waits, as the page says it.
const (
	updateDebounce = "debounce"
	updateRetry    = "retry"
	updateAsked    = "asked"
)

// scheduleUpdateAt runs an update at that time, for reason, in place of the one scheduled already,
// with the mutex held.
func (h *Hostname) scheduleUpdateAt(at time.Time, reason string) {
	if h.stopped {
		return
	}
	h.nextUpdateReason = reason

	if h.nextUpdateTimer != nil {
		h.nextUpdateTimer.Stop()
	}

	asked := reason == updateAsked
	h.nextUpdateTimer = time.AfterFunc(time.Until(at), func() { h.update(asked) })
	h.nextUpdateTime = at
}

func latest(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// update sends the addresses of now to the endpoint, once it is its turn. A timer that has fired
// can't be stopped, so each change that comes while an update runs or waits has its own call
// waiting here: the first to run sends the addresses of the end, and the others, which find them
// sent, return. An asked one sends them all the same.
func (h *Hostname) update(asked bool) {
	h.updateMutex.Lock()
	defer h.updateMutex.Unlock()
	if h.endpointMutex != nil {
		h.endpointMutex.Lock()
		defer h.endpointMutex.Unlock()
	}

	h.mutex.Lock()
	// One that waited here through an update that failed leaves it to the retry, scheduled then.
	if h.stopped || !asked && (h.sent() || time.Now().Before(h.retryNotBefore)) {
		h.mutex.Unlock()
		return
	}
	h.updateRunning = true
	addrs, changes := h.addrs, h.addrsChanges
	h.mutex.Unlock()

	err := h.updateAction(addrs)

	h.mutex.Lock()
	h.updateRunning = false
	h.updateError = err
	h.updates++
	if err == nil {
		h.updatedTime = time.Now()
		h.updatedChanges = changes
		h.retryNotBefore = time.Time{}
	} else {
		h.failures++
		h.retryNotBefore = time.Now().Add(h.updateRetryInterval)
		// Addresses that changed meanwhile have their update scheduled, by the debounce time
		// alone: it waits for the retry too, and is the retry, with the addresses of then.
		if h.addrsChanges == changes || h.nextUpdateTime.Before(h.retryNotBefore) {
			h.scheduleUpdateAt(h.retryNotBefore, updateRetry)
		}
	}
	h.mutex.Unlock()
}

// Stop cancels the update scheduled, and keeps more from being: one running goes on, Wait waits
// for it.
func (h *Hostname) Stop() {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	h.stopped = true
	if h.nextUpdateTimer != nil {
		h.nextUpdateTimer.Stop()
	}
	h.nextUpdateTime = time.Time{}
}

// Wait returns once no update runs.
func (h *Hostname) Wait() {
	h.updateMutex.Lock()
	defer h.updateMutex.Unlock()
}

// sent tells whether the endpoint has the addresses of now: the last update succeeded, and it was
// of them. With the mutex held.
func (h *Hostname) sent() bool {
	return h.updateError == nil && h.updatedChanges == h.addrsChanges
}

// idle tells whether the name has no addresses and nothing left to do about it: none to remove
// at its endpoint, and no update running or failed. A template's name is forgotten then. It goes
// by what was sent, not by the times: the removal may have fired and be waiting for the endpoint,
// behind another name's update, with the records still there.
func (h *Hostname) idle() bool {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	return len(h.addrs.Get()) == 0 && !h.updateRunning && h.sent()
}

func (h *Hostname) status() hostnameStatus {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	return hostnameStatus{
		addrs:            h.addrs,
		updatedTime:      h.updatedTime,
		nextUpdateTime:   h.nextUpdateTime,
		nextUpdateReason: h.nextUpdateReason,
		debounce:         h.updateDebounceTime,
		emptiedTime:      h.emptiedTime,
		updateRunning:    h.updateRunning,
		updateError:      h.updateError,
		updates:          h.updates,
		failures:         h.failures,
	}
}

// NewHostname makes a Hostname that updates with updateAction. A retry interval under a second is
// a second, so that a failing endpoint is not tried without a pause, and a negative debounce time
// is none.
func NewHostname(updateAction func(*ipv6disc.AddrCollection) error, updateDebounceTime time.Duration, updateRetryInterval time.Duration) *Hostname {
	updateDebounceTime = max(updateDebounceTime, 0)
	updateRetryInterval = max(updateRetryInterval, time.Second)
	return &Hostname{
		addrs:               ipv6disc.NewAddrCollection(),
		updateAction:        updateAction,
		updateDebounceTime:  updateDebounceTime,
		updateRetryInterval: updateRetryInterval,
	}
}
