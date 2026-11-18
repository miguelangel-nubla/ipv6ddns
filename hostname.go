package ipv6ddns

import (
	"sync"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
)

// Hostname keeps the records of one name at one endpoint in step with its addresses: once they
// stop changing for the debounce time it updates the records, and after a failure it tries again
// at every retry interval.
type Hostname struct {
	mutex sync.Mutex
	addrs *ipv6disc.AddrCollection

	updatedTime     time.Time
	nextUpdateTime  time.Time
	nextUpdateTimer *time.Timer
	updateRunning   bool
	updateError     error

	// One update at a time.
	updateMutex sync.Mutex

	updateAction        func(*ipv6disc.AddrCollection) error
	updateDebounceTime  time.Duration
	updateRetryInterval time.Duration
}

// hostnameStatus is a snapshot of a Hostname, for display.
type hostnameStatus struct {
	addrs          *ipv6disc.AddrCollection
	updatedTime    time.Time
	nextUpdateTime time.Time
	updateRunning  bool
	updateError    error
}

// SetAddrCollection sets the addresses the name should have. The valid ones only count, and a
// change schedules an update.
func (h *Hostname) SetAddrCollection(addrCollection *ipv6disc.AddrCollection) {
	addrCollection = addrCollection.FilterValid()

	h.mutex.Lock()
	changed := !h.addrs.Equal(addrCollection)
	h.addrs = addrCollection
	h.mutex.Unlock()

	if changed {
		h.ScheduleUpdate(h.updateDebounceTime)
	}
}

// ScheduleUpdate runs an update after timeout, in place of the one scheduled already.
func (h *Hostname) ScheduleUpdate(timeout time.Duration) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if h.nextUpdateTimer != nil {
		h.nextUpdateTimer.Stop()
	}

	h.nextUpdateTimer = time.AfterFunc(timeout, h.update)
	h.nextUpdateTime = time.Now().Add(timeout)
}

func (h *Hostname) update() {
	h.updateMutex.Lock()
	defer h.updateMutex.Unlock()

	h.mutex.Lock()
	h.updateRunning = true
	addrs := h.addrs
	h.mutex.Unlock()

	err := h.updateAction(addrs)

	h.mutex.Lock()
	h.updateRunning = false
	h.updateError = err
	if err == nil {
		h.updatedTime = time.Now()
	}
	h.mutex.Unlock()

	if err != nil {
		h.ScheduleUpdate(h.updateRetryInterval)
	}
}

func (h *Hostname) status() hostnameStatus {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	return hostnameStatus{
		addrs:          h.addrs,
		updatedTime:    h.updatedTime,
		nextUpdateTime: h.nextUpdateTime,
		updateRunning:  h.updateRunning,
		updateError:    h.updateError,
	}
}

func NewHostname(updateAction func(*ipv6disc.AddrCollection) error, updateDebounceTime time.Duration, updateRetryInterval time.Duration) *Hostname {
	return &Hostname{
		addrs:               ipv6disc.NewAddrCollection(),
		updateAction:        updateAction,
		updateDebounceTime:  updateDebounceTime,
		updateRetryInterval: updateRetryInterval,
	}
}
