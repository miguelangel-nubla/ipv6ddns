package ipv6ddns

import (
	"sync"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
)

type Hostname struct {
	ipv6disc.AddrCollection

	mutex sync.RWMutex

	updatedTime time.Time

	nextUpdateTime  time.Time
	nextUpdateTimer *time.Timer

	updateRunning bool
	updateError   error

	updateAction        func(*ipv6disc.AddrCollection) error
	updateDebounceTime  time.Duration
	updateRetryInterval time.Duration
}

func (h *Hostname) SetAddrCollection(addrCollection *ipv6disc.AddrCollection) {
	addrCollection = addrCollection.FilterValid()
	if !h.AddrCollection.Equal(addrCollection) {
		h.AddrCollection.Join(addrCollection)
		h.ScheduleUpdate(h.updateDebounceTime)
	}

	h.mutex.Lock()
	h.AddrCollection = *h.AddrCollection.FilterValid()
	h.mutex.Unlock()
}

func (h *Hostname) ScheduleUpdate(timeout time.Duration) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	// stop the current update timer if it exists
	if h.nextUpdateTimer != nil {
		h.nextUpdateTimer.Stop()
		h.nextUpdateTime = time.Time{}
	}

	h.nextUpdateTimer = time.AfterFunc(timeout, h.update)
	h.nextUpdateTime = time.Now().Add(timeout)
}

func (h *Hostname) update() {
	h.updateRunning = true

	h.updateError = h.updateAction(&h.AddrCollection)
	if h.updateError == nil {
		h.updatedTime = time.Now()
	} else {
		h.ScheduleUpdate(h.updateRetryInterval)
	}

	h.updateRunning = false
}

func NewHostname(updateAction func(*ipv6disc.AddrCollection) error, updateDebounceTime time.Duration, updateRetryInterval time.Duration) *Hostname {
	return &Hostname{
		AddrCollection:      *ipv6disc.NewAddrCollection(),
		updateAction:        updateAction,
		updateDebounceTime:  updateDebounceTime,
		updateRetryInterval: updateRetryInterval,
	}
}
