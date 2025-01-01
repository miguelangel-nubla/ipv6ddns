package ipv6ddns

import (
	"sync"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
)

type AddressFamily string

const (
	IPv4 AddressFamily = "ipv4"
	IPv6 AddressFamily = "ipv6"
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

func (h *Hostname) SetState(addressFamily AddressFamily, addrCollection *ipv6disc.AddrCollection) {
	var oldHosts *ipv6disc.AddrCollection
	switch addressFamily {
	case IPv4:
		oldHosts = h.AddrCollection.Filter4()
	default:
		oldHosts = h.AddrCollection.Filter6()
	}

	if !oldHosts.Equal(addrCollection) {
		h.AddrCollection.Join(addrCollection)
		h.ScheduleUpdate(h.updateDebounceTime)
	}
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
