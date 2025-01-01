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

	updateAction        func() error
	updateRetryInterval time.Duration
}

func (hostname *Hostname) ScheduleUpdate(debounceTime time.Duration, action func() error) {
	hostname.mutex.Lock()
	// stop the current update timer if it exists
	if hostname.nextUpdateTimer != nil {
		hostname.nextUpdateTimer.Stop()
		hostname.nextUpdateTime = time.Time{}
	}
	hostname.updateAction = action
	hostname.updateRetryInterval = debounceTime
	hostname.mutex.Unlock()
	hostname.reScheduleUpdate()
}

func (hostname *Hostname) update() {
	hostname.mutex.Lock()
	hostname.updateRunning = true
	hostname.mutex.Unlock()

	// no mutex lock while working
	err := hostname.updateAction()

	hostname.mutex.Lock()
	hostname.updateError = err
	if hostname.updateError == nil {
		hostname.updatedTime = time.Now()
	} else {
		hostname.reScheduleUpdate()
	}
	hostname.updateRunning = false
	hostname.mutex.Unlock()
}

func (hostname *Hostname) reScheduleUpdate() {
	hostname.mutex.Lock()
	defer hostname.mutex.Unlock()

	// stop the current update timer if it exists
	if hostname.nextUpdateTimer != nil {
		hostname.nextUpdateTimer.Stop()
		hostname.nextUpdateTime = time.Time{}
	}

	hostname.nextUpdateTimer = time.AfterFunc(hostname.updateRetryInterval, hostname.update)
	hostname.nextUpdateTime = time.Now().Add(hostname.updateRetryInterval)
}

func NewHostname() *Hostname {
	return &Hostname{
		AddrCollection: *ipv6disc.NewAddrCollection(),
	}
}
