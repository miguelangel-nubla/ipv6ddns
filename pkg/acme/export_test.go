package acme

import "time"

// SetNow sets the clock a manager looks at a certificate with, for the live test to look at one
// later than it is: a certificate just got is never due, whatever RenewBefore.
func (m *Manager) SetNow(now func() time.Time) { m.now = now }
