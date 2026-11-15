// Package engine holds every decision rule of lethe as pure code: severity overrides,
// deduplication, alert lifecycle, global color, session state machine and response plans
// (spec §5.3, §6, §10). It performs no I/O and never reads the wall clock directly.
package engine

import "time"

// Clock supplies the current time. Production passes a real clock; tests pass a fake.
type Clock interface {
	Now() time.Time
}

// FakeClock is a manually advanced clock for tests and simulations.
type FakeClock struct{ T time.Time }

// Now returns the fake time.
func (c *FakeClock) Now() time.Time { return c.T }

// Advance moves the fake clock forward.
func (c *FakeClock) Advance(d time.Duration) { c.T = c.T.Add(d) }
