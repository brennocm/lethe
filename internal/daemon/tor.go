package daemon

import (
	"io"
	"reflect"
	"sync"

	"lethe/internal/discovery"
	"lethe/internal/discovery/torctl"
)

// asyncTor keeps tor's last answer so that discovery passes, which run under d.mu, never wait on
// the control port: a slow tor would otherwise delay panic (≤ 200 ms) behind the lock. The first
// query (at arm) is synchronous; later ones return the cached answer and refresh it in the
// background, signalling Changed when it differs. Tor's own events refresh it as well.
type asyncTor struct {
	src     discovery.TorSource
	changed chan struct{}

	mu     sync.Mutex
	st     torctl.Status
	err    error
	primed bool
	busy   bool
	once   sync.Once
}

func newAsyncTor(src discovery.TorSource) *asyncTor {
	return &asyncTor{src: src, changed: make(chan struct{}, 1)}
}

// Status implements discovery.TorSource.
func (a *asyncTor) Status() (torctl.Status, error) {
	a.once.Do(a.forward)
	a.mu.Lock()
	if !a.primed {
		a.mu.Unlock()
		st, err := a.src.Status()
		a.mu.Lock()
		a.st, a.err, a.primed = st, err, true
		a.mu.Unlock()
		return st, err
	}
	defer a.mu.Unlock()
	a.kickLocked()
	return a.st, a.err
}

func (a *asyncTor) kickLocked() {
	if a.busy {
		return
	}
	a.busy = true
	go func() {
		st, err := a.src.Status()
		a.mu.Lock()
		diff := !reflect.DeepEqual(st, a.st) || errString(err) != errString(a.err)
		a.st, a.err, a.busy = st, err, false
		a.mu.Unlock()
		if diff {
			a.notify()
		}
	}()
}

// forward turns the source's own change signal (tor events) into a refresh.
func (a *asyncTor) forward() {
	n, ok := a.src.(interface{ Changed() <-chan struct{} })
	if !ok {
		return
	}
	ch := n.Changed()
	go func() {
		for range ch {
			a.mu.Lock()
			a.kickLocked()
			a.mu.Unlock()
		}
	}()
}

// Changed is signalled when a background refresh found a different answer.
func (a *asyncTor) Changed() <-chan struct{} { return a.changed }

func (a *asyncTor) notify() {
	select {
	case a.changed <- struct{}{}:
	default:
	}
}

// Close closes the source.
func (a *asyncTor) Close() error {
	if c, ok := a.src.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
