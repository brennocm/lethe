package tui

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"lethe/internal/contracts"
	"lethe/internal/daemon"
	"lethe/internal/ipc"
)

// Backend is what the TUI asks the daemon. The real one speaks IPC, even inside `run --tui`:
// the TUI goes through the same peer check, proofs and failure budget (SELF-006) as any client.
type Backend interface {
	Status() (daemon.Status, error)
	Recent(limit int) ([]contracts.Event, error)
	// Subscribe streams events until ctx ends; the channel closes when the stream breaks.
	Subscribe(ctx context.Context) (<-chan contracts.Event, error)
	Panic() error
	// Ack acknowledges alert id. pass is nil for a non-CRITICAL alert; Ack never keeps it.
	Ack(id, reason string, pass []byte) error
	// Selftest runs every case (full, RESP-001 included, needs pass) or every case but RESP-001.
	Selftest(ctx context.Context, full bool, pass []byte) (daemon.SelftestResult, error)
}

// IPC is the Backend over the daemon socket.
type IPC struct {
	Socket string
}

const callTimeout = 5 * time.Second

func (b IPC) dial() (*ipc.Client, error) { return ipc.DialDaemon(b.Socket, 2*time.Second) }

func (b IPC) call(method string, params any, out any) error {
	c, err := b.dial()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(callTimeout))
	return c.Call(method, params, nil, out)
}

// Status implements Backend.
func (b IPC) Status() (daemon.Status, error) {
	var st daemon.Status
	return st, b.call("status.get", nil, &st)
}

// Recent implements Backend.
func (b IPC) Recent(limit int) ([]contracts.Event, error) {
	var evs []contracts.Event
	return evs, b.call("events.query", daemon.QueryParams{Limit: limit}, &evs)
}

// Subscribe implements Backend.
func (b IPC) Subscribe(ctx context.Context) (<-chan contracts.Event, error) {
	c, err := b.dial()
	if err != nil {
		return nil, err
	}
	if err := c.Call("events.subscribe", daemon.QueryParams{}, nil, nil); err != nil {
		_ = c.Close()
		return nil, err
	}
	ch := make(chan contracts.Event, 64)
	go func() { <-ctx.Done(); _ = c.Close() }()
	go func() {
		defer close(ch)
		for {
			raw, err := c.ReadNotification()
			if err != nil {
				return
			}
			var ev contracts.Event
			if json.Unmarshal(raw, &ev) != nil {
				continue
			}
			select {
			case ch <- ev:
			case <-ctx.Done():
				return
			}
		}
	}()
	return ch, nil
}

// Panic implements Backend. Engaging the panic needs no passphrase (spec §10.5).
func (b IPC) Panic() error { return b.call("panic.engage", nil, nil) }

// proved runs method(params) with a passphrase proof on one connection.
func (b IPC) proved(method string, params any, pass []byte, timeout time.Duration, out any) error {
	c, err := b.dial()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(timeout))
	var proof *ipc.Auth
	if pass != nil {
		var st daemon.Status
		if err := c.Call("status.get", nil, nil, &st); err != nil {
			return err
		}
		if len(st.AuthSalt) == 0 {
			return errors.New("no armed session")
		}
		key, err := ipc.DeriveKey(pass, st.AuthSalt)
		if err != nil {
			return err
		}
		proof, err = c.Prove(key, method, params)
		clear(key)
		if err != nil {
			return err
		}
	}
	return c.Call(method, params, proof, out)
}

// Ack implements Backend.
func (b IPC) Ack(id, reason string, pass []byte) error {
	return b.proved("alert.ack", map[string]string{"id": id, "reason": reason}, pass, callTimeout+10*time.Second, nil)
}

// QuickCases are every selftest case but RESP-001 (the one that cuts the network).
func QuickCases() []string {
	return slices.DeleteFunc(slices.Clone(daemon.SelftestCases), func(c string) bool { return c == daemon.Resp001 })
}

// Selftest implements Backend.
func (b IPC) Selftest(ctx context.Context, full bool, pass []byte) (daemon.SelftestResult, error) {
	req := daemon.SelftestRequest{Resp: full}
	if !full {
		req.Cases, pass = QuickCases(), nil
	}
	var res daemon.SelftestResult
	done := make(chan error, 1)
	go func() { done <- b.proved("selftest.run", req, pass, 5*time.Minute, &res) }()
	select {
	case err := <-done:
		return res, err
	case <-ctx.Done():
		return res, ctx.Err()
	}
}
