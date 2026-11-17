// Package gui is lethe-gui (spec §16): the tray, the panel and the full-screen alert. It only
// talks IPC (spec §20.3: it imports internal/contracts, internal/ipc and the operator texts of
// internal/i18n). It never acts on the network or on processes: the daemon does, so a frozen GUI
// changes nothing (spec §10.3).
package gui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"lethe/internal/contracts"
	"lethe/internal/ipc"
)

// Backend is what the GUI asks the daemon.
type Backend interface {
	Status() (contracts.Status, error)
	Recent(limit int) ([]contracts.Event, error)
	Subscribe(ctx context.Context) (<-chan contracts.Event, error)
	Heartbeat() error
	Panic() error
	Ack(id, reason string, pass []byte) error
	Selftest(ctx context.Context, full bool, pass []byte) (contracts.SelftestResult, error)
	Disarm(pass []byte) error
	Unpanic(pass []byte) error
	Fullscreen(r contracts.FullscreenReport) error
	Arm(req ArmRequest) (ArmResult, error)
	CheckNow() error
	DNSLeak(ctx context.Context) (contracts.DNSLeakResult, error)
}

// ArmRequest is session.arm's params (the daemon's ArmRequest: profile and baseline read by the
// operator, the passphrase that decrypts the baseline, the guard chosen in the panel).
type ArmRequest struct {
	Profile    []byte `json:"profile"`
	Baseline   []byte `json:"baseline"`
	Passphrase []byte `json:"passphrase"`
	Guard      string `json:"guard,omitempty"`
}

// ArmResult is the part of session.arm's answer the panel shows.
type ArmResult struct {
	Session string `json:"session"`
}

// Client is the Backend over the daemon socket. Without Socket it tries Others in order (the
// portable daemon, then the service), so the panel finds whichever is running.
type Client struct {
	Socket string
	Others []string
}

const callTimeout = 5 * time.Second

func (c Client) dial() (*ipc.Client, error) {
	if c.Socket != "" {
		return ipc.DialDaemon(c.Socket, 2*time.Second)
	}
	err := errors.New("no daemon socket")
	for _, s := range c.Others {
		var cl *ipc.Client
		if cl, err = ipc.DialDaemon(s, 2*time.Second); err == nil {
			return cl, nil
		}
	}
	return nil, err
}

func (c Client) call(method string, params, out any) error {
	cl, err := c.dial()
	if err != nil {
		return err
	}
	defer func() { _ = cl.Close() }()
	_ = cl.SetDeadline(time.Now().Add(callTimeout))
	return cl.Call(method, params, nil, out)
}

// proved runs method(params) with a passphrase proof (pass nil = no proof).
func (c Client) proved(method string, params any, pass []byte, timeout time.Duration, out any) error {
	cl, err := c.dial()
	if err != nil {
		return err
	}
	defer func() { _ = cl.Close() }()
	_ = cl.SetDeadline(time.Now().Add(timeout))
	var proof *ipc.Auth
	if pass != nil {
		var st contracts.Status
		if err := cl.Call("status.get", nil, nil, &st); err != nil {
			return err
		}
		if len(st.AuthSalt) == 0 {
			return errors.New("no armed session")
		}
		key, err := ipc.DeriveKey(pass, st.AuthSalt)
		if err != nil {
			return err
		}
		proof, err = cl.Prove(key, method, params)
		clear(key)
		if err != nil {
			return err
		}
	}
	return cl.Call(method, params, proof, out)
}

// Status implements Backend.
func (c Client) Status() (contracts.Status, error) {
	var st contracts.Status
	return st, c.call("status.get", nil, &st)
}

// Recent implements Backend.
func (c Client) Recent(limit int) ([]contracts.Event, error) {
	var evs []contracts.Event
	return evs, c.call("events.query", contracts.QueryParams{Limit: limit}, &evs)
}

// Subscribe implements Backend.
func (c Client) Subscribe(ctx context.Context) (<-chan contracts.Event, error) {
	cl, err := c.dial()
	if err != nil {
		return nil, err
	}
	if err := cl.Call("events.subscribe", contracts.QueryParams{}, nil, nil); err != nil {
		_ = cl.Close()
		return nil, err
	}
	ch := make(chan contracts.Event, 64)
	go func() { <-ctx.Done(); _ = cl.Close() }()
	go func() {
		defer close(ch)
		for {
			raw, err := cl.ReadNotification()
			if err != nil {
				return
			}
			var ev contracts.Event
			if json.Unmarshal(raw, &ev) == nil {
				select {
				case ch <- ev:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return ch, nil
}

// Heartbeat implements Backend (SELF-003 sees the GUI by it).
func (c Client) Heartbeat() error { return c.call("heartbeat", nil, nil) }

// Panic implements Backend (no passphrase, spec §10.5).
func (c Client) Panic() error { return c.call("panic.engage", nil, nil) }

// Ack implements Backend.
func (c Client) Ack(id, reason string, pass []byte) error {
	return c.proved("alert.ack", map[string]string{"id": id, "reason": reason}, pass, 20*time.Second, nil)
}

// QuickCases are every selftest case but RESP-001.
func QuickCases() []string {
	return slices.DeleteFunc(slices.Clone(contracts.SelftestCases), func(s string) bool { return s == contracts.Resp001 })
}

// Selftest implements Backend.
func (c Client) Selftest(ctx context.Context, full bool, pass []byte) (contracts.SelftestResult, error) {
	req := contracts.SelftestRequest{Resp: full}
	if !full {
		req.Cases, pass = QuickCases(), nil
	}
	var res contracts.SelftestResult
	done := make(chan error, 1)
	go func() { done <- c.proved("selftest.run", req, pass, 5*time.Minute, &res) }()
	select {
	case err := <-done:
		return res, err
	case <-ctx.Done():
		return res, ctx.Err()
	}
}

// Disarm implements Backend (sensitive).
func (c Client) Disarm(pass []byte) error {
	return c.proved("session.disarm", nil, pass, 30*time.Second, nil)
}

// Unpanic implements Backend (sensitive).
func (c Client) Unpanic(pass []byte) error {
	return c.proved("panic.release", nil, pass, 30*time.Second, nil)
}

// Arm implements Backend. The arm waits for the preflight and, in strict, for the proof that the
// tunnel works (guard.arm_confirm), hence the long deadline.
func (c Client) Arm(req ArmRequest) (ArmResult, error) {
	cl, err := c.dial()
	if err != nil {
		return ArmResult{}, err
	}
	defer func() { _ = cl.Close() }()
	_ = cl.SetDeadline(time.Now().Add(3 * time.Minute))
	var res ArmResult
	return res, cl.Call("session.arm", req, nil, &res)
}

// CheckNow implements Backend.
func (c Client) CheckNow() error { return c.call("active.check_now", nil, nil) }

// DNSLeak implements Backend.
func (c Client) DNSLeak(ctx context.Context) (contracts.DNSLeakResult, error) {
	cl, err := c.dial()
	if err != nil {
		return contracts.DNSLeakResult{}, err
	}
	defer func() { _ = cl.Close() }()
	_ = cl.SetDeadline(time.Now().Add(90 * time.Second))
	go func() { <-ctx.Done(); _ = cl.Close() }()
	var res contracts.DNSLeakResult
	return res, cl.Call("dns.leak_test", nil, nil, &res)
}

// Sockets are where the daemon listens: the portable mode's (sudo lethe run, in the operator's
// runtime directory) and the service's (lethed.service).
func Sockets(uid int) []string {
	return []string{fmt.Sprintf("/run/user/%d/lethe/lethe.sock", uid), "/run/lethe/lethe.sock"}
}

// Fullscreen implements Backend.
func (c Client) Fullscreen(r contracts.FullscreenReport) error {
	return c.call("gui.fullscreen_result", r, nil)
}
