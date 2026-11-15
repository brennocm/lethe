package engine

import (
	"errors"
	"fmt"
)

// SessionState is the operation lifecycle state (spec §6.1).
type SessionState string

const (
	StateNoBaseline SessionState = "NO_BASELINE"
	StateReady      SessionState = "READY"
	StateVerified   SessionState = "VERIFIED"
	StateArmed      SessionState = "ARMED"
	StatePanic      SessionState = "PANIC"
)

// SessionStates lists every state (for exhaustive tests).
func SessionStates() []SessionState {
	return []SessionState{StateNoBaseline, StateReady, StateVerified, StateArmed, StatePanic}
}

// Command is an input to the session state machine.
type Command string

const (
	CmdBaselineCreated Command = "baseline_created"
	CmdPreflightPass   Command = "preflight_pass"
	CmdPreflightFail   Command = "preflight_fail"
	CmdArm             Command = "arm"
	CmdArmForce        Command = "arm_force"
	CmdPanic           Command = "panic"
	CmdUnpanic         Command = "unpanic"
	CmdDisarm          Command = "disarm"
)

// Commands lists every command (for exhaustive tests).
func Commands() []Command {
	return []Command{CmdBaselineCreated, CmdPreflightPass, CmdPreflightFail, CmdArm, CmdArmForce, CmdPanic, CmdUnpanic, CmdDisarm}
}

// ErrInvalidTransition is returned for any (state, command) pair not in the transition table.
var ErrInvalidTransition = errors.New("invalid session transition")

type transitionKey struct {
	from SessionState
	cmd  Command
}

// transitions is the complete table. Anything absent is invalid. Disarm is not allowed from
// PANIC: the operator must unpanic (re-check + passphrase) first; root can still run cleanup.
var transitions = map[transitionKey]SessionState{
	{StateNoBaseline, CmdBaselineCreated}: StateReady,
	{StateReady, CmdBaselineCreated}:      StateReady,
	{StateReady, CmdPreflightPass}:        StateVerified,
	{StateReady, CmdPreflightFail}:        StateReady,
	{StateReady, CmdArmForce}:             StateArmed,
	{StateVerified, CmdPreflightPass}:     StateVerified,
	{StateVerified, CmdPreflightFail}:     StateReady,
	{StateVerified, CmdArm}:               StateArmed,
	{StateVerified, CmdArmForce}:          StateArmed,
	{StateArmed, CmdPanic}:                StatePanic,
	{StateArmed, CmdDisarm}:               StateReady,
	{StatePanic, CmdPanic}:                StatePanic,
	{StatePanic, CmdUnpanic}:              StateArmed,
}

// Next returns the state reached by applying cmd in from, or ErrInvalidTransition.
func Next(from SessionState, cmd Command) (SessionState, error) {
	to, ok := transitions[transitionKey{from, cmd}]
	if !ok {
		return from, fmt.Errorf("%w: %s in %s", ErrInvalidTransition, cmd, from)
	}
	return to, nil
}
