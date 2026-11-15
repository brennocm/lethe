package engine

import (
	"errors"
	"testing"
)

// TestSession_ExhaustiveTransitions checks every (state, command) pair against spec §6.1.
func TestSession_ExhaustiveTransitions(t *testing.T) {
	want := map[SessionState]map[Command]SessionState{
		StateNoBaseline: {CmdBaselineCreated: StateReady},
		StateReady: {CmdBaselineCreated: StateReady, CmdPreflightPass: StateVerified,
			CmdPreflightFail: StateReady, CmdArmForce: StateArmed},
		StateVerified: {CmdPreflightPass: StateVerified, CmdPreflightFail: StateReady,
			CmdArm: StateArmed, CmdArmForce: StateArmed},
		StateArmed: {CmdPanic: StatePanic, CmdDisarm: StateReady},
		StatePanic: {CmdPanic: StatePanic, CmdUnpanic: StateArmed},
	}
	for _, s := range SessionStates() {
		for _, c := range Commands() {
			got, err := Next(s, c)
			exp, ok := want[s][c]
			switch {
			case ok && (err != nil || got != exp):
				t.Errorf("%s + %s = %s, %v; want %s", s, c, got, err, exp)
			case !ok && !errors.Is(err, ErrInvalidTransition):
				t.Errorf("%s + %s should be invalid, got %s", s, c, got)
			case !ok && got != s:
				t.Errorf("%s + %s invalid but state changed to %s", s, c, got)
			}
		}
	}
}

func TestSession_ArmWithoutPreflightRejected(t *testing.T) {
	e := New(&FakeClock{}, Config{}, StateReady)
	if _, err := e.Apply(CmdArm); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("arm from READY must need preflight or --force, got %v", err)
	}
	if s, err := e.Apply(CmdArmForce); err != nil || s != StateArmed {
		t.Fatalf("arm --force: %s %v", s, err)
	}
}

func TestSession_ApplyRejectsUnpanic(t *testing.T) {
	e := New(&FakeClock{}, Config{}, StatePanic)
	if _, err := e.Apply(CmdUnpanic); err == nil {
		t.Fatal("Apply(unpanic) must be refused; Unpanic checks preconditions")
	}
}
