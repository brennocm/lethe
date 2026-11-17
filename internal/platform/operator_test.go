package platform

import (
	"os"
	"os/user"
	"strconv"
	"strings"
	"testing"
)

func TestCurrentOperator(t *testing.T) {
	op, err := CurrentOperator(func(string) string { return "" })
	if err != nil || op.UID != os.Getuid() || op.Home == "" {
		t.Fatalf("%+v %v", op, err)
	}
	uid := strconv.Itoa(os.Getuid())
	op2, err := CurrentOperator(func(k string) string {
		if k == "SUDO_UID" {
			return uid
		}
		return ""
	})
	if err != nil || op2.UID != op.UID {
		t.Fatalf("%+v %v", op2, err)
	}
	if _, err := CurrentOperator(func(k string) string { return "999999999" }); err == nil {
		t.Fatal("unknown SUDO_UID accepted")
	}
}

func TestPlatform_TermSafe(t *testing.T) {
	if got := TermSafe("exe=/tmp/\x1b]0;pwned\x07x\u009b31m ok"); got != "exe=/tmp/?]0;pwned?x?31m ok" {
		t.Fatalf("%q", got)
	}
}

func TestM14_ServiceOperator(t *testing.T) {
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == "LETHE_OPERATOR" {
				return v
			}
			return ""
		}
	}
	if _, err := ServiceOperator(env("")); err == nil || !strings.Contains(err.Error(), "systemctl edit lethed") {
		t.Fatalf("no operator must be refused with the way out: %v", err)
	}
	if _, err := ServiceOperator(env("root")); err == nil {
		t.Fatal("root accepted as the operator")
	}
	if _, err := ServiceOperator(env("no-such-user-lethe")); err == nil {
		t.Fatal("unknown user accepted")
	}
	me, err := user.Current()
	if err != nil || me.Uid == "0" {
		t.Skip("needs a non-root user")
	}
	if op, err := ServiceOperator(env(me.Username)); err != nil || strconv.Itoa(op.UID) != me.Uid {
		t.Fatalf("%+v %v", op, err)
	}
}
