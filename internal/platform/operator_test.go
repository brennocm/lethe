package platform

import (
	"os"
	"strconv"
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
