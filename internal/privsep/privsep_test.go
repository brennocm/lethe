package privsep

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivsep_KeepMask(t *testing.T) {
	// NET_RAW 13, NET_ADMIN 12, KILL 5, SYS_PTRACE 19, DAC_READ_SEARCH 2, IPC_LOCK 14
	want := uint64(1<<13 | 1<<12 | 1<<5 | 1<<19 | 1<<2 | 1<<14)
	if KeepMask() != want {
		t.Fatalf("mask %x want %x", KeepMask(), want)
	}
}

func TestPrivsep_ReadStatus(t *testing.T) {
	p := filepath.Join(t.TempDir(), "status")
	_ = os.WriteFile(p, []byte("Name:\tlethe\nCapInh:\t0000000000000000\nCapPrm:\t0000000000087024\nCapEff:\t0000000000087024\nCapBnd:\t0000000000087024\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n"), 0o644)
	st, err := ReadStatus(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Eff != 0x87024 || st.Prm != st.Eff || st.Bnd != st.Eff || st.Inh != 0 || st.Amb != 0 || !st.NoNewPrivs {
		t.Fatalf("%+v", st)
	}
	self, err := ReadStatus("/proc/self/status")
	if err != nil || self.Bnd == 0 {
		t.Fatalf("%+v %v", self, err)
	}
	if _, err := ReadStatus(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing file")
	}
}
