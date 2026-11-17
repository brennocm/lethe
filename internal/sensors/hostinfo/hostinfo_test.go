package hostinfo

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func write(t *testing.T, root, p, content string) {
	t.Helper()
	full := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// fixture: / on dm-1 (LVM) over dm-0 (LUKS); swap on a plain partition and on zram.
func fixture(t *testing.T) string {
	root := t.TempDir()
	write(t, root, "proc/sys/kernel/hostname", "estacao-real\n")
	write(t, root, "etc/locale.conf", "LANG=\"pt_BR.UTF-8\"\n")
	write(t, root, "etc/vconsole.conf", "KEYMAP=br-abnt2\n")
	write(t, root, "etc/default/keyboard", "XKBMODEL=\"pc105\"\nXKBLAYOUT=\"br\"\n")
	_ = os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	_ = os.Symlink("/usr/share/zoneinfo/America/Sao_Paulo", filepath.Join(root, "etc/localtime"))
	write(t, root, "proc/self/mountinfo", "22 1 253:1 / / rw,relatime - ext4 /dev/mapper/vg-root rw\n23 22 0:5 / /dev rw - devtmpfs udev rw\n")
	write(t, root, "sys/dev/block/253:1/dm/uuid", "LVM-abc")
	write(t, root, "sys/dev/block/253:1/slaves/dm-0/dm/uuid", "CRYPT-LUKS2-xyz")
	write(t, root, "proc/swaps", "Filename\tType\tSize\tUsed\tPriority\n/dev/sda3 partition 100 0 -2\n/dev/zram0 partition 100 0 100\n")
	write(t, root, "sys/class/block/sda3/size", "100")
	write(t, root, "etc/chrony/chrony.conf", "pool 2.debian.pool.ntp.org iburst\n")
	return root
}

func TestHOST004_HOST005_HOST006_HOST007_Read(t *testing.T) {
	f := Reader{Root: fixture(t)}.Read()
	if f.Hostname != "estacao-real" || f.Timezone != "America/Sao_Paulo" || f.Locale != "pt_BR.UTF-8" || f.Keyboard != "br" {
		t.Fatalf("%+v", f)
	}
	if f.RootEncrypted == nil || !*f.RootEncrypted {
		t.Fatalf("root on LVM over LUKS must be encrypted: %+v", f.RootEncrypted)
	}
	if !reflect.DeepEqual(f.PlainSwap, []string{"/dev/sda3"}) {
		t.Fatalf("plain swap %v", f.PlainSwap)
	}
	if !reflect.DeepEqual(f.TimeSync, []string{"chrony"}) {
		t.Fatalf("time sync %v", f.TimeSync)
	}
}

func TestHOST006_UnknownAndPlainRoot(t *testing.T) {
	root := t.TempDir()
	if f := (Reader{Root: root}).Read(); f.RootEncrypted != nil || f.Hostname != "" {
		t.Fatalf("empty host: %+v", f)
	}
	write(t, root, "proc/self/mountinfo", "22 1 8:2 / / rw - ext4 /dev/sda2 rw\n")
	write(t, root, "sys/dev/block/8:2/partition", "2")
	if f := (Reader{Root: root}).Read(); f.RootEncrypted == nil || *f.RootEncrypted {
		t.Fatalf("plain partition: %+v", f.RootEncrypted)
	}
}

func TestHOST005_KeyboardFallbacks(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/X11/xorg.conf.d/00-keyboard.conf", "Section \"InputClass\"\n  Option \"XkbLayout\" \"de\"\nEndSection\n")
	if f := (Reader{Root: root}).Read(); f.Keyboard != "de" {
		t.Fatalf("%q", f.Keyboard)
	}
}

func TestPER002_BrowserPrefs(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "prefs.js", "user_pref(\"media.peerconnection.enabled\", true);\nuser_pref(\"network.proxy.type\", 1);\nuser_pref(\"network.proxy.socks\", \"127.0.0.1\");\nuser_pref(\"network.trr.mode\", 2);\n")
	write(t, dir, "user.js", "user_pref(\"media.peerconnection.enabled\", false);\n")
	p := BrowserPrefs(dir)
	if !p.Found || p.PeerConnection || !p.SOCKSProxy || p.SOCKSRemoteDNS || p.TRRMode != 2 {
		t.Fatalf("%+v", p)
	}
	if q := BrowserPrefs(filepath.Join(dir, "none")); q.Found || !q.PeerConnection {
		t.Fatalf("missing profile %+v", q)
	}
	link := t.TempDir()
	_ = os.Symlink(filepath.Join(dir, "prefs.js"), filepath.Join(link, "prefs.js"))
	if q := BrowserPrefs(link); q.Found {
		t.Fatal("a symlinked prefs.js must not be followed")
	}
}

func TestPER002_ChromiumPolicy(t *testing.T) {
	root := t.TempDir()
	write(t, root, "usr/bin/chromium", "")
	if c := (Reader{Root: root}).Chromium(); !c.Installed || c.WebRtcIPHandling != "" {
		t.Fatalf("%+v", c)
	}
	write(t, root, "etc/chromium/policies/managed/lethe.json", `{"WebRtcIPHandling": "disable_non_proxied_udp"}`)
	if c := (Reader{Root: root}).Chromium(); c.WebRtcIPHandling != "disable_non_proxied_udp" {
		t.Fatalf("%+v", c)
	}
}

func TestPER001_ZoneCountries(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "usr/share/zoneinfo")
	_ = os.MkdirAll(dir, 0o755)
	_ = os.WriteFile(filepath.Join(dir, "zone1970.tab"), []byte("# comment\nNL,BE,LU\t+5222+00454\tEurope/Brussels\nBR\t-2332-04637\tAmerica/Sao_Paulo\n"), 0o644)
	z := ZoneCountries(root)
	if strings.Join(z["Europe/Brussels"], ",") != "NL,BE,LU" || z["America/Sao_Paulo"][0] != "BR" {
		t.Fatal(z)
	}
	if len(ZoneCountries(t.TempDir())) != 0 {
		t.Fatal("no tz database")
	}
}
