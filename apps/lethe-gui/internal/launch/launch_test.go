package launch

import (
	"testing"

	"fyne.io/fyne/v2/test"
)

// What main runs compiles and builds a panel (the GL driver aside), so a missing method can no
// longer hide behind cgo.
func TestM13_LaunchBuildsThePanel(t *testing.T) {
	if _, err := Setup(test.NewTempApp(t), []string{"--lang", "en-US", "--socket", t.TempDir() + "/none.sock"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Setup(test.NewTempApp(t), []string{"--bogus"}); err == nil {
		t.Fatal("unknown flag accepted")
	}
}
