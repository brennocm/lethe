package journal

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

// FuzzReadSegment mutates a valid segment and requires Read/Verify to fail cleanly, never panic.
func FuzzReadSegment(f *testing.F) {
	fx := newFixture(f, nil)
	fx.add(f, 3)
	_ = fx.w.Close(nil)
	seg := filepath.Join(fx.dir, segmentName(1))
	orig, err := os.ReadFile(seg)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(orig)
	f.Add(orig[:len(orig)/2])
	f.Add([]byte("{}\n"))
	ids := []age.Identity{fx.id}
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, segmentName(1)), data, 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := Read(dir, ids)
		if err != nil {
			return
		}
		_, _ = Verify(s, "")
	})
}
