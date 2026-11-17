package gui

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The GUI talks to the daemon only through IPC (spec §20.3): of the core it imports the
// contracts, the IPC client, the operator texts (ADR 0013) and the profile parser, to find the
// baseline a session starts with (ADR 0015); never the daemon, the guard or the sensors.
func TestM13_GUIImportsOnlyContractsIPCAndTexts(t *testing.T) {
	allowed := map[string]bool{"lethe/internal/contracts": true, "lethe/internal/ipc": true, "lethe/internal/i18n": true, "lethe/internal/profile": true}
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") {
			return err
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, im := range f.Imports {
			path, _ := strconv.Unquote(im.Path.Value)
			if strings.HasPrefix(path, "lethe/") && !strings.HasPrefix(path, "lethe/apps/lethe-gui/") && !allowed[path] {
				t.Errorf("%s imports %s", p, path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
