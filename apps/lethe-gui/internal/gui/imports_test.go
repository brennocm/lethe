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
// contracts, the IPC client, the operator texts (ADR 0013), the profile parser, to find the
// baseline a session starts with, and the first-use creation (internal/setup, which itself never
// reaches the guard, the responses or the daemon: ADR 0015); never the daemon or the guard.
func TestM13_GUIImportsOnlyContractsIPCAndTexts(t *testing.T) {
	allowed := map[string]bool{"lethe/internal/contracts": true, "lethe/internal/ipc": true, "lethe/internal/i18n": true, "lethe/internal/profile": true,
		"lethe/internal/setup": true, "lethe/internal/buildinfo": true}
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
			testOnly := strings.HasSuffix(p, "_test.go") && path == "lethe/internal/baseline" // tests open what the form wrote
			if strings.HasPrefix(path, "lethe/") && !strings.HasPrefix(path, "lethe/apps/lethe-gui/") && !allowed[path] && !testOnly {
				t.Errorf("%s imports %s", p, path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
