// Package contracts holds the JSON Schemas that are the single source of truth for every
// machine-readable format of lethe (events, IPC, profile, --json outputs) and validates against them.
package contracts

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed schemas/*.json
var schemaFS embed.FS

var (
	compileOnce sync.Once
	compiled    map[string]*jsonschema.Schema
	compileErr  error
)

// Names lists every embedded schema by short name ("version", "event", ...).
func Names() []string {
	entries, err := schemaFS.ReadDir("schemas")
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, strings.TrimSuffix(e.Name(), ".schema.json"))
	}
	return names
}

func compileAll() {
	c := jsonschema.NewCompiler()
	compiled = map[string]*jsonschema.Schema{}
	for _, name := range Names() {
		raw, err := schemaFS.ReadFile(path.Join("schemas", name+".schema.json"))
		if err != nil {
			compileErr = err
			return
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			compileErr = fmt.Errorf("parse schema %s: %w", name, err)
			return
		}
		if err := c.AddResource("lethe:"+name, doc); err != nil {
			compileErr = fmt.Errorf("add schema %s: %w", name, err)
			return
		}
	}
	for _, name := range Names() {
		s, err := c.Compile("lethe:" + name)
		if err != nil {
			compileErr = fmt.Errorf("compile schema %s: %w", name, err)
			return
		}
		compiled[name] = s
	}
}

// ValidateJSON validates raw JSON bytes against the named schema.
func ValidateJSON(name string, raw []byte) error {
	compileOnce.Do(compileAll)
	if compileErr != nil {
		return compileErr
	}
	s, ok := compiled[name]
	if !ok {
		return fmt.Errorf("unknown schema %q", name)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("decode JSON for schema %s: %w", name, err)
	}
	if err := s.Validate(doc); err != nil {
		return fmt.Errorf("schema %s: %w", name, err)
	}
	return nil
}

// Validate marshals v and validates it against the named schema.
func Validate(name string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal for schema %s: %w", name, err)
	}
	return ValidateJSON(name, raw)
}
