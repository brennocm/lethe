// Package i18n holds the operator texts (spec §16.6): the short title, the meaning and what to
// do for every check, and the strings of the TUI. The files are a small TOML subset read here,
// without a TOML dependency (ADR 0012): comments (#), [section] headers and key = "text" lines,
// with \" and \\ escapes. They are embedded and trusted (repository files); a malformed file
// fails the tests, and Load falls back to the key itself at run time.
package i18n

import (
	"embed"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

//go:embed *.toml
var files embed.FS

// Langs are the shipped languages; Default is used for anything else.
var Langs = []string{"en-US", "pt-BR"}

// Default language.
const Default = "en-US"

// Table is one language: section → key → text.
type Table map[string]map[string]string

var (
	once   sync.Once
	tables map[string]Table
	errs   error
)

func load() {
	tables = map[string]Table{}
	for _, l := range Langs {
		raw, err := files.ReadFile(l + ".toml")
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		t, err := Parse(string(raw))
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("%s.toml: %w", l, err))
		}
		tables[l] = t
	}
}

// Tables returns every language and the parse errors (tests).
func Tables() (map[string]Table, error) {
	once.Do(load)
	return tables, errs
}

// Norm maps a ui.language value to a shipped language.
func Norm(lang string) string {
	switch strings.ToLower(lang) {
	case "pt", "pt-br", "pt_br":
		return "pt-BR"
	}
	return Default
}

// Text is section.key in lang, falling back to en-US and then to the key itself.
func Text(lang, section, key string) string {
	once.Do(load)
	for _, l := range []string{Norm(lang), Default} {
		if v, ok := tables[l][section][key]; ok {
			return v
		}
	}
	return key
}

// UI is a [ui] string.
func UI(lang, key string) string { return Text(lang, "ui", key) }

// Check is the text of one check.
type Check struct{ Title, Meaning, Todo string }

// CheckText returns the texts of check id (the id itself as the title when unknown).
func CheckText(lang, id string) Check {
	c := Check{Title: Text(lang, id, "title"), Meaning: Text(lang, id, "meaning"), Todo: Text(lang, id, "todo")}
	if c.Title == "title" {
		c.Title = id
	}
	if c.Meaning == "meaning" {
		c.Meaning = ""
	}
	if c.Todo == "todo" {
		c.Todo = ""
	}
	return c
}

// CheckIDs lists the checks that have texts, sorted (the GUI grid).
func CheckIDs() []string {
	once.Do(load)
	var ids []string
	for sec := range tables[Default] {
		if sec != "ui" && sec != "actions" {
			ids = append(ids, sec)
		}
	}
	sort.Strings(ids)
	return ids
}

// Parse reads the TOML subset.
func Parse(src string) (Table, error) {
	t := Table{}
	section := ""
	for n, line := range strings.Split(src, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") || len(line) < 3 {
				return t, fmt.Errorf("line %d: bad section header", n+1)
			}
			section = line[1 : len(line)-1]
			if _, dup := t[section]; dup {
				return t, fmt.Errorf("line %d: section [%s] repeated", n+1, section)
			}
			t[section] = map[string]string{}
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		if !ok || key == "" || section == "" {
			return t, fmt.Errorf("line %d: expected key = \"text\" inside a section", n+1)
		}
		s, err := unquote(val)
		if err != nil {
			return t, fmt.Errorf("line %d: %w", n+1, err)
		}
		if _, dup := t[section][key]; dup {
			return t, fmt.Errorf("line %d: key %s.%s repeated", n+1, section, key)
		}
		t[section][key] = s
	}
	return t, nil
}

func unquote(v string) (string, error) {
	if len(v) < 2 || v[0] != '"' {
		return "", errors.New("the value must be a double-quoted string")
	}
	var b strings.Builder
	for i := 1; i < len(v); i++ {
		c := v[i]
		switch {
		case c == '\\' && i+1 < len(v):
			i++
			switch v[i] {
			case '"', '\\':
				b.WriteByte(v[i])
			case 'n':
				b.WriteByte('\n')
			default:
				return "", fmt.Errorf("unknown escape \\%c", v[i])
			}
		case c == '"':
			if rest := strings.TrimSpace(v[i+1:]); rest != "" && !strings.HasPrefix(rest, "#") {
				return "", errors.New("text after the closing quote")
			}
			return b.String(), nil
		default:
			b.WriteByte(c)
		}
	}
	return "", errors.New("unterminated string")
}
