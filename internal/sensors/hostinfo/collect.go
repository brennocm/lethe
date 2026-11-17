package hostinfo

import (
	"encoding/json"
	"path/filepath"
	"time"

	"lethe/internal/sensors/dbusmon"
	"lethe/internal/sensors/procscan"
)

// State is everything the host, persona and preflight checks look at, read in one pass outside
// the daemon lock (D-Bus and /proc reads may be slow).
type State struct {
	Facts    Facts              `json:"facts"`
	Bus      dbusmon.State      `json:"bus"`
	BusRead  bool               `json:"bus_read"` // false = no system bus
	Procs    []procscan.Process `json:"-"`
	Prefs    []Prefs            `json:"-"`
	Chromium ChromiumPolicy     `json:"chromium"`
	Selftest Selftest           `json:"selftest"`
	Errors   []string           `json:"errors"`
}

// Selftest is the last result recorded in storage.dir/state/selftest.json (SELF-004).
type Selftest struct {
	FinishedAt time.Time `json:"finished_at"`
	Passed     bool      `json:"passed"`
	Critical   bool      `json:"critical"` // a failure in ST-NET-001, ST-NET-002 (strict) or RESP-001
}

// Collector reads a State. Zero fields take the production defaults.
type Collector struct {
	Root            string             // files and sysfs ("/")
	ProcRoot        string             // "/proc"
	Bus             func() dbusmon.Bus // nil = no system bus reading
	PersonaProfiles []string           // browsers.persona_profiles
	StateDir        string             // storage.dir/state ("" = no selftest record)
}

// Collect reads every source; a failing one is listed in Errors and leaves its part empty.
func (c Collector) Collect() State {
	st := State{Errors: []string{}}
	st.Facts = Reader{Root: c.Root}.Read()
	st.Chromium = Reader{Root: c.Root}.Chromium()
	proc := c.ProcRoot
	if proc == "" {
		proc = "/proc"
	}
	ps, err := procscan.Scan(proc, procscan.Detail{Cmdline: true, Devices: true})
	if err != nil {
		st.Errors = append(st.Errors, err.Error())
	}
	st.Procs = ps
	for _, p := range c.PersonaProfiles {
		st.Prefs = append(st.Prefs, BrowserPrefs(p))
	}
	if c.Bus != nil {
		if b := c.Bus(); b != nil {
			st.Bus, st.BusRead = dbusmon.Reader{Bus: b}.Read(), true
			st.Errors = append(st.Errors, st.Bus.Unavailable...)
		}
	}
	if c.StateDir != "" {
		var s Selftest
		if json.Unmarshal(readNoFollow(filepath.Join(c.StateDir, "selftest.json"), 1<<20), &s) == nil {
			st.Selftest = s
		}
	}
	return st
}

// Timezone, Locale and Keyboard prefer the files and fall back to timedate1 / locale1.
func (s State) Timezone() string { return firstNonEmpty(s.Facts.Timezone, s.Bus.Timezone) }
func (s State) Locale() string   { return firstNonEmpty(s.Facts.Locale, s.Bus.Locale) }
func (s State) Keyboard() string { return firstNonEmpty(s.Bus.Keyboard, s.Facts.Keyboard) }
