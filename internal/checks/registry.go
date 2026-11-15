package checks

// Registry is the static list of implemented checks (no dynamic loading, spec §5.4).
func Registry() []Check {
	return []Check{
		NET001{}, NET003{}, NET004{}, NET005{}, NET006{}, NET009{}, NET010{}, NET012{}, DNS001{},
	}
}

// ByID finds a registered check.
func ByID(id string) (Check, bool) {
	for _, c := range Registry() {
		if c.ID() == id {
			return c, true
		}
	}
	return nil, false
}
