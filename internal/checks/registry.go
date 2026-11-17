package checks

// Registry is the static list of implemented checks (no dynamic loading, spec §5.4).
func Registry() []Check {
	return []Check{
		NET001{}, NET002{}, NET003{}, NET004{}, NET005{}, NET006{}, NET007{}, NET008{}, NET009{}, NET010{}, NET012{},
		NET013{}, NET014{}, DNS001{}, DNS004{},
		TUN001{}, TUN002{}, TUN003{}, TUN004{}, TUN005{}, TUN006{}, TUN007{}, TUN008{},
		HOST001{}, HOST002{}, HOST003{}, HOST004{}, HOST005{}, HOST006{}, HOST007{}, HOST008{}, HOST009{},
		PER001{}, PER002{}, PER003{},
		SELF001{}, SELF002{}, SELF003{}, SELF004{}, SELF005{}, SELF006{},
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
