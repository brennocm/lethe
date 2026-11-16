package cli

import "errors"

// Exit codes (spec §15.2).
const (
	ExitOK              = 0
	ExitGeneric         = 1
	ExitPreflightFailed = 2
	ExitSessionCritical = 3
	ExitIntegrity       = 4
	ExitAuth            = 5
	ExitArmUnconfirmed  = 6
	ExitPrivileges      = 10
	ExitRequirement     = 11
	ExitDaemonDown      = 12
)

// ExitError carries a specific exit code up to Execute.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string { return e.Err.Error() }
func (e *ExitError) Unwrap() error { return e.Err }

// WithCode wraps err so that Execute exits with code.
func WithCode(code int, err error) error {
	if err == nil {
		return nil
	}
	return &ExitError{Code: code, Err: err}
}

func exitCode(err error) int {
	if err == nil {
		return ExitOK
	}
	var ee *ExitError
	if errors.As(err, &ee) {
		return ee.Code
	}
	return ExitGeneric
}
