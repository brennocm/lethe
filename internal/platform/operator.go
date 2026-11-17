// Package platform detects facts about the host: the operator behind sudo, kernel features, distro.
package platform

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
)

// Operator is the human running lethe (the sudo caller when run through sudo).
type Operator struct {
	UID  int
	GID  int
	Name string
	Home string
}

// CurrentOperator resolves SUDO_UID/SUDO_GID when present, else the current user.
func CurrentOperator(getenv func(string) string) (Operator, error) {
	if s := getenv("SUDO_UID"); s != "" {
		u, err := user.LookupId(s)
		if err != nil {
			return Operator{}, err
		}
		return fromUser(u), nil
	}
	u, err := user.Current()
	if err != nil {
		return Operator{}, err
	}
	op := fromUser(u)
	if op.Home == "" {
		op.Home, _ = os.UserHomeDir()
	}
	return op, nil
}

// ServiceOperator is the operator of service mode (lethed.service runs as root with no sudo):
// the user named by LETHE_OPERATOR, which the unit's drop-in declares. Root, an unknown name or
// no name at all is refused: the socket would then admit only root and the operator could never
// acknowledge an alert (fail-closed, and said at start rather than at the first alert).
func ServiceOperator(getenv func(string) string) (Operator, error) {
	name := getenv("LETHE_OPERATOR")
	if name == "" {
		return Operator{}, errors.New("LETHE_OPERATOR is not set: declare the operator in a drop-in (systemctl edit lethed: Environment=LETHE_OPERATOR=<user>)")
	}
	u, err := user.Lookup(name)
	if err != nil {
		return Operator{}, fmt.Errorf("LETHE_OPERATOR: %w", err)
	}
	op := fromUser(u)
	if op.UID == 0 {
		return Operator{}, errors.New("LETHE_OPERATOR is root: name the user who operates, not root")
	}
	return op, nil
}

func fromUser(u *user.User) Operator {
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	return Operator{UID: uid, GID: gid, Name: u.Username, Home: u.HomeDir}
}
