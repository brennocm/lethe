// Package platform detects facts about the host: the operator behind sudo, kernel features, distro.
package platform

import (
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

func fromUser(u *user.User) Operator {
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	return Operator{UID: uid, GID: gid, Name: u.Username, Home: u.HomeDir}
}
