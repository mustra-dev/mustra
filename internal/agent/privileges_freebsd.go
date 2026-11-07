//go:build freebsd

package agent

import (
	"context"
	"os"
	"os/user"

	"github.com/mustra-dev/mustra/internal/proto"
)

// collectPrivileges reports what the agent can do on FreeBSD. There are no
// capabilities to narrow root here; a jail is the one thing that does, and
// it is reported when the agent runs in one.
func collectPrivileges(ctx context.Context) (proto.PrivilegeInfo, error) {
	info := proto.PrivilegeInfo{UID: os.Geteuid(), Elevated: os.Geteuid() == 0, Service: "rc.d"}
	if u, err := user.Current(); err == nil {
		info.Account = u.Username
	}
	if !info.Elevated {
		info.Limitations = append(info.Limitations,
			"the agent is not running as root, so it cannot install packages or manage services")
		info.Remedy = append(info.Remedy, "reinstall as root; the installer registers an rc.d service, which runs as root")
	} else if out, err := sysctlString("security.jail.jailed"); err == nil && out == "1" {
		info.Limitations = append(info.Limitations, "running in a jail, which limits what root can see and change")
		info.Remedy = append(info.Remedy, "install the agent on the jail host to manage the whole system")
	}
	info.FullRights = len(info.Limitations) == 0
	return info, nil
}
