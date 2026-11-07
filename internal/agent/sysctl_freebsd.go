//go:build freebsd

package agent

import (
	"os/exec"
	"strings"
)

func sysctlString(name string) (string, error) {
	out, err := exec.Command("sysctl", "-n", name).Output()
	return strings.TrimSpace(string(out)), err
}
