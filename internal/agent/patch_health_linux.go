//go:build linux

package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// A box too sick to answer systemctl within this is reported as such
// rather than waited on.
const systemctlTimeout = 30 * time.Second

// sampleUnits reads every loaded service from systemd, inactive and
// failed ones included, in one call as restartStaleServices does.
func sampleUnits(ctx context.Context) (map[string]unitState, error) {
	if fi, err := os.Stat("/run/systemd/system"); err != nil || !fi.IsDir() {
		return nil, errUnitsUnsupported
	}
	cctx, cancel := context.WithTimeout(ctx, systemctlTimeout)
	defer cancel()
	out, err := exec.CommandContext(cctx, "systemctl", "show", "--type=service", "--all", "--no-pager",
		"--property=Id,LoadState,ActiveState,SubState,UnitFileState,NRestarts", "*").Output()
	if err != nil {
		if cctx.Err() != nil {
			return nil, fmt.Errorf("systemctl did not answer within %s", systemctlTimeout)
		}
		return nil, fmt.Errorf("systemctl show: %w", err)
	}
	return parseSystemctlShow(string(out)), nil
}
