//go:build windows

package agent

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/mustra-dev/mustra/internal/proto"
)

// collectHotpatch runs the probe (hotpatch.go) and evaluates it. Published
// as a one-row slice, like every sensor.
func collectHotpatch(ctx context.Context) ([]proto.HotpatchStatus, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", hotpatchProbeScript)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("hotpatch probe: %w (did not finish in time: %v)", err, ctx.Err())
		}
		return nil, fmt.Errorf("hotpatch probe: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	p, err := decodeHotpatchProbe(bytes.TrimSpace(stdout.Bytes()))
	if err != nil {
		return nil, err
	}
	return []proto.HotpatchStatus{evaluateHotpatch(p)}, nil
}
