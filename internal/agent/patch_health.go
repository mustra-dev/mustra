package agent

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/shirou/gopsutil/v4/host"
)

// "Verified: all N update(s) are installed" proves the packages are there,
// not that the machine still works. An app update whose new binary needs a
// newer glibc installs cleanly and leaves its service crash-looping into
// failed; mustra used to call that a success. A patch job now notes which
// services are running before it starts and checks them again afterwards,
// and again after any restart it scheduled.

const (
	// A unit restarting after its package was upgraded is not yet a
	// failure, and one that crash-loops can look running between attempts:
	// services are watched for at least unitSettleMin, and while any is
	// still unsettled, up to unitSettleMax.
	unitSettleMin      = 30 * time.Second
	unitSettleMax      = 2 * time.Minute
	unitSettleInterval = 10 * time.Second
	// Restarts systemd made on its own while being watched that mark a
	// unit as crash-looping even when a sample catches it running.
	unitCrashLoopRestarts = 2
)

// errUnitsUnsupported: this endpoint's services are not checked.
var errUnitsUnsupported = errors.New("service checks run on Linux with systemd only")

// unitState is one service as systemd describes it.
type unitState struct {
	Load     string `json:"load,omitempty"`
	Active   string `json:"active"`
	Sub      string `json:"sub,omitempty"`
	File     string `json:"file,omitempty"` // UnitFileState: enabled, static, ...
	Restarts int    `json:"restarts,omitempty"`
}

func (u unitState) String() string {
	if u.Load == "not-found" {
		return "not installed"
	}
	if u.Sub == "" || u.Sub == u.Active {
		return u.Active
	}
	return u.Active + " (" + u.Sub + ")"
}

// running: up, or reloading its configuration.
func (u unitState) running() bool {
	return u.Active == "active" || u.Active == "reloading"
}

// enabled: started at boot, so expected to be running after a restart.
// Units that are merely static (pulled in by a timer, a socket or another
// unit) come and go on their own and are not held against a patch.
func (u unitState) enabled() bool {
	return u.File == "enabled" || u.File == "enabled-runtime"
}

// unitSampler reads every loaded service's state.
type unitSampler func(ctx context.Context) (map[string]unitState, error)

// healthBaseline is the endpoint before a patch job: kept with a job
// waiting on a restart, so the check after the restart compares against
// the machine as it was before the job, not as it came up.
type healthBaseline struct {
	Kernel string `json:"kernel,omitempty"`
	// Watched are the services running and enabled before the job.
	Watched map[string]unitState `json:"watched,omitempty"`
	// Failed were already failed; they do not count against the job.
	Failed    []string `json:"failed,omitempty"`
	Unchecked string   `json:"unchecked,omitempty"`
}

// takeBaseline notes the services to hold a patch job to.
func takeBaseline(units map[string]unitState) healthBaseline {
	b := healthBaseline{Watched: map[string]unitState{}}
	for name, u := range units {
		switch {
		case u.Active == "failed":
			b.Failed = append(b.Failed, name)
		case u.running() && u.enabled():
			b.Watched[name] = u
		}
	}
	sort.Strings(b.Failed)
	return b
}

// unsettled names watched units not running in cur, or restarted by systemd
// since prev: either way, too early to tell.
func unsettled(watched map[string]unitState, prev, cur map[string]unitState) bool {
	for name := range watched {
		c, ok := cur[name]
		if !ok || !c.running() {
			return true
		}
		if p, ok := prev[name]; ok && c.Restarts > p.Restarts {
			return true
		}
	}
	return false
}

// settleUnits samples the services until they settle or unitSettleMax
// passes, and returns what regressed against the baseline. sameBoot says
// the baseline's restart counts still apply (no reboot in between), so
// restarts during the install count too; after a reboot systemd's counts
// start again and only those seen while watching count.
func settleUnits(ctx context.Context, base healthBaseline, sample unitSampler, sleep func(context.Context, time.Duration) error, sameBoot bool) ([]proto.UnitRegression, error) {
	cur, err := sample(ctx)
	if err != nil {
		return nil, err
	}
	ref := cur
	if sameBoot {
		ref = base.Watched
	}
	prev := cur
	var elapsed time.Duration
	for elapsed < unitSettleMax && (elapsed < unitSettleMin || unsettled(base.Watched, prev, cur)) {
		if err := sleep(ctx, unitSettleInterval); err != nil {
			return nil, err
		}
		elapsed += unitSettleInterval
		next, err := sample(ctx)
		if err != nil {
			// A check that hangs or fails partway is itself a sign: report
			// it rather than judge from the last good sample.
			return nil, fmt.Errorf("checking services after %s: %w", elapsed, err)
		}
		prev, cur = cur, next
	}
	return unitRegressions(base.Watched, ref, cur), nil
}

// unitRegressions compares the watched units' final state with the
// baseline: not running, or restarted by systemd unitCrashLoopRestarts
// times or more since ref.
func unitRegressions(watched, ref, final map[string]unitState) []proto.UnitRegression {
	var out []proto.UnitRegression
	for name, before := range watched {
		after, present := final[name]
		if !present {
			after = unitState{Active: "inactive", Load: "not-found"}
		}
		restarts := 0
		if r, ok := ref[name]; ok && present {
			restarts = max(0, after.Restarts-r.Restarts)
		}
		if after.running() && restarts < unitCrashLoopRestarts {
			continue
		}
		out = append(out, proto.UnitRegression{Unit: name, Before: before.String(), After: after.String(), Restarts: restarts})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Unit < out[j].Unit })
	return out
}

// describeRegressions is the line a result leads with.
func describeRegressions(rs []proto.UnitRegression) string {
	parts := make([]string, 0, len(rs))
	for _, r := range rs {
		s := fmt.Sprintf("%s went %s -> %s", r.Unit, r.Before, r.After)
		if r.Restarts > 0 {
			s += fmt.Sprintf(", restarted %d time(s)", r.Restarts)
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, "; ")
}

// isKernelPackage: a package a restart boots into.
func isKernelPackage(name string) bool {
	n := name
	if i := strings.IndexByte(n, ' '); i > 0 {
		n = n[:i]
	}
	for _, p := range []string{"linux-image-", "pve-kernel-", "proxmox-kernel-", "linux-signed-image-"} {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	// RPM names, sometimes with the architecture appended.
	n, _, _ = strings.Cut(n, ".")
	return slices.Contains([]string{"kernel", "kernel-core", "kernel-default", "kernel-uek", "kernel-rt"}, n)
}

// kernelUpdates lists the kernel packages among a job's targets, with the
// version where the pending list had it.
func kernelUpdates(targeted []string, pending []proto.PatchInfo) []string {
	var out []string
	for _, n := range targeted {
		if !isKernelPackage(n) {
			continue
		}
		label := n
		for _, p := range pending {
			if p.Name == n && p.NewVersion != "" {
				label = n + " " + p.NewVersion
				break
			}
		}
		out = append(out, label)
	}
	return out
}

func runningKernel(ctx context.Context) string {
	k, _ := host.KernelVersionWithContext(ctx)
	return k
}

// patchHealthBaseline notes the endpoint's state before a patch job.
func (a *Agent) patchHealthBaseline(ctx context.Context) healthBaseline {
	units, err := sampleUnits(ctx)
	if err != nil {
		return healthBaseline{Kernel: runningKernel(ctx), Unchecked: err.Error()}
	}
	b := takeBaseline(units)
	b.Kernel = runningKernel(ctx)
	return b
}

// checkPatchHealth compares the endpoint with its baseline. err is set
// when the services could not be checked at all on an endpoint where they
// were before: a box too sick to answer systemctl is not healthy.
func (a *Agent) checkPatchHealth(ctx context.Context, base healthBaseline, sameBoot bool) (*proto.PatchHealth, error) {
	h := &proto.PatchHealth{
		KernelBefore: base.Kernel, Kernel: runningKernel(ctx),
		AlreadyFailed: base.Failed, Unchecked: base.Unchecked,
		AgentConnected: a.nc != nil && a.nc.IsConnected(),
	}
	if base.Unchecked != "" {
		return h, nil
	}
	regs, err := settleUnits(ctx, base, sampleUnits, sleepCtx, sameBoot)
	if err != nil {
		h.Unchecked = err.Error()
		return h, err
	}
	h.Checked, h.Regressed = true, regs
	return h, nil
}

// parseSystemctlShow reads `systemctl show -p ...` output: one block of
// Key=Value lines per unit, blocks separated by a blank line.
func parseSystemctlShow(out string) map[string]unitState {
	units := map[string]unitState{}
	var id string
	var u unitState
	flush := func() {
		if id != "" {
			units[id] = u
		}
		id, u = "", unitState{}
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			flush()
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "Id":
			id = v
		case "LoadState":
			u.Load = v
		case "ActiveState":
			u.Active = v
		case "SubState":
			u.Sub = v
		case "UnitFileState":
			u.File = v
		case "NRestarts":
			fmt.Sscan(v, &u.Restarts)
		}
	}
	flush()
	return units
}
