package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/shirou/gopsutil/v4/host"
)

// A patch job that installed updates waiting on a restart ends at "pending
// restart", and nothing used to close it: whether the restart finished the
// updates was left for someone to check by hand. The agent now remembers
// each such job across the restart and, once the endpoint is back up,
// checks the updates again and reports how it ended.

// patchVerification is one job waiting on a restart.
type patchVerification struct {
	RunID    string    `json:"run_id"`
	ActionID string    `json:"action_id"`
	Names    []string  `json:"names"`
	Saved    time.Time `json:"saved"`
	// Restarting: the job scheduled the restart itself, so the endpoint is
	// also held to staying up for patchStabilityWindow after it boots.
	Restarting bool `json:"restarting,omitempty"`
	// Baseline is the endpoint before the job, for the checks after boot.
	Baseline      *healthBaseline `json:"baseline,omitempty"`
	KernelUpdates []string        `json:"kernel_updates,omitempty"`
	// VerifiedBoot is set once the check after the restart passed: the
	// boot it passed in. The record stays until the stability report.
	VerifiedBoot int64 `json:"verified_boot,omitempty"`
}

const (
	maxPatchVerifications = 20
	// A record that never saw a restart in a month is not going to.
	patchVerificationMaxAge = 30 * 24 * time.Hour
	// Windows Update is busy right after boot finishing what the restart
	// started; asked too early, it still lists updates being completed.
	patchVerifySettle = 2 * time.Minute
	// How long after boot an endpoint a patch job restarted must stay up
	// before its last report: a bad kernel can oops a few minutes in, after
	// the first check has passed. The server waits for this report
	// (patchStabilityWindow there) and fails the job without it.
	patchStabilityWindow = 10 * time.Minute
)

var patchVerifyMu sync.Mutex

func (a *Agent) loadPatchVerifications() []patchVerification {
	raw, err := a.store.LoadPatchVerifications()
	if err != nil || len(raw) == 0 {
		return nil
	}
	var out []patchVerification
	_ = json.Unmarshal(raw, &out)
	return out
}

func (a *Agent) savePatchVerifications(list []patchVerification) {
	raw, _ := json.Marshal(list)
	if err := a.store.SavePatchVerifications(raw); err != nil {
		a.logger.Warn("saving patch verifications failed", "error", err)
	}
}

// rememberPatchVerification records a job to check after the next restart.
func (a *Agent) rememberPatchVerification(v patchVerification) {
	if a.store == nil || (len(v.Names) == 0 && !v.Restarting) {
		return
	}
	patchVerifyMu.Lock()
	defer patchVerifyMu.Unlock()
	list := append(a.loadPatchVerifications(), v)
	if len(list) > maxPatchVerifications {
		list = list[len(list)-maxPatchVerifications:]
	}
	a.savePatchVerifications(list)
}

// replacePatchVerification stores v in place of the record for its
// action, or drops that record when v is nil. The checks run without the
// lock, which a new job finishing meanwhile must not wait minutes on.
func (a *Agent) replacePatchVerification(actionID string, v *patchVerification) {
	patchVerifyMu.Lock()
	defer patchVerifyMu.Unlock()
	var list []patchVerification
	for _, old := range a.loadPatchVerifications() {
		switch {
		case old.ActionID != actionID:
			list = append(list, old)
		case v != nil:
			list = append(list, *v)
		}
	}
	a.savePatchVerifications(list)
}

// verifyPatchesAfterRestart runs once at startup. Jobs saved before the
// endpoint last booted have had their restart: each is checked against the
// current patch list and its services against the baseline, and closed.
// A job that restarted the endpoint itself is then reported on once more
// when the endpoint has stayed up for the stability window. Jobs saved
// since boot are still waiting.
func (a *Agent) verifyPatchesAfterRestart(ctx context.Context) {
	if a.store == nil || len(a.loadPatchVerifications()) == 0 {
		return
	}
	bootSecs, err := host.BootTimeWithContext(ctx)
	if err != nil {
		return
	}
	boot := time.Unix(int64(bootSecs), 0)
	if wait := patchVerifySettle - time.Since(boot); wait > 0 {
		if sleepCtx(ctx, wait) != nil {
			return
		}
	}

	patchVerifyMu.Lock()
	list := a.loadPatchVerifications()
	patchVerifyMu.Unlock()
	var after []proto.PatchInfo
	collected := false
	var stable []patchVerification
	for _, v := range list {
		switch {
		case time.Since(v.Saved) > patchVerificationMaxAge:
			a.replacePatchVerification(v.ActionID, nil)
			continue
		case !v.Saved.Before(boot):
			continue // still waiting on its restart
		case v.VerifiedBoot != 0:
			// Checked in an earlier start; only the stability report is
			// left, and this boot is the one that has to last.
			v.VerifiedBoot = boot.Unix()
			a.replacePatchVerification(v.ActionID, &v)
			stable = append(stable, v)
			continue
		}
		if !collected {
			if after, err = collectPatches(ctx, a.nc, a.agentID); err != nil {
				a.logger.Warn("patch check after restart failed", "error", err)
				return // all kept; the next start tries again
			}
			collected = true
		}
		res, again := patchVerificationResult(v, after)
		if v.Baseline != nil {
			a.addHealthAfterRestart(ctx, &res, v)
		}
		switch {
		case again && res.OK:
			v.Saved = time.Now()
			a.replacePatchVerification(v.ActionID, &v)
		case res.OK && v.Restarting:
			v.VerifiedBoot = boot.Unix()
			a.replacePatchVerification(v.ActionID, &v)
			stable = append(stable, v)
		default:
			a.replacePatchVerification(v.ActionID, nil)
		}
		a.logger.Info("patch job checked after restart", "run_id", v.RunID, "ok", res.OK, "detail", res.Detail)
		a.reportActionResult(ctx, res)
	}
	if len(stable) == 0 {
		return
	}
	if sleepCtx(ctx, patchStabilityWindow-time.Since(boot)) != nil {
		return
	}
	for _, v := range stable {
		res := proto.AgentActionResult{RunID: v.RunID, ActionID: v.ActionID, Kind: "patch_apply",
			Verification: true, Stability: true, OK: true,
			Detail: fmt.Sprintf("Stayed up for %s after the restart.", time.Since(boot).Round(time.Minute))}
		a.addHealthAfterRestart(ctx, &res, v)
		a.replacePatchVerification(v.ActionID, nil)
		a.logger.Info("patch job stable after restart", "run_id", v.RunID, "ok", res.OK, "detail", res.Detail)
		a.reportActionResult(ctx, res)
	}
}

// addHealthAfterRestart checks the services against the job's baseline
// and fails res when any that ran before no longer do.
func (a *Agent) addHealthAfterRestart(ctx context.Context, res *proto.AgentActionResult, v patchVerification) {
	base := healthBaseline{}
	if v.Baseline != nil {
		base = *v.Baseline
	}
	h, err := a.checkPatchHealth(ctx, base, false)
	h.KernelUpdates = v.KernelUpdates
	res.Health = h
	switch {
	case len(h.Regressed) > 0:
		res.OK, res.RebootRequired = false, false
		res.Detail = fmt.Sprintf("After the restart, %d service(s) that ran before the updates are not running: %s\n%s",
			len(h.Regressed), describeRegressions(h.Regressed), res.Detail)
	case err != nil:
		res.OK, res.RebootRequired = false, false
		res.Detail = "After the restart, the services could not be checked: " + err.Error() + "\n" + res.Detail
	}
	if h.KernelBefore != "" && h.Kernel != "" && h.Kernel != h.KernelBefore {
		res.Detail += fmt.Sprintf("\nRunning kernel %s (was %s).", h.Kernel, h.KernelBefore)
	}
}

// patchVerificationResult turns one check into the action's final report.
// again is true when the updates want yet another restart (a .NET update
// can take two), in which case the job stays pending and is kept.
func patchVerificationResult(v patchVerification, after []proto.PatchInfo) (res proto.AgentActionResult, again bool) {
	res = proto.AgentActionResult{RunID: v.RunID, ActionID: v.ActionID, Kind: "patch_apply", Verification: true}
	needRestart, notInstalled := patchesStillPending(v.Names, after)
	switch {
	case len(notInstalled) > 0:
		res.Detail = fmt.Sprintf("After the restart, %d of %d update(s) are still pending: %s",
			len(notInstalled), len(v.Names), strings.Join(notInstalled, ", "))
	case len(needRestart) > 0:
		res.OK, res.RebootRequired = true, true
		res.Detail = "After the restart, still waiting on another restart: " + strings.Join(needRestart, ", ")
		return res, true
	case len(v.Names) == 0:
		res.OK = true
		res.Detail = "Back up after the restart."
	default:
		res.OK = true
		res.Detail = fmt.Sprintf("Verified after the restart: all %d update(s) are installed.", len(v.Names))
	}
	return res, false
}
