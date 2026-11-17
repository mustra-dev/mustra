package server

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

// A patch job that restarts its endpoint is not done when the endpoint
// goes down: a new kernel can boot, pass the agent's first check and then
// oops a few minutes later, leaving a box that is half alive and cannot
// report anything. The agent cannot report a failure from a hung machine,
// so the server owns this check. Each such job is watched until the
// endpoint has come back on a new boot within patchCheckinDeadline and
// stayed up for patchStabilityWindow; anything else fails the job.

const (
	// How long after the restart was due the endpoint has to be back.
	patchCheckinDeadline = 10 * time.Minute
	// How long after boot it has to stay up. The agent sends its last
	// health report at this point (patchStabilityWindow in the agent).
	patchStabilityWindow = 10 * time.Minute
	// Time for that report to arrive: the agent's own service check can
	// take two minutes, and the report rides the durable outbox.
	patchStabilityGrace = 5 * time.Minute
	// Silence longer than this on an endpoint that should be up is a
	// failure; agents heartbeat every few seconds.
	patchSilenceMin = 2 * time.Minute
)

// restartVerdict is what one look at a watch decided. State is empty when
// nothing has changed.
type restartVerdict struct {
	State    string // stabilizing, healthy, failed, not_restarted
	BootedAt *time.Time
	Detail   string
}

// judgeRestartWatch decides a watch from what the server knows of the
// endpoint: its boot time (from facts), its last heartbeat, and whether
// the agent sends its own health report.
func judgeRestartWatch(w store.PatchRestartWatch, now time.Time, silence time.Duration) restartVerdict {
	var v restartVerdict
	quiet := w.LastHeartbeat == nil || now.Sub(*w.LastHeartbeat) > silence
	booted := w.BootedAt
	rebooted := w.BootTime != nil && w.BootTime.After(w.CreatedAt) &&
		w.LastHeartbeat != nil && !w.LastHeartbeat.Before(*w.BootTime)
	// Back, but only after the deadline: the server was not looking when
	// it passed (restarting itself, say). Late is still late.
	late := rebooted && w.BootTime.After(w.CheckinDeadline)
	if booted == nil && rebooted && !late {
		b := *w.BootTime
		booted = &b
		v.State, v.BootedAt = "stabilizing", booted
	}
	if booted == nil {
		switch {
		case now.Before(w.CheckinDeadline):
			return v
		case !quiet && !rebooted:
			// Still up on the boot it had: the restart never happened
			// (cancelled on the endpoint, say). Nothing broke; the updates
			// are still waiting on a restart.
			return restartVerdict{State: "not_restarted",
				Detail: "The endpoint did not restart: it is still up on the same boot. The updates wait on a restart."}
		}
		heard := "last heard from never"
		switch {
		case late:
			heard = "it booted again only at " + w.BootTime.UTC().Format(time.RFC3339)
		case w.LastHeartbeat != nil:
			heard = "last heard from " + w.LastHeartbeat.UTC().Format(time.RFC3339)
		}
		return restartVerdict{State: "failed", Detail: strings.TrimSpace(fmt.Sprintf(
			"Restarted for patches and did not report back within %s (%s). %s",
			patchCheckinDeadline, heard, kernelSummary(w, late)))}
	}
	stableAt := booted.Add(patchStabilityWindow)
	switch {
	case !w.ReportsHealth && w.LastHeartbeat != nil && !w.LastHeartbeat.Before(stableAt):
		v.State = "healthy"
		v.Detail = fmt.Sprintf("Stayed up for %s after the restart.", patchStabilityWindow)
	case quiet && (w.LastHeartbeat == nil || w.LastHeartbeat.Before(stableAt)):
		after := "before checking in"
		if w.LastHeartbeat != nil {
			after = fmt.Sprintf("%s after boot", w.LastHeartbeat.Sub(*booted).Round(time.Second))
		}
		v.State = "failed"
		v.Detail = strings.TrimSpace(fmt.Sprintf(
			"Came back after the restart for patches, then stopped reporting %s, inside the %s stability window. %s",
			after, patchStabilityWindow, kernelSummary(w, true)))
	case w.ReportsHealth && now.After(stableAt.Add(patchStabilityGrace)):
		// Still heartbeating, but the agent never managed its own check:
		// the endpoint answers, and cannot do much else.
		v.State = "failed"
		v.Detail = strings.TrimSpace(fmt.Sprintf(
			"Came back after the restart for patches but did not complete its health check %s after boot; the endpoint may be partly hung. %s",
			patchStabilityWindow, kernelSummary(w, true)))
	}
	return v
}

// kernelSummary names the kernels involved, which is usually the first
// thing to look at when an endpoint does not survive its patch restart.
func kernelSummary(w store.PatchRestartWatch, cameBack bool) string {
	var parts []string
	if len(w.KernelUpdates) > 0 {
		parts = append(parts, "Kernel update installed: "+strings.Join(w.KernelUpdates, ", ")+".")
	}
	if cameBack && w.Kernel != "" {
		parts = append(parts, "Booted kernel "+w.Kernel+".")
	}
	if w.KernelBefore != "" {
		parts = append(parts, "Was running "+w.KernelBefore+".")
	}
	return strings.Join(parts, " ")
}

// patchSilence is how long an endpoint that should be up may go quiet.
func (s *Server) patchSilence() time.Duration {
	return max(patchSilenceMin, s.staleAfter())
}

// watchPatchRestart starts watching a job's restart when its result says
// one was scheduled. An older agent says so only in prose, so for one that
// sends no health block the job's restart choice decides.
func (s *Server) watchPatchRestart(ctx context.Context, res proto.AgentActionResult, status string) error {
	if res.Kind != "patch_apply" || status != "pending_restart" {
		return nil
	}
	w := store.PatchRestartWatch{ActionID: res.ActionID, AgentID: res.AgentID, RunID: res.RunID, CreatedAt: time.Now()}
	warn := 0
	if h := res.Health; h != nil {
		if !h.RestartScheduled {
			return nil
		}
		w.ReportsHealth, warn = true, h.RestartInMinutes
		w.KernelBefore, w.KernelUpdates = h.KernelBefore, h.KernelUpdates
	} else {
		mode, minutes, err := s.store.ActionRestart(ctx, res.ActionID)
		if err != nil {
			return err
		}
		if mode != "always" && (mode != "if_required" || !res.RebootRequired) {
			return nil
		}
		warn = max(1, minutes)
	}
	w.CheckinDeadline = w.CreatedAt.Add(time.Duration(warn)*time.Minute + patchCheckinDeadline)
	return s.store.CreatePatchRestartWatch(ctx, w)
}

// restartScheduled: a successful result whose job restarts the endpoint,
// which is pending that restart whatever the updates themselves needed.
func (s *Server) restartScheduled(ctx context.Context, res proto.AgentActionResult) bool {
	if res.Kind != "patch_apply" || !res.OK {
		return false
	}
	if res.Health != nil {
		return res.Health.RestartScheduled
	}
	mode, _, err := s.store.ActionRestart(ctx, res.ActionID)
	return err == nil && mode == "always"
}

// patchRestartWatchLoop judges the open watches every 30 seconds.
func (s *Server) patchRestartWatchLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		s.judgePatchRestarts(ctx, time.Now())
	}
}

func (s *Server) judgePatchRestarts(ctx context.Context, now time.Time) {
	watches, err := s.store.OpenPatchRestartWatches(ctx)
	if err != nil {
		s.logger.Warn("list patch restart watches", "error", err)
		return
	}
	silence := s.patchSilence()
	for _, w := range watches {
		v := judgeRestartWatch(w, now, silence)
		if v.BootedAt != nil {
			if err := s.store.MarkPatchRestartBooted(ctx, w.ActionID, *v.BootedAt); err != nil {
				s.logger.Warn("mark patch restart booted", "action_id", w.ActionID, "error", err)
				continue
			}
			w.BootedAt = v.BootedAt
			note := fmt.Sprintf("Back after the restart (booted %s); watching that it stays up for %s.",
				v.BootedAt.UTC().Format(time.RFC3339), patchStabilityWindow)
			if _, err := s.store.UpdateRestartedAction(ctx, w.AgentID, w.ActionID, "verifying", note); err != nil {
				s.logger.Warn("mark patch job verifying", "action_id", w.ActionID, "error", err)
			}
		}
		switch v.State {
		case "healthy":
			s.closeRestartHealthy(ctx, w, v.Detail)
		case "failed":
			s.failPatchHealth(ctx, w.AgentID, w.Hostname, w.RunID, w.ActionID, "failed", v.Detail)
		case "not_restarted":
			if closed, err := s.store.ClosePatchRestartWatch(ctx, w.ActionID, v.State, v.Detail); err == nil && closed {
				_, _ = s.store.UpdateRestartedAction(ctx, w.AgentID, w.ActionID, "pending_restart", v.Detail)
				s.logger.Info("patch restart did not happen", "agent_id", w.AgentID, "action_id", w.ActionID)
			}
		}
	}
}

func (s *Server) closeRestartHealthy(ctx context.Context, w store.PatchRestartWatch, detail string) {
	closed, err := s.store.ClosePatchRestartWatch(ctx, w.ActionID, "healthy", detail)
	if err != nil || !closed {
		return
	}
	if _, err := s.store.SucceedVerifiedAction(ctx, w.AgentID, w.ActionID, detail); err != nil {
		s.logger.Warn("close verified patch job", "action_id", w.ActionID, "error", err)
	}
	s.announceRunCompleted(ctx, w.RunID)
	s.logger.Info("patch restart healthy", "agent_id", w.AgentID, "action_id", w.ActionID)
}

// failPatchHealth closes a patch job whose endpoint did not come through
// it healthy, tells the operator, and holds the rest of the run. status
// is "failed" or "degraded" (services that ran before no longer do).
func (s *Server) failPatchHealth(ctx context.Context, agentID, hostname, runID, actionID, status, detail string) {
	// The watch closes first: whichever of the loop and a late report gets
	// there first acts on the outcome, the other finds it closed.
	closed, err := s.store.ClosePatchRestartWatch(ctx, actionID, "failed", detail)
	if err != nil {
		s.logger.Warn("close patch restart watch", "action_id", actionID, "error", err)
		return
	}
	if !closed {
		return
	}
	if _, err := s.store.UpdateRestartedAction(ctx, agentID, actionID, status, detail); err != nil {
		s.logger.Warn("fail patch job after health check", "action_id", actionID, "error", err)
	}
	s.reportPatchHealthFailure(ctx, agentID, hostname, runID, status, detail)
	s.announceRunCompleted(ctx, runID)
}

// reportPatchHealthFailure raises the notification and holds back the
// rest of the run.
func (s *Server) reportPatchHealthFailure(ctx context.Context, agentID, hostname, runID, status, detail string) {
	if hostname == "" {
		hostname, _ = s.store.GetAgentHostname(ctx, agentID)
	}
	if hostname == "" {
		hostname = agentID
	}
	title := hostname + " did not come back healthy after patching"
	if status == "degraded" {
		title = "Patching broke services on " + hostname
	}
	body := detail
	reason := fmt.Sprintf("Held back: %s failed its check after patching in this run, so these updates were not rolled to more endpoints. %s",
		hostname, safeTruncate(detail, 500))
	if n, err := s.store.HoldWaitingRunActions(ctx, runID, reason); err != nil {
		s.logger.Warn("hold rest of patch run", "run_id", runID, "error", err)
	} else if n > 0 {
		body = fmt.Sprintf("%d endpoint(s) still waiting in this run were held back. %s", n, detail)
		s.audit(ctx, auditEvent{Action: "patch_run.held", Actor: "system", Target: runID, Severity: "warning",
			Detail: map[string]any{"agent_id": agentID, "hostname": hostname, "held": n}})
	}
	s.notify(ctx, "critical", "Patch", title, safeTruncate(strings.TrimSpace(body), 300),
		"/endpoint/"+url.PathEscape(agentID)+"#activity")
	s.logger.Warn("patch health check failed", "agent_id", agentID, "hostname", hostname,
		"run_id", runID, "status", status, "detail", detail)
}

// patchHealthStatus is a patch result's status once its health block is
// read: an install that left services broken is degraded, not failed.
func patchHealthStatus(res proto.AgentActionResult, status string) string {
	if !res.OK && res.Health != nil && len(res.Health.Regressed) > 0 {
		return "degraded"
	}
	return status
}

// consumeWatchedVerification handles the agent's reports after a restart
// the server is watching: the check soon after boot moves the job to
// verifying, the stability report closes it, and a failing one of either
// fails it.
func (s *Server) consumeWatchedVerification(ctx context.Context, res proto.AgentActionResult, w store.PatchRestartWatch) error {
	detail := safeTruncate(res.Detail, 2000)
	if !res.OK {
		s.failPatchHealth(ctx, res.AgentID, w.Hostname, w.RunID, res.ActionID, patchHealthStatus(res, "failed"), detail)
		return nil
	}
	if w.BootedAt == nil {
		// The report is itself proof the endpoint is back.
		boot := time.Now()
		if w.BootTime != nil && w.BootTime.After(w.CreatedAt) {
			boot = *w.BootTime
		}
		if err := s.store.MarkPatchRestartBooted(ctx, res.ActionID, boot); err != nil {
			return err
		}
	}
	if res.Stability {
		closed, err := s.store.ClosePatchRestartWatch(ctx, res.ActionID, "healthy", detail)
		if err != nil {
			return err
		}
		if closed {
			if _, err := s.store.SucceedVerifiedAction(ctx, res.AgentID, res.ActionID, detail); err != nil {
				return err
			}
			s.afterRemediation(ctx, res.AgentID)
			s.announceRunCompleted(ctx, w.RunID)
		}
		return nil
	}
	status := "verifying"
	if res.RebootRequired {
		// Wants another restart: still pending it, and still watched for
		// staying up on this boot.
		status = "pending_restart"
	}
	_, err := s.store.UpdateRestartedAction(ctx, res.AgentID, res.ActionID, status, detail)
	return err
}
