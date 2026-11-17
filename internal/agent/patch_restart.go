package agent

import (
	"context"
	"fmt"
)

// patchRestartNote decides and schedules the restart a patch job asked
// for, and returns the line the job's result reports and whether a restart
// is now on its way. Nothing restarts after a failed or timed-out run, or
// one that broke a service (blocked says which): an endpoint in that state
// is better left up for someone to look at.
func patchRestartNote(ctx context.Context, mode string, warnMinutes int, required bool, blocked string) (string, bool) {
	if mode == "" {
		return "", false
	}
	if blocked != "" {
		return "Not restarting: " + blocked, false
	}
	if mode == "if_required" && !required {
		return "No restart needed.", false
	}
	if warnMinutes < 1 {
		warnMinutes = 1
	}
	msg := fmt.Sprintf("This computer will restart in %d minute(s) to finish installing updates. Save your work.", warnMinutes)
	if err := scheduleRestart(ctx, warnMinutes, msg); err != nil {
		return "Could not schedule the restart: " + err.Error(), false
	}
	return fmt.Sprintf("Restarting in %d minute(s) to finish the updates; the signed-in user was warned.", warnMinutes), true
}
