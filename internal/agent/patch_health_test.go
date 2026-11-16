package agent

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// sequence replays one sample per call, repeating the last, and counts the
// time a real check would have waited.
func sequence(samples ...map[string]unitState) (unitSampler, func(context.Context, time.Duration) error, *time.Duration) {
	i := 0
	var waited time.Duration
	sample := func(context.Context) (map[string]unitState, error) {
		s := samples[min(i, len(samples)-1)]
		i++
		return s, nil
	}
	sleep := func(_ context.Context, d time.Duration) error { waited += d; return nil }
	return sample, sleep, &waited
}

var (
	running  = unitState{Load: "loaded", Active: "active", Sub: "running", File: "enabled"}
	failed   = unitState{Load: "loaded", Active: "failed", Sub: "failed", File: "enabled"}
	autoRest = unitState{Load: "loaded", Active: "activating", Sub: "auto-restart", File: "enabled"}
)

func withRestarts(u unitState, n int) unitState { u.Restarts = n; return u }

// An app update whose new sqlite binary needs a newer glibc: the service
// crash-loops into failed while the job reports every update verified.
func TestPatchHealthUnitActiveToFailed(t *testing.T) {
	before := map[string]unitState{"seerr.service": running, "ssh.service": running}
	base := takeBaseline(before)
	sample, sleep, waited := sequence(
		map[string]unitState{"seerr.service": withRestarts(autoRest, 1), "ssh.service": running},
		map[string]unitState{"seerr.service": withRestarts(running, 2), "ssh.service": running},
		map[string]unitState{"seerr.service": withRestarts(failed, 5), "ssh.service": running},
	)
	regs, err := settleUnits(context.Background(), base, sample, sleep, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(regs) != 1 || regs[0].Unit != "seerr.service" || regs[0].Before != "active (running)" || regs[0].After != "failed" {
		t.Fatalf("regressions: %+v", regs)
	}
	if regs[0].Restarts != 5 {
		t.Errorf("restarts = %d, want 5", regs[0].Restarts)
	}
	if !strings.Contains(describeRegressions(regs), "seerr.service went active (running) -> failed") {
		t.Errorf("description: %q", describeRegressions(regs))
	}
	if *waited < unitSettleMin {
		t.Errorf("judged after %s, before the minimum watch", *waited)
	}
}

// A unit caught running between crashes is still crash-looping.
func TestPatchHealthCrashLoopCaughtWhileRunning(t *testing.T) {
	base := takeBaseline(map[string]unitState{"app.service": running})
	var samples []map[string]unitState
	for n := 0; n <= 14; n++ {
		samples = append(samples, map[string]unitState{"app.service": withRestarts(running, n)})
	}
	sample, sleep, waited := sequence(samples...)
	regs, err := settleUnits(context.Background(), base, sample, sleep, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(regs) != 1 || regs[0].Restarts < unitCrashLoopRestarts {
		t.Fatalf("crash loop not caught: %+v", regs)
	}
	if *waited != unitSettleMax {
		t.Errorf("watched %s, want the full %s while it kept restarting", *waited, unitSettleMax)
	}
}

// A unit restarted by its package upgrade that comes back is fine, and is
// not misread while it is still coming back.
func TestPatchHealthRestartingUnitSettles(t *testing.T) {
	base := takeBaseline(map[string]unitState{"nginx.service": running})
	sample, sleep, waited := sequence(
		map[string]unitState{"nginx.service": {Load: "loaded", Active: "activating", Sub: "start", File: "enabled"}},
		map[string]unitState{"nginx.service": running},
	)
	regs, err := settleUnits(context.Background(), base, sample, sleep, true)
	if err != nil || len(regs) != 0 {
		t.Fatalf("regs=%+v err=%v", regs, err)
	}
	if *waited != unitSettleMin {
		t.Errorf("waited %s; a settled endpoint should be done at the minimum", *waited)
	}
}

// A unit already failed before patching does not count against the job,
// and neither do units that were never enabled.
func TestPatchHealthIgnoresUnitsFailedBefore(t *testing.T) {
	before := map[string]unitState{
		"broken.service":    failed,
		"ssh.service":       running,
		"apt-daily.service": {Load: "loaded", Active: "active", Sub: "running", File: "static"},
	}
	base := takeBaseline(before)
	if !slices.Equal(base.Failed, []string{"broken.service"}) {
		t.Fatalf("already failed: %v", base.Failed)
	}
	if _, ok := base.Watched["apt-daily.service"]; ok {
		t.Fatal("a static unit was watched")
	}
	sample, sleep, _ := sequence(map[string]unitState{
		"broken.service":    failed,
		"ssh.service":       running,
		"apt-daily.service": {Load: "loaded", Active: "inactive", Sub: "dead", File: "static"},
	})
	regs, err := settleUnits(context.Background(), base, sample, sleep, true)
	if err != nil || len(regs) != 0 {
		t.Fatalf("regs=%+v err=%v", regs, err)
	}
}

// After a restart systemd's restart counts start again: only restarts
// seen while watching count, and a unit that never loaded is reported.
func TestPatchHealthAfterReboot(t *testing.T) {
	base := takeBaseline(map[string]unitState{"db.service": withRestarts(running, 7), "gone.service": running})
	sample, sleep, _ := sequence(map[string]unitState{"db.service": withRestarts(running, 0)})
	regs, err := settleUnits(context.Background(), base, sample, sleep, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(regs) != 1 || regs[0].Unit != "gone.service" || regs[0].After != "not installed" {
		t.Fatalf("regs: %+v", regs)
	}
}

func TestParseSystemctl(t *testing.T) {
	units := parseSystemctlShow("NRestarts=0\nId=cron.service\nLoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\n\n" +
		"NRestarts=5\nId=seerr.service\nLoadState=loaded\nActiveState=failed\nSubState=failed\nUnitFileState=enabled\n")
	if got := units["cron.service"]; !got.running() || !got.enabled() {
		t.Errorf("cron: %+v", got)
	}
	if got := units["seerr.service"]; got.Active != "failed" || got.Restarts != 5 {
		t.Errorf("seerr: %+v", got)
	}
}

func TestKernelUpdates(t *testing.T) {
	got := kernelUpdates([]string{"linux-image-6.1.0-55-amd64", "curl", "kernel-core.x86_64", "linux-headers-6.1.0-55-amd64"},
		[]proto.PatchInfo{{Name: "linux-image-6.1.0-55-amd64", NewVersion: "6.1.192-1"}})
	if !slices.Equal(got, []string{"linux-image-6.1.0-55-amd64 6.1.192-1", "kernel-core.x86_64"}) {
		t.Errorf("got %v", got)
	}
}
