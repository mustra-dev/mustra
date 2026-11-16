package server

import (
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/store"
)

// A patch job installed a kernel and restarted the endpoint. These pin how
// the server judges what happened next from boot times and heartbeats
// alone, since a hung endpoint cannot report its own failure.

var watchT0 = time.Date(2026, 11, 16, 8, 22, 0, 0, time.UTC)

func ptr(t time.Time) *time.Time { return &t }

func kernelWatch(reportsHealth bool) store.PatchRestartWatch {
	return store.PatchRestartWatch{
		ActionID: "act-1", AgentID: "agt-1", Hostname: "web-01",
		CreatedAt:       watchT0,
		CheckinDeadline: watchT0.Add(2*time.Minute + patchCheckinDeadline),
		ReportsHealth:   reportsHealth,
		KernelBefore:    "6.1.0-54-amd64",
		KernelUpdates:   []string{"linux-image-6.1.0-55-amd64 6.1.192-1"},
		BootTime:        ptr(watchT0.Add(-30 * 24 * time.Hour)),
		Kernel:          "6.1.0-54-amd64",
		LastHeartbeat:   ptr(watchT0.Add(2 * time.Minute)), // went down for the restart
	}
}

const silence = 2 * time.Minute

// An endpoint that never checks in after its patch restart fails the job,
// naming the kernel it was meant to boot.
func TestRestartWatchNeverChecksIn(t *testing.T) {
	w := kernelWatch(true)
	if v := judgeRestartWatch(w, watchT0.Add(8*time.Minute), silence); v.State != "" {
		t.Fatalf("judged before the deadline: %+v", v)
	}
	v := judgeRestartWatch(w, w.CheckinDeadline.Add(time.Second), silence)
	if v.State != "failed" {
		t.Fatalf("state = %q, want failed", v.State)
	}
	for _, want := range []string{"did not report back", "linux-image-6.1.0-55-amd64 6.1.192-1", "Was running 6.1.0-54-amd64"} {
		if !strings.Contains(v.Detail, want) {
			t.Errorf("detail %q lacks %q", v.Detail, want)
		}
	}

	// Coming back after the deadline, noticed late, is still a failure.
	lateBoot := w.CheckinDeadline.Add(20 * time.Minute)
	w.BootTime, w.LastHeartbeat = ptr(lateBoot), ptr(lateBoot.Add(time.Minute))
	v = judgeRestartWatch(w, lateBoot.Add(90*time.Second), silence)
	if v.State != "failed" || !strings.Contains(v.Detail, "booted again only at") {
		t.Fatalf("late check-in: %+v", v)
	}
}

// One that comes back, then goes silent inside the stability window (the
// oops came 2-4 minutes after each boot), fails too, with the kernel it
// booted.
func TestRestartWatchSilentInsideStabilityWindow(t *testing.T) {
	boot := watchT0.Add(3 * time.Minute)
	w := kernelWatch(true)
	w.BootTime, w.Kernel = ptr(boot), "6.1.0-55-amd64"
	w.LastHeartbeat = ptr(boot.Add(40 * time.Second))

	v := judgeRestartWatch(w, boot.Add(90*time.Second), silence)
	if v.State != "stabilizing" || v.BootedAt == nil || !v.BootedAt.Equal(boot) {
		t.Fatalf("check-in not noticed: %+v", v)
	}
	w.BootedAt = v.BootedAt

	// The agent reported once at boot+2m, then nothing.
	w.LastHeartbeat = ptr(boot.Add(3 * time.Minute))
	if v := judgeRestartWatch(w, boot.Add(4*time.Minute), silence); v.State != "" {
		t.Fatalf("judged while still reporting: %+v", v)
	}
	v = judgeRestartWatch(w, boot.Add(6*time.Minute), silence)
	if v.State != "failed" {
		t.Fatalf("state = %q, want failed", v.State)
	}
	for _, want := range []string{"stopped reporting 3m0s after boot", "Booted kernel 6.1.0-55-amd64", "linux-image-6.1.0-55-amd64"} {
		if !strings.Contains(v.Detail, want) {
			t.Errorf("detail %q lacks %q", v.Detail, want)
		}
	}
}

// An agent that sends health reports must send the one at the end of the
// window; one that keeps heartbeating without it is not healthy.
func TestRestartWatchHeartbeatsWithoutHealthReport(t *testing.T) {
	boot := watchT0.Add(3 * time.Minute)
	w := kernelWatch(true)
	w.BootTime, w.BootedAt = ptr(boot), ptr(boot)
	stableAt := boot.Add(patchStabilityWindow)

	w.LastHeartbeat = ptr(stableAt.Add(time.Minute))
	if v := judgeRestartWatch(w, stableAt.Add(time.Minute), silence); v.State != "" {
		t.Fatalf("judged before the report was due: %+v", v)
	}
	now := stableAt.Add(patchStabilityGrace + time.Minute)
	w.LastHeartbeat = ptr(now.Add(-5 * time.Second))
	if v := judgeRestartWatch(w, now, silence); v.State != "failed" || !strings.Contains(v.Detail, "partly hung") {
		t.Fatalf("got %+v", v)
	}
}

// An older agent sends no health report: staying up through the window
// is what it is judged on.
func TestRestartWatchOlderAgentHealthy(t *testing.T) {
	boot := watchT0.Add(3 * time.Minute)
	w := kernelWatch(false)
	w.BootTime, w.BootedAt = ptr(boot), ptr(boot)
	w.LastHeartbeat = ptr(boot.Add(patchStabilityWindow + 10*time.Second))
	if v := judgeRestartWatch(w, boot.Add(patchStabilityWindow+20*time.Second), silence); v.State != "healthy" {
		t.Fatalf("got %+v", v)
	}
}

// A restart that never happened (cancelled on the endpoint) is not a
// broken endpoint: it is still up on the same boot.
func TestRestartWatchNoRestart(t *testing.T) {
	w := kernelWatch(true)
	now := w.CheckinDeadline.Add(time.Minute)
	w.LastHeartbeat = ptr(now.Add(-5 * time.Second))
	if v := judgeRestartWatch(w, now, silence); v.State != "not_restarted" {
		t.Fatalf("got %+v", v)
	}
}
