package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
)

// An answer token works once, only before its expiry, only while it is the
// machine's newest, and fetching it disarms the machine. Status reports
// are taken only between the answer file and the end of the install.
func TestProvisioningAnswerTokenLifecycle(t *testing.T) {
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	run := idgen.New("")[:10]
	m, err := s.SaveProvisioningMachine(ctx, ProvisioningMachine{ID: "pmc-" + run, MAC: "02:00:00:" + run[0:2] + ":" + run[2:4] + ":" + run[4:6], Name: "lab"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.DeleteProvisioningMachine(context.Background(), m.ID)
		_, _ = s.pool.Exec(context.Background(), `DELETE FROM provisioning_installs WHERE machine_id = $1`, m.ID)
	})
	if _, err := s.SaveProvisioningMachine(ctx, ProvisioningMachine{ID: "pmc-other-" + run, MAC: m.MAC}); err != ErrMACTaken {
		t.Fatalf("a second machine with the same MAC: %v, want ErrMACTaken", err)
	}
	arm := func() {
		t.Helper()
		if _, err := s.SetProvisioningArmed(ctx, m.ID, true, "tester", time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	start := func(answer, status string, expires time.Time) string {
		t.Helper()
		id := idgen.New("pin-")
		if err := s.StartProvisioningInstall(ctx, NewProvisioningInstall{ID: id, MachineID: m.ID, MAC: m.MAC, Hostname: "lab",
			Family: "ubuntu", AnswerTokenHash: answer, StatusTokenHash: status, AnswerExpiresAt: expires,
			StatusExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		return id
	}

	// Expired before it was used.
	arm()
	start("ans-expired-"+run, "st-expired-"+run, time.Now().Add(-time.Minute))
	if c, _ := s.PeekProvisioningAnswer(ctx, "ans-expired-"+run); c != nil {
		t.Fatal("an expired token was peekable")
	}
	if c, _ := s.ClaimProvisioningAnswer(ctx, "ans-expired-"+run, "10.0.0.9"); c != nil {
		t.Fatal("an expired token was claimed")
	}

	// A newer boot script supersedes the older one's token.
	arm()
	start("ans-old-"+run, "st-old-"+run, time.Now().Add(time.Hour))
	start("ans-new-"+run, "st-new-"+run, time.Now().Add(time.Hour))
	if c, _ := s.ClaimProvisioningAnswer(ctx, "ans-old-"+run, "10.0.0.9"); c != nil {
		t.Fatal("a superseded token was claimed")
	}

	// A status report before the answer file is refused.
	if in, _ := s.ReportProvisioningStatus(ctx, "st-new-"+run, "installed", ""); in != nil {
		t.Fatal("a status was taken before the answer file was served")
	}
	if c, _ := s.PeekProvisioningAnswer(ctx, "ans-new-"+run); c == nil || c.Family != "ubuntu" {
		t.Fatalf("peek: %+v", c)
	}
	c, err := s.ClaimProvisioningAnswer(ctx, "ans-new-"+run, "10.0.0.9")
	if err != nil || c == nil {
		t.Fatalf("claim: %v %+v", err, c)
	}
	if again, _ := s.ClaimProvisioningAnswer(ctx, "ans-new-"+run, "10.0.0.9"); again != nil {
		t.Fatal("the token was claimed twice")
	}
	if p, _ := s.PeekProvisioningAnswer(ctx, "ans-new-"+run); p != nil {
		t.Fatal("a used token still serves the other files")
	}
	got, _ := s.GetProvisioningMachine(ctx, m.ID)
	if got.InstallNextBoot || got.Armed(time.Now()) {
		t.Fatal("fetching the answer file did not disarm the machine")
	}
	in, err := s.ReportProvisioningStatus(ctx, "st-new-"+run, "installing", "")
	if err != nil || in == nil || in.Status != "installing" {
		t.Fatalf("installing: %v %+v", err, in)
	}
	if in, _ := s.ReportProvisioningStatus(ctx, "st-new-"+run, "installed", "done"); in == nil || in.Status != "installed" {
		t.Fatalf("installed: %+v", in)
	}
	if in, _ := s.ReportProvisioningStatus(ctx, "st-new-"+run, "failed", "rewriting history"); in != nil {
		t.Fatal("a finished install took another status")
	}

	// Disarming withdraws a served script.
	arm()
	start("ans-withdrawn-"+run, "st-withdrawn-"+run, time.Now().Add(time.Hour))
	if _, err := s.SetProvisioningArmed(ctx, m.ID, false, "tester", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.ClaimProvisioningAnswer(ctx, "ans-withdrawn-"+run, "10.0.0.9"); c != nil {
		t.Fatal("a token survived disarming")
	}

	list, err := s.ListProvisioningInstalls(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, in := range list {
		if in.MachineID == m.ID {
			n++
		}
	}
	if n != 4 {
		t.Fatalf("listed %d installs of the machine, want 4", n)
	}
}
