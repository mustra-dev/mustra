package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/scarules"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

var debian12 = store.CompliancePolicy{ID: "imported-cis-debian-12", Name: "CIS Debian 12", OS: "linux"}

// Every rule form the engine reads is carried over exactly as the check
// has it, with the check's condition, title and severity: the setting and
// the check must judge a machine the same way.
func TestSettingFromCheckKeepsEveryRuleType(t *testing.T) {
	var rules []string
	for _, c := range scarules.Corpus {
		if !c.Unsupported && (c.Platform == "linux" || c.Platform == "") {
			rules = append(rules, c.Rule)
		}
	}
	check := proto.ComplianceCheck{ID: "35600", Title: " Ensure sshd PermitRootLogin is disabled. ",
		Severity: "High", Condition: "any", Rules: rules, Remediation: "Set PermitRootLogin no."}
	s, unsupported := settingFromCheck(debian12, check, "linux")
	if len(unsupported) != 0 {
		t.Fatalf("supported rules reported unsupported: %+v", unsupported)
	}
	if !reflect.DeepEqual(s.Rules, rules) {
		t.Errorf("rules changed in translation:\n got %q\nwant %q", s.Rules, rules)
	}
	if s.Name != "Ensure sshd PermitRootLogin is disabled." || s.Severity != "high" || s.Condition != "any" {
		t.Errorf("name %q severity %q condition %q", s.Name, s.Severity, s.Condition)
	}
	if s.Benchmark == nil || *s.Benchmark != (proto.EnforceBenchmarkRef{PolicyID: debian12.ID, PolicyName: "CIS Debian 12", CheckID: "35600"}) {
		t.Errorf("reference %+v", s.Benchmark)
	}
	if s.RemediateLinux+s.RemediateWindows+s.RemediateDarwin != "" {
		t.Error("a fix was generated from the benchmark's text")
	}

	// The evaluator reads a missing or unfamiliar condition as "all", so
	// the setting says so rather than failing validation or meaning less.
	for _, c := range []string{"", "ALL", "majority"} {
		s, _ := settingFromCheck(debian12, proto.ComplianceCheck{ID: "1", Title: "t", Condition: c, Rules: []string{"p:sshd"}}, "linux")
		if s.Condition != "all" || s.Severity != "medium" {
			t.Errorf("condition %q: got %q severity %q", c, s.Condition, s.Severity)
		}
	}
}

// Rules the engine cannot read stay in the setting, every one of them, and
// are named with the reason and what they do to the result.
func TestUntranslatableRulesAreKeptAndNamed(t *testing.T) {
	check := proto.ComplianceCheck{ID: "9", Title: "Mixed", Rules: []string{
		"f:/etc/passwd",
		`r:HKLM\SYSTEM\CurrentControlSet\Control\Lsa -> LimitBlankPasswordUse -> 1`,
		"f:/etc/shadow -> r:(?=x)",
	}}
	s, unsupported := settingFromCheck(debian12, check, "linux")
	if len(s.Rules) != 3 {
		t.Fatalf("rules dropped: %q", s.Rules)
	}
	if len(unsupported) != 2 || unsupported[0].Rule != check.Rules[1] || unsupported[1].Rule != check.Rules[2] {
		t.Fatalf("unsupported %+v", unsupported)
	}
	for _, u := range unsupported {
		if u.Reason == "" {
			t.Errorf("%s: no reason", u.Rule)
		}
	}
	if e := unsupportedEffect("all", 2, 3); !strings.Contains(e, "unknown") || strings.Contains(e, "always") {
		t.Errorf("effect for some unreadable rules: %q", e)
	}
	if e := unsupportedEffect("any", 3, 3); !strings.Contains(e, "always report unknown") {
		t.Errorf("effect for no readable rules: %q", e)
	}
	if unsupportedEffect("all", 0, 3) != "" {
		t.Error("an effect for a check the engine reads fully")
	}
	// Judged for Windows, the registry rule is readable.
	if _, u := settingFromCheck(debian12, check, "windows"); len(u) != 1 {
		t.Errorf("on windows: %+v", u)
	}
}

// The starting fix is the benchmark's text as comments, which is no fix:
// nothing is sent, so nothing runs, until the operator writes a command.
func TestStartingFixRunsNothing(t *testing.T) {
	text := "Run the following command to remove the package:\n# apt purge telnet\nThen reboot; rm -rf / is not part of this."
	fix := remediationComment(text)
	if !strings.Contains(fix, "apt purge telnet") {
		t.Fatalf("remediation text lost: %q", fix)
	}
	if runnableFix(fix) != "" {
		t.Fatalf("the starting fix is runnable:\n%s", fix)
	}
	if remediationComment("  ") != "" {
		t.Error("a starting fix from no text")
	}
	if got := runnableFix(fix + "apt-get purge -y telnet\n"); got == "" {
		t.Error("a command under the comments was not kept")
	}
	set := proto.EnforceSetting{RemediateLinux: fix}
	if remediationForPlatform(set, "linux") != "" {
		t.Error("a comment-only fix counts as a remediation")
	}
	if _, err := validateEnforceSettings([]proto.EnforceSetting{{Name: "x", Rules: []string{"p:x"}, RemediateLinux: fix}}, "enforce", "linux"); err == nil {
		t.Error("an enforcing policy saved with only a comment for a fix")
	}
}

func ref(bench, check string) *proto.EnforceBenchmarkRef {
	return &proto.EnforceBenchmarkRef{PolicyID: bench, CheckID: check}
}

// Creating from a check a policy already holds links to the setting it
// has; the same check twice in one request is made once.
func TestMergeBenchmarkSettingsIsIdempotent(t *testing.T) {
	existing := []proto.EnforceSetting{
		{ID: "set-hand", Name: "hand written", Rules: []string{"p:chronyd"}},
		{ID: "set-old", Name: "already", Rules: []string{"p:sshd"}, Benchmark: ref("b", "1")},
	}
	add := []proto.EnforceSetting{
		{Name: "again", Rules: []string{"p:sshd"}, Benchmark: ref("b", "1")},
		{Name: "new", Rules: []string{"p:auditd"}, Benchmark: ref("b", "2")},
		{Name: "new twice", Rules: []string{"p:auditd"}, Benchmark: ref("b", "2")},
		{Name: "other benchmark", Rules: []string{"p:sshd"}, Benchmark: ref("c", "1")},
	}
	merged, created, linked := mergeBenchmarkSettings(existing, add)
	if len(merged) != 4 || len(created) != 2 || len(linked) != 2 {
		t.Fatalf("merged %d created %d linked %d", len(merged), len(created), len(linked))
	}
	if linked[0].ID != "set-old" || linked[1].ID != created[0].ID {
		t.Errorf("linked %q and %q, want set-old and %q", linked[0].ID, linked[1].ID, created[0].ID)
	}
	for _, c := range created {
		if !strings.HasPrefix(c.ID, "set-") {
			t.Errorf("created setting without an id: %+v", c)
		}
	}
	// Doing it again changes nothing.
	again, created2, linked2 := mergeBenchmarkSettings(merged, add)
	if len(again) != len(merged) || len(created2) != 0 || len(linked2) != len(add) {
		t.Errorf("second run: merged %d created %d linked %d", len(again), len(created2), len(linked2))
	}
}

func TestBenchmarkDestination(t *testing.T) {
	ok := store.EnforcePolicy{Name: "p", Mode: "report", OS: "linux"}
	if why := benchmarkDestinationError(ok, "linux"); why != "" {
		t.Errorf("a report-mode Linux policy refused: %s", why)
	}
	for _, c := range []struct {
		p    store.EnforcePolicy
		want string
	}{
		{store.EnforcePolicy{Name: "p", Mode: "enforce", OS: "linux"}, "report mode"},
		{store.EnforcePolicy{Name: "p", Mode: "report", Kind: "bitlocker", OS: "windows"}, "typed"},
		{store.EnforcePolicy{Name: "p", Mode: "report", OS: "windows"}, "written for Linux"},
	} {
		if why := benchmarkDestinationError(c.p, "linux"); !strings.Contains(why, c.want) {
			t.Errorf("%+v: %q, want it to mention %q", c.p, why, c.want)
		}
	}
	if why := benchmarkDestinationError(store.EnforcePolicy{Name: "any", Mode: "report"}, "darwin"); why != "" {
		t.Errorf("an any-platform policy refused: %s", why)
	}
}

// Making settings from checks takes what writing an Enforce setting by
// hand takes, deploy.manage, and saving one is checked for reach like
// saving a policy.
func TestEnforceFromChecksPermissions(t *testing.T) {
	s := &Server{logger: slog.Default()}
	s.routes()
	perms := map[string][]string{}
	gated := map[string]bool{}
	for _, e := range s.routeLog.entries {
		if pg, ok := e.Handler.(*permGuard); ok {
			perms[e.Pattern] = pg.perms
			_, gated[e.Pattern] = pg.next.(*actionGate)
		}
	}
	want := perms["POST /api/enforce/policies"]
	if !slices.Equal(want, []string{auth.PermDeployManage}) {
		t.Fatalf("creating a policy takes %v; this test assumes deploy.manage", want)
	}
	for _, p := range []string{"POST /api/enforce/from-checks", "POST /api/enforce/from-checks/preview"} {
		if !slices.Equal(perms[p], want) {
			t.Errorf("%s takes %v, want %v", p, perms[p], want)
		}
	}
	if !gated["POST /api/enforce/from-checks"] {
		t.Error("POST /api/enforce/from-checks is not behind the endpoint-action gate")
	}

	// A caller without deploy.manage (here a token that may run Comply
	// but not author Enforce) is refused before anything is read: this
	// bare server has no store, so getting further would panic.
	caller := &store.User{ID: "usr-comply", Username: "comply", Active: true}
	for _, e := range s.routeLog.entries {
		if e.Pattern != "POST /api/enforce/from-checks" && e.Pattern != "POST /api/enforce/from-checks/preview" {
			continue
		}
		req := httptest.NewRequest("POST", "/x", strings.NewReader(`{"checks":[{"benchmark_id":"b","check_id":"1"}]}`))
		ctx := auth.WithToken(auth.WithUser(req.Context(), caller), []string{auth.PermPatchesManage}, nil)
		rec := httptest.NewRecorder()
		e.Handler.ServeHTTP(rec, req.WithContext(ctx))
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s without deploy.manage: %d %q, want 403", e.Pattern, rec.Code, rec.Body.String())
		}
	}
}

// Against a real store: a check becomes a setting in a new report-mode
// policy; asking again links to it, for a new policy or the same one; a
// fix for a check with rules the engine cannot read is refused.
func TestEnforceFromChecksAgainstStore(t *testing.T) {
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := &Server{logger: slog.Default(), store: st, live: &liveConfig{}, syslog: &syslogSink{}}
	admin := &store.User{ID: idgen.New("usr-"), Username: idgen.New("bench-"), IsAdmin: true, Active: true}

	bench := store.CompliancePolicy{ID: idgen.New("imported-test-"), Name: "CIS Debian 12 test", OS: "linux", Source: "imported", CreatedBy: "test"}
	checks, _ := json.Marshal([]proto.ComplianceCheck{
		{ID: "100", Title: "Ensure sshd PermitRootLogin is disabled.", Severity: "high",
			Remediation: "Set PermitRootLogin no.", Rules: []string{`c:sshd -T -> r:^\s*permitrootlogin\s+no`}},
		{ID: "200", Title: "Registry only", Rules: []string{`r:HKLM\SOFTWARE\X -> Y -> 1`}},
	})
	bench.Checks = checks
	if err := st.UpsertCompliancePolicy(ctx, bench); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteCompliancePolicy(context.Background(), bench.ID) })

	post := func(h http.HandlerFunc, body string) (int, enforceFromChecksResponse, string) {
		r := httptest.NewRequest("POST", "/api/enforce/from-checks", strings.NewReader(body))
		rec := httptest.NewRecorder()
		h(rec, asUser(r, admin))
		var out enforceFromChecksResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out, rec.Body.String()
	}
	cleanup := func(id string) { t.Cleanup(func() { _ = st.DeleteEnforcePolicy(context.Background(), id) }) }

	// The preview names the unreadable rule, offers no fix for it, and a
	// starting fix of comments for the other.
	r := httptest.NewRequest("POST", "/api/enforce/from-checks/preview", strings.NewReader(
		`{"checks":[{"benchmark_id":"`+bench.ID+`","check_id":"100"},{"benchmark_id":"`+bench.ID+`","check_id":"200"}]}`))
	rec := httptest.NewRecorder()
	s.handleEnforceFromChecksPreview(rec, asUser(r, admin))
	var prev enforceFromChecksPreviewResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &prev); err != nil || len(prev.Drafts) != 2 {
		t.Fatalf("preview: %d %s", rec.Code, rec.Body.String())
	}
	if d := prev.Drafts[0]; !d.FixAllowed || runnableFix(d.Setting.RemediateLinux) != "" || !strings.Contains(d.Setting.RemediateLinux, "PermitRootLogin no") {
		t.Errorf("first draft: %+v", d)
	}
	if d := prev.Drafts[1]; d.FixAllowed || len(d.Unsupported) != 1 || d.Setting.RemediateLinux != "" || d.Effect == "" {
		t.Errorf("registry-only draft: %+v", d)
	}

	// A fix on the unreadable check is refused.
	code, _, body := post(s.handleEnforceFromChecks, `{"name":"x","checks":[{"benchmark_id":"`+bench.ID+`","check_id":"200","remediate_linux":"true"}]}`)
	if code != http.StatusBadRequest || !strings.Contains(body, "cannot read") {
		t.Fatalf("fix on an unreadable check: %d %s", code, body)
	}

	both := `[{"benchmark_id":"` + bench.ID + `","check_id":"100","remediate_linux":"systemctl reload ssh"},{"benchmark_id":"` + bench.ID + `","check_id":"200"}]`
	code, first, body := post(s.handleEnforceFromChecks, `{"name":"From Comply","checks":`+both+`}`)
	if code != http.StatusOK || first.Policy == nil || len(first.Created) != 2 {
		t.Fatalf("create: %d %s", code, body)
	}
	cleanup(first.Policy.ID)
	if first.Policy.Mode != "report" || first.Policy.OS != "linux" || first.Created[1].Unsupported != 1 {
		t.Errorf("created policy %+v, outcomes %+v", first.Policy, first.Created)
	}

	// Again, for a new policy: everything links, nothing is written.
	code, second, body := post(s.handleEnforceFromChecks, `{"name":"From Comply again","checks":`+both+`}`)
	if code != http.StatusOK || second.Policy != nil || len(second.Created) != 0 || len(second.Linked) != 2 ||
		second.Linked[0].SettingID != first.Created[0].SettingID || second.Linked[0].PolicyID != first.Policy.ID {
		t.Fatalf("second create: %d %s", code, body)
	}

	// Into the same policy: linked, and the policy still has two settings.
	code, third, body := post(s.handleEnforceFromChecks, `{"policy_id":"`+first.Policy.ID+`","checks":`+both+`}`)
	if code != http.StatusOK || len(third.Created) != 0 || len(third.Linked) != 2 || third.Policy == nil || third.Policy.SettingCount != 2 {
		t.Fatalf("add to the same policy: %d %s", code, body)
	}

	// An enforcing policy is not a destination.
	enforcing := store.EnforcePolicy{ID: idgen.New("enf-"), Name: "Enforcing", OS: "linux", Mode: "enforce", Enabled: false,
		Settings: json.RawMessage(`[{"id":"set-a","name":"a","rules":["p:a"],"remediate_linux":"true"}]`), UpdatedBy: "test"}
	if err := st.UpsertEnforcePolicy(ctx, enforcing); err != nil {
		t.Fatal(err)
	}
	cleanup(enforcing.ID)
	code, _, body = post(s.handleEnforceFromChecks, `{"policy_id":"`+enforcing.ID+`","checks":`+both+`}`)
	if code != http.StatusBadRequest || !strings.Contains(body, "report mode") {
		t.Errorf("enforcing destination: %d %s", code, body)
	}

	// A check that is not in the benchmark is named.
	code, _, body = post(s.handleEnforceFromChecks, `{"name":"x","checks":[{"benchmark_id":"`+bench.ID+`","check_id":"999"}]}`)
	if code != http.StatusBadRequest || !strings.Contains(body, "999") {
		t.Errorf("missing check: %d %s", code, body)
	}
}
