package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Fixtures in the shape the embedded callback prints (one line, sorted
// keys) and the ansible.posix json callback prints (indented).
const (
	reportCompliant = `{"plays": [{"play": {"name": "Baseline"}, "tasks": [{"hosts": {"localhost": {"action": "ansible.builtin.copy", "changed": false}}, "task": {"id": "1", "name": "motd"}}]}], "stats": {"localhost": {"changed": 0, "failures": 0, "ignored": 0, "ok": 1, "rescued": 0, "skipped": 0, "unreachable": 0}}}`
	reportChanged   = `{"plays": [{"play": {"name": "Baseline"}, "tasks": [
		{"hosts": {"localhost": {"action": "ansible.builtin.copy", "changed": true, "mustra_diff": "--- before: /etc/motd\n+++ after: /etc/motd\n@@ -1 +1 @@\n-old\n+new\n"}}, "task": {"name": "motd"}},
		{"hosts": {"localhost": {"action": "ansible.builtin.package", "changed": false}}, "task": {"name": "chrony installed"}},
		{"hosts": {"localhost": {"action": "ansible.builtin.service", "changed": true}}, "task": {"name": "chronyd running"}},
		{"hosts": {"localhost": {"action": "ansible.builtin.command", "changed": false, "skipped": true, "msg": "skipped in check mode"}}, "task": {"name": "reload"}}
	]}], "stats": {"localhost": {"changed": 2, "failures": 0, "ok": 3, "skipped": 1, "unreachable": 0}}}`
	reportFailed = `{"plays": [{"play": {"name": "Baseline"}, "tasks": [
		{"hosts": {"localhost": {"action": "ansible.builtin.copy", "changed": true}}, "task": {"name": "motd"}},
		{"hosts": {"localhost": {"action": "ansible.builtin.template", "changed": false, "failed": true, "msg": "Could not find or access 'app.j2'"}}, "task": {"name": "app config"}}
	]}], "stats": {"localhost": {"changed": 1, "failures": 1, "ok": 1, "skipped": 0, "unreachable": 0}}}`
	reportIgnored = `{"plays": [{"play": {"name": "Baseline"}, "tasks": [
		{"hosts": {"localhost": {"action": "ansible.builtin.command", "changed": false, "failed": true, "mustra_ignored": true, "msg": "non-zero return code"}}, "task": {"name": "probe"}}
	]}], "stats": {"localhost": {"changed": 0, "failures": 0, "ignored": 1, "ok": 0, "skipped": 0, "unreachable": 0}}}`
	reportUnreachable = `{"plays": [{"play": {"name": "Baseline"}, "tasks": [
		{"hosts": {"localhost": {"action": "ansible.builtin.setup", "changed": false, "unreachable": true, "msg": "Failed to create temporary directory"}}, "task": {"name": "Gathering Facts"}}
	]}], "stats": {"localhost": {"changed": 0, "failures": 0, "ok": 0, "skipped": 0, "unreachable": 1}}}`
	reportNoHosts = `{"plays": [{"play": {"name": "Web"}, "tasks": []}], "stats": {}}`
	// ansible.posix.json: indented, full module results, a custom_stats key.
	reportPosix = `{
    "custom_stats": {},
    "global_custom_stats": {},
    "plays": [
        {
            "play": {"duration": {}, "id": "x", "name": "Baseline"},
            "tasks": [
                {
                    "hosts": {
                        "localhost": {
                            "_ansible_no_log": false,
                            "action": "ansible.builtin.lineinfile",
                            "changed": true,
                            "diff": [{"after": "", "before": ""}],
                            "msg": ["line added"]
                        }
                    },
                    "task": {"duration": {}, "id": "y", "name": "sshd PermitRootLogin no"}
                }
            ]
        }
    ],
    "stats": {"localhost": {"changed": 1, "failures": 0, "ignored": 0, "ok": 1, "rescued": 0, "skipped": 0, "unreachable": 0}}
}`
)

func TestJudgeAnsibleCheck(t *testing.T) {
	cases := []struct {
		name        string
		run         ansibleRun
		diff        bool
		state       string
		detail      []string
		report      []string
		notInReport []string
	}{
		{name: "nothing would change", run: ansibleRun{Stdout: []byte(reportCompliant)}, state: "compliant"},
		{name: "changed tasks are drift", run: ansibleRun{Stdout: []byte(reportChanged), Err: nil}, diff: true, state: "drifted",
			detail: []string{"2 tasks would change", "motd", "chronyd running"},
			report: []string{"would change: motd (ansible.builtin.copy)", "+new", "would change: chronyd running"}},
		{name: "diff withheld unless asked", run: ansibleRun{Stdout: []byte(reportChanged)}, state: "drifted",
			report: []string{"would change: motd"}, notInReport: []string{"+new"}},
		// A failure in check mode leaves the rest unevaluated: unknown, even
		// though another task already said it would change.
		{name: "failed task is unknown", run: ansibleRun{Stdout: []byte(reportFailed), Err: errors.New("exit status 2")}, state: "unknown",
			detail: []string{"app config", "Could not find"}},
		{name: "ignored failure does not count", run: ansibleRun{Stdout: []byte(reportIgnored)}, state: "compliant"},
		{name: "unreachable is unknown", run: ansibleRun{Stdout: []byte(reportUnreachable), Err: errors.New("exit status 4")}, state: "unknown",
			detail: []string{"could not run on localhost", "temporary directory"}},
		{name: "no host matched is unknown", run: ansibleRun{Stdout: []byte(reportNoHosts)}, state: "unknown", detail: []string{"ran nothing"}},
		{name: "parse error is unknown", run: ansibleRun{Stderr: []byte("[WARNING]: something\nERROR! We were unable to read either as JSON nor YAML\n  line 3"), Err: errors.New("exit status 4")},
			state: "unknown", detail: []string{"--check failed", "ERROR! We were unable to read"}},
		{name: "callback missing is unknown", run: ansibleRun{Stdout: []byte("PLAY [x] ****\n"), Err: errors.New("exit status 1")}, state: "unknown", detail: []string{"exit status 1"}},
		{name: "timeout is unknown", run: ansibleRun{Stdout: []byte(reportCompliant), TimedOut: true, Budget: 4 * time.Minute}, state: "unknown", detail: []string{"did not finish within 4m0s"}},
		{name: "error exit with clean stats is unknown", run: ansibleRun{Stdout: []byte(reportCompliant), Err: errors.New("exit status 250")}, state: "unknown"},
		{name: "posix json callback", run: ansibleRun{Stdout: []byte("noise\n" + reportPosix)}, state: "drifted", detail: []string{"1 task would change: sshd PermitRootLogin no"}},
	}
	for _, c := range cases {
		v := judgeAnsibleCheck(c.run, c.diff)
		if v.State != c.state {
			t.Errorf("%s: state %q (%s), want %q", c.name, v.State, v.Detail, c.state)
			continue
		}
		for _, w := range c.detail {
			if !strings.Contains(v.Detail, w) {
				t.Errorf("%s: detail %q lacks %q", c.name, v.Detail, w)
			}
		}
		for _, w := range c.report {
			if !strings.Contains(v.Report, w) {
				t.Errorf("%s: report %q lacks %q", c.name, v.Report, w)
			}
		}
		for _, w := range c.notInReport {
			if strings.Contains(v.Report, w) {
				t.Errorf("%s: report %q should not contain %q", c.name, v.Report, w)
			}
		}
	}
}

func TestAnsibleReportIsBounded(t *testing.T) {
	var tasks []string
	for i := range 200 {
		tasks = append(tasks, `{"hosts": {"localhost": {"action": "copy", "changed": true, "mustra_diff": "`+strings.Repeat("x", 500)+`"}}, "task": {"name": "task `+strings.Repeat("n", 30)+string(rune('a'+i%26))+`"}}`)
	}
	doc := `{"plays": [{"play": {"name": "big"}, "tasks": [` + strings.Join(tasks, ",") + `]}], "stats": {"localhost": {"changed": 200}}}`
	v := judgeAnsibleCheck(ansibleRun{Stdout: []byte(doc)}, true)
	if v.State != "drifted" || len(v.Detail) > ansibleMaxDetail+len("…") || len(v.Report) > ansibleMaxOutput+len("…") {
		t.Fatalf("unbounded: state %s, detail %d bytes, report %d bytes", v.State, len(v.Detail), len(v.Report))
	}
	if !strings.HasPrefix(v.Detail, "200 tasks would change") {
		t.Errorf("detail %q", v.Detail)
	}
}

func TestTidyDiffDropsStagingPaths(t *testing.T) {
	got := tidyDiff("--- before: /etc/motd\n+++ after: /tmp/mustra-ansible-1/tmp/ansible-local-x/tmpab\n@@ -1 +1 @@\n-a\n+b\n")
	if got != "--- before: /etc/motd\n+++ after\n@@ -1 +1 @@\n-a\n+b" {
		t.Errorf("got %q", got)
	}
}

func TestSummarizeAnsibleApply(t *testing.T) {
	failed, report := summarizeAnsibleApply(ansibleRun{Stdout: []byte(reportFailed), Err: errors.New("exit status 2")})
	if !strings.Contains(failed, "app config") || !strings.Contains(report, "changed: motd") || !strings.Contains(report, "failed: app config") {
		t.Errorf("failed %q report %q", failed, report)
	}
	failed, report = summarizeAnsibleApply(ansibleRun{Stdout: []byte(reportChanged)})
	if failed != "" || !strings.Contains(report, "recap: ok=3 changed=2") {
		t.Errorf("clean run: failed %q report %q", failed, report)
	}
	failed, _ = summarizeAnsibleApply(ansibleRun{TimedOut: true, Budget: time.Minute})
	if !strings.Contains(failed, "did not finish") {
		t.Errorf("timeout: %q", failed)
	}
}

// fakeAnsible replaces the process with canned runs and records each call.
type fakeAnsible struct {
	runs  []ansibleRun
	calls [][]string
	seen  func(args []string) // inspects the staged files during a call
}

func (f *fakeAnsible) install(t *testing.T) {
	t.Helper()
	oldOS, oldFind, oldExec := ansibleGOOS, findAnsiblePlaybook, execAnsible
	t.Cleanup(func() { ansibleGOOS, findAnsiblePlaybook, execAnsible = oldOS, oldFind, oldExec })
	ansibleGOOS = "linux"
	findAnsiblePlaybook = func() (string, error) { return "/usr/bin/ansible-playbook", nil }
	execAnsible = func(_ context.Context, bin string, args, env []string, dir string, budget time.Duration) ansibleRun {
		f.calls = append(f.calls, args)
		if f.seen != nil {
			f.seen(args)
		}
		if len(f.runs) == 0 {
			t.Fatalf("unexpected ansible-playbook run %v", args)
		}
		r := f.runs[0]
		f.runs = f.runs[1:]
		return r
	}
}

func ansibleSetting(enforce bool) proto.EnforceSetting {
	return proto.EnforceSetting{ID: "set-a", Name: "Ansible: Baseline", Rules: []string{"ansible:playbook"}, Enforce: enforce,
		Ansible: &proto.AnsiblePlaybook{Playbook: "- hosts: localhost\n  tasks: []\n", Vars: `{"motd":"hi"}`}}
}

func TestEnforceAnsibleUnknownNeverRuns(t *testing.T) {
	f := &fakeAnsible{}
	f.install(t)

	ansibleGOOS = "windows"
	if r := enforceSetting(context.Background(), ansibleSetting(true)); r.State != "unknown" || !strings.Contains(r.Detail, "Linux") {
		t.Errorf("windows: %+v", r)
	}
	ansibleGOOS = "linux"

	findAnsiblePlaybook = func() (string, error) { return "", errors.New("not found") }
	if r := enforceSetting(context.Background(), ansibleSetting(true)); r.State != "unknown" || !strings.Contains(r.Detail, "not installed") {
		t.Errorf("ansible missing: %+v", r)
	}
	findAnsiblePlaybook = func() (string, error) { return "/usr/bin/ansible-playbook", nil }

	if r := enforceSetting(withoutCheckCommands(context.Background()), ansibleSetting(true)); r.State != "unknown" {
		t.Errorf("inventory-and-patching mode: %+v", r)
	}
	if len(f.calls) != 0 {
		t.Fatalf("ansible-playbook ran %d times; none of these may run it", len(f.calls))
	}

	// A check that errors is unknown, and in enforce mode the playbook is
	// still not applied: no fix on an answer we do not have.
	f.runs = []ansibleRun{{Stdout: []byte(reportFailed), Err: errors.New("exit status 2")}}
	r := enforceSetting(context.Background(), ansibleSetting(true))
	if r.State != "unknown" || len(f.calls) != 1 || !slices.Contains(f.calls[0], "--check") {
		t.Fatalf("failing check: %+v after %v", r, f.calls)
	}
}

func TestEnforceAnsibleReportModeOnlyChecks(t *testing.T) {
	f := &fakeAnsible{runs: []ansibleRun{{Stdout: []byte(reportChanged)}}}
	f.install(t)
	r := enforceSetting(context.Background(), ansibleSetting(false))
	if r.State != "drifted" || !strings.Contains(r.Detail, "2 tasks would change") || !strings.Contains(r.Output, "would change: motd") {
		t.Fatalf("report mode: %+v", r)
	}
	if len(f.calls) != 1 {
		t.Fatalf("report mode ran ansible-playbook %d times, want only the check", len(f.calls))
	}
}

func TestEnforceAnsibleFixesThenRechecks(t *testing.T) {
	cases := []struct {
		name   string
		apply  ansibleRun
		after  ansibleRun
		state  string
		detail string
	}{
		{"converged", ansibleRun{Stdout: []byte(reportChanged)}, ansibleRun{Stdout: []byte(reportCompliant)}, "remediated", "was: 2 tasks would change"},
		{"still drifting", ansibleRun{Stdout: []byte(reportChanged)}, ansibleRun{Stdout: []byte(reportChanged)}, "failed", "the playbook ran, but 2 tasks would change"},
		{"run failed", ansibleRun{Stdout: []byte(reportFailed), Err: errors.New("exit status 2")}, ansibleRun{Stdout: []byte(reportChanged)}, "failed", "the playbook run failed: app config"},
		{"run failed but converged", ansibleRun{Stdout: []byte(reportFailed), Err: errors.New("exit status 2")}, ansibleRun{Stdout: []byte(reportCompliant)}, "remediated", "reported an error"},
		{"re-check unknown", ansibleRun{Stdout: []byte(reportChanged)}, ansibleRun{Stdout: []byte(reportUnreachable)}, "failed", "could not tell"},
	}
	for _, c := range cases {
		f := &fakeAnsible{runs: []ansibleRun{{Stdout: []byte(reportChanged)}, c.apply, c.after}}
		f.install(t)
		r := enforceSetting(context.Background(), ansibleSetting(true))
		if r.State != c.state || !strings.Contains(r.Detail, c.detail) {
			t.Errorf("%s: %s %q, want %s containing %q", c.name, r.State, r.Detail, c.state, c.detail)
		}
		if len(f.calls) != 3 || !slices.Contains(f.calls[0], "--check") || slices.Contains(f.calls[1], "--check") || !slices.Contains(f.calls[2], "--check") {
			t.Errorf("%s: want check, apply, re-check; got %v", c.name, f.calls)
		}
	}
}

// The playbook and vars reach ansible-playbook as files in a private
// directory, by path, and the directory is gone afterwards.
func TestAnsibleStagingIsPrivateAndRemoved(t *testing.T) {
	// Windows has no Unix permission bits, and the policy only runs on Linux.
	if runtime.GOOS == "windows" {
		t.Skip("file modes are not meaningful on Windows")
	}
	var dir string
	f := &fakeAnsible{runs: []ansibleRun{{Stdout: []byte(reportCompliant)}}}
	f.seen = func(args []string) {
		pb := args[len(args)-1]
		dir = filepath.Dir(pb)
		for _, p := range []string{pb, filepath.Join(dir, "vars.json"), filepath.Join(dir, "callbacks", "mustra_json.py")} {
			fi, err := os.Stat(p)
			if err != nil {
				t.Errorf("%s not staged: %v", p, err)
				continue
			}
			if fi.Mode().Perm()&0o077 != 0 {
				t.Errorf("%s is mode %v; only the owner may read it", p, fi.Mode().Perm())
			}
		}
		if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm()&0o077 != 0 {
			t.Errorf("staging directory %s: %v %v", dir, fi.Mode(), err)
		}
		data, _ := os.ReadFile(pb)
		if string(data) != ansibleSetting(false).Ansible.Playbook {
			t.Errorf("playbook staged as %q", data)
		}
		want := []string{"-i", "localhost,", "-c", "local", "--check", "-e", "@" + filepath.Join(dir, "vars.json"), pb}
		if !slices.Equal(args, want) {
			t.Errorf("args %q, want %q", args, want)
		}
	}
	f.install(t)
	if r := enforceSetting(context.Background(), ansibleSetting(false)); r.State != "compliant" {
		t.Fatalf("%+v", r)
	}
	if dir == "" {
		t.Fatal("ansible-playbook was not run")
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("staging directory %s left behind: %v", dir, err)
	}
}

func TestCappedBuffer(t *testing.T) {
	b := &cappedBuffer{max: 5}
	n, err := b.Write([]byte("abc"))
	if n != 3 || err != nil {
		t.Fatal(n, err)
	}
	if n, _ := b.Write([]byte("defgh")); n != 5 || b.String() != "abcde" || !b.overflow {
		t.Fatalf("got %q overflow=%v", b.String(), b.overflow)
	}
}

// What an agent without Ansible support does with the setting: it sees
// only the "ansible:" rule, which it does not understand, so the setting is
// unknown and never remediated.
func TestAnsibleRuleIsUnknownToTheRuleEngine(t *testing.T) {
	got := evaluateCheck(context.Background(), proto.ComplianceCheck{ID: "x", Rules: []string{"ansible:playbook"}})
	if got.State != "unknown" || got.Pass {
		t.Fatalf("ansible rule evaluated as %+v, want unknown", got)
	}
}
