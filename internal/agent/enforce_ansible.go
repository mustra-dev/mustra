package agent

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Enforce with an Ansible playbook: the playbook is both the check and the
// fix. ansible-playbook --check answers "would anything change", which is
// the drift question, and running it for real is the remediation. The
// engine's rules hold as for every other setting: only a check that ran
// cleanly says compliant or drifted, anything else is unknown and is never
// fixed, and a fix only counts once a second check finds nothing to change.
//
// The playbook is operator code (deploy.manage, as for packages). It is
// written to a file in a private temporary directory and passed to
// ansible-playbook as an argument, never through a shell.

//go:embed ansible_callback.py
var ansibleCallbackPlugin []byte

// Budgets for one ansible-playbook run. The server waits 15 minutes for the
// whole policy; check, apply and re-check must fit inside it with room for
// the reply.
const (
	ansibleCheckBudget = 4 * time.Minute
	ansibleApplyBudget = 6 * time.Minute

	// ansibleMaxCapture bounds what is read from ansible-playbook. A run
	// that prints more than this is not producing a result worth parsing.
	ansibleMaxCapture = 8 << 20
	ansibleMaxDetail  = 500
	ansibleMaxOutput  = 3500
	ansibleMaxListed  = 40
)

// Seams for tests. Production code always uses the defaults.
var (
	ansibleGOOS         = runtime.GOOS
	findAnsiblePlaybook = lookupAnsiblePlaybook
	execAnsible         = runAnsibleProcess
)

// ansibleRun is what one ansible-playbook process left behind.
type ansibleRun struct {
	Stdout, Stderr []byte
	Err            error
	TimedOut       bool
	Budget         time.Duration
}

// ansibleVerdict is one check's answer.
type ansibleVerdict struct {
	State  string // compliant | drifted | unknown
	Detail string
	Report string // the tasks that would change, for the result's output
}

func enforceAnsible(ctx context.Context, setting proto.EnforceSetting) proto.EnforceResult {
	res := proto.EnforceResult{SettingID: setting.ID, Name: setting.Name}
	unknown := func(detail string) proto.EnforceResult {
		res.State, res.Detail = "unknown", clipText(detail, ansibleMaxDetail)
		return res
	}
	if ansibleGOOS != "linux" {
		return unknown(fmt.Sprintf("Ansible policies run on Linux endpoints; this one is %s", ansibleGOOS))
	}
	if checkCommandsDisabled(ctx) || noRemoteCodeActive.Load() {
		return unknown("this endpoint runs no server-supplied code (inventory-and-patching mode)")
	}
	pb := setting.Ansible
	if strings.TrimSpace(pb.Playbook) == "" {
		return unknown("the setting carries no playbook")
	}
	bin, err := findAnsiblePlaybook()
	if err != nil {
		return unknown("ansible-playbook is not installed on this endpoint (install ansible-core)")
	}
	work, err := stageAnsible(pb)
	if err != nil {
		return unknown("could not stage the playbook: " + err.Error())
	}
	defer work.cleanup()

	check := func() ansibleVerdict {
		return judgeAnsibleCheck(execAnsible(ctx, bin, work.args(true, pb.Diff), work.env(), work.dir, ansibleCheckBudget), pb.Diff)
	}
	before := check()
	switch before.State {
	case "unknown":
		return unknown(before.Detail)
	case "compliant":
		res.State = "compliant"
		return res
	}
	res.State, res.Detail, res.Output = "drifted", before.Detail, before.Report
	if !setting.Enforce {
		return res
	}

	applied := execAnsible(ctx, bin, work.args(false, false), work.env(), work.dir, ansibleApplyBudget)
	applyErr, applyReport := summarizeAnsibleApply(applied)
	res.Output = clipText(applyReport, ansibleMaxOutput)

	// Re-check whatever the run reported, as for a command remediation: a
	// failed run may still have converged, and a clean one may not have.
	after := check()
	switch {
	case after.State == "compliant":
		res.State = "remediated"
		res.Detail = "was: " + before.Detail
		if applyErr != "" {
			res.Detail += " (the playbook reported an error but nothing is left to change: " + applyErr + ")"
		}
	case applyErr != "":
		res.State, res.Detail = "failed", "the playbook run failed: "+applyErr
	case after.State == "unknown":
		res.State, res.Detail = "failed", "the playbook ran, but the re-check could not tell whether it took: "+after.Detail
	default:
		res.State, res.Detail = "failed", "the playbook ran, but "+after.Detail
	}
	res.Detail = clipText(res.Detail, ansibleMaxDetail)
	return res
}

// ansibleWork is a private directory holding one setting's run.
type ansibleWork struct {
	dir, playbook, vars, callbacks, tmp string
}

func stageAnsible(pb *proto.AnsiblePlaybook) (*ansibleWork, error) {
	dir, err := os.MkdirTemp("", "mustra-ansible-") // 0700
	if err != nil {
		return nil, err
	}
	w := &ansibleWork{dir: dir, playbook: filepath.Join(dir, "playbook.yml"),
		callbacks: filepath.Join(dir, "callbacks"), tmp: filepath.Join(dir, "tmp")}
	fail := func(err error) (*ansibleWork, error) { w.cleanup(); return nil, err }
	if err := os.WriteFile(w.playbook, []byte(pb.Playbook), 0o600); err != nil {
		return fail(err)
	}
	if strings.TrimSpace(pb.Vars) != "" {
		w.vars = filepath.Join(dir, "vars.json")
		if err := os.WriteFile(w.vars, []byte(pb.Vars), 0o600); err != nil {
			return fail(err)
		}
	}
	for _, d := range []string{w.callbacks, w.tmp} {
		if err := os.Mkdir(d, 0o700); err != nil {
			return fail(err)
		}
	}
	if err := os.WriteFile(filepath.Join(w.callbacks, "mustra_json.py"), ansibleCallbackPlugin, 0o600); err != nil {
		return fail(err)
	}
	return w, nil
}

func (w *ansibleWork) cleanup() { _ = os.RemoveAll(w.dir) }

func (w *ansibleWork) args(check, diff bool) []string {
	args := []string{"-i", "localhost,", "-c", "local"}
	if check {
		args = append(args, "--check")
	}
	if diff {
		args = append(args, "--diff")
	}
	if w.vars != "" {
		args = append(args, "-e", "@"+w.vars)
	}
	return append(args, w.playbook)
}

func (w *ansibleWork) env() []string {
	return append(childEnv(),
		"ANSIBLE_STDOUT_CALLBACK=mustra_json",
		"ANSIBLE_CALLBACK_PLUGINS="+w.callbacks,
		"ANSIBLE_NOCOLOR=1",
		"ANSIBLE_FORCE_COLOR=0",
		"ANSIBLE_RETRY_FILES_ENABLED=0",
		"ANSIBLE_LOCAL_TEMP="+w.tmp,
		"ANSIBLE_LOCALHOST_WARNING=0",
		"ANSIBLE_INVENTORY_UNPARSED_WARNING=0",
		"ANSIBLE_PYTHON_INTERPRETER=auto_silent",
		"DEBIAN_FRONTEND=noninteractive",
	)
}

// lookupAnsiblePlaybook finds ansible-playbook on PATH, then where package
// managers and pip put it: a service's PATH is often shorter than a shell's.
func lookupAnsiblePlaybook() (string, error) {
	if p, err := exec.LookPath("ansible-playbook"); err == nil {
		return p, nil
	}
	for _, p := range []string{"/usr/bin/ansible-playbook", "/usr/local/bin/ansible-playbook", "/root/.local/bin/ansible-playbook"} {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", errors.New("ansible-playbook not found")
}

func runAnsibleProcess(ctx context.Context, bin string, args, env []string, dir string, budget time.Duration) ansibleRun {
	run := ansibleRun{Budget: budget}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir, cmd.Env = dir, env
	cmd.WaitDelay = softwareWaitDelay
	// Its own process group, so a timeout or cancellation kills the module
	// processes ansible started, not only ansible-playbook.
	afterStart, release, err := configureSoftwareProcess(cmd)
	if err != nil {
		run.Err = err
		return run
	}
	defer release()
	stdout, stderr := &cappedBuffer{max: ansibleMaxCapture}, &cappedBuffer{max: ansibleMaxCapture}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err = cmd.Start(); err == nil {
		if scopeErr := afterStart(); scopeErr != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			err = scopeErr
		} else {
			err = cmd.Wait()
		}
	}
	run.Stdout, run.Stderr, run.Err = stdout.Bytes(), stderr.Bytes(), err
	run.TimedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
	if stdout.overflow {
		run.Err = fmt.Errorf("ansible-playbook printed more than %d MiB", ansibleMaxCapture>>20)
		run.Stdout = nil
	}
	return run
}

// cappedBuffer keeps the first max bytes and discards the rest, so a
// runaway task cannot exhaust the agent's memory.
type cappedBuffer struct {
	bytes.Buffer
	max      int
	overflow bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.Len(); room < len(p) {
		b.overflow = true
		if room > 0 {
			b.Buffer.Write(p[:room])
		}
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

// ansibleReport is the document the callback prints. Its shape is the
// ansible.posix json callback's, so either can be read.
type ansibleReport struct {
	Plays []struct {
		Play struct {
			Name string `json:"name"`
		} `json:"play"`
		Tasks []struct {
			Task struct {
				Name string `json:"name"`
			} `json:"task"`
			Hosts map[string]ansibleHostResult `json:"hosts"`
		} `json:"tasks"`
	} `json:"plays"`
	Stats map[string]ansibleStats `json:"stats"`
}

type ansibleHostResult struct {
	Action      string          `json:"action"`
	Changed     bool            `json:"changed"`
	Failed      bool            `json:"failed"`
	Ignored     bool            `json:"mustra_ignored"`
	Unreachable bool            `json:"unreachable"`
	Skipped     bool            `json:"skipped"`
	Msg         json.RawMessage `json:"msg"`
	Diff        string          `json:"mustra_diff"`
}

type ansibleStats struct {
	OK          int `json:"ok"`
	Changed     int `json:"changed"`
	Failures    int `json:"failures"`
	Unreachable int `json:"unreachable"`
	Skipped     int `json:"skipped"`
	Ignored     int `json:"ignored"`
}

// ansibleTask is one task's result, flattened for the verdict.
type ansibleTask struct {
	Name, Action, Msg, Diff string
	Changed, Failed         bool
	Unreachable             bool
}

// parseAnsibleReport finds the JSON document in ansible-playbook's stdout.
// Anything printed before it (a plugin's stray output) is skipped.
func parseAnsibleReport(stdout []byte) (*ansibleReport, error) {
	for i := 0; i < len(stdout); i++ {
		if stdout[i] != '{' || (i > 0 && stdout[i-1] != '\n') {
			continue
		}
		var r ansibleReport
		if err := json.NewDecoder(bytes.NewReader(stdout[i:])).Decode(&r); err == nil && r.Stats != nil {
			return &r, nil
		}
	}
	return nil, errors.New("ansible-playbook printed no results")
}

func (r *ansibleReport) tasks() []ansibleTask {
	var out []ansibleTask
	for _, play := range r.Plays {
		for _, t := range play.Tasks {
			hosts := make([]string, 0, len(t.Hosts))
			for h := range t.Hosts {
				hosts = append(hosts, h)
			}
			sort.Strings(hosts)
			for _, h := range hosts {
				hr := t.Hosts[h]
				name := strings.TrimSpace(t.Task.Name)
				if name == "" {
					name = hr.Action
				}
				out = append(out, ansibleTask{Name: name, Action: hr.Action, Msg: rawText(hr.Msg), Diff: hr.Diff,
					Changed: hr.Changed && !hr.Skipped && !hr.Failed, Failed: hr.Failed && !hr.Ignored, Unreachable: hr.Unreachable})
			}
		}
	}
	return out
}

func (r *ansibleReport) total() ansibleStats {
	var t ansibleStats
	for _, s := range r.Stats {
		t.OK += s.OK
		t.Changed += s.Changed
		t.Failures += s.Failures
		t.Unreachable += s.Unreachable
		t.Skipped += s.Skipped
	}
	return t
}

// judgeAnsibleCheck turns a --check run into compliant, drifted or
// unknown. Only a run that finished with no failures can say compliant or
// drifted: a task that fails in check mode leaves every later task
// unevaluated, so "nothing else would change" is not known.
func judgeAnsibleCheck(run ansibleRun, withDiff bool) ansibleVerdict {
	unknown := func(detail string) ansibleVerdict { return ansibleVerdict{State: "unknown", Detail: detail} }
	if run.TimedOut {
		return unknown(fmt.Sprintf("ansible-playbook --check did not finish within %s", run.Budget))
	}
	report, err := parseAnsibleReport(run.Stdout)
	if err != nil {
		// No results at all: the playbook did not parse, a module or role
		// is missing, or ansible itself could not start.
		why := stderrSummary(run.Stderr)
		if why == "" && run.Err != nil {
			why = run.Err.Error()
		}
		if why == "" {
			why = err.Error()
		}
		return unknown("ansible-playbook --check failed: " + why)
	}
	if len(report.Stats) == 0 {
		return unknown("the playbook ran nothing on this endpoint: no play matched localhost")
	}
	tasks := report.tasks()
	total := report.total()
	if total.Unreachable > 0 {
		return unknown("ansible could not run on localhost: " + firstMsg(tasks, func(t ansibleTask) bool { return t.Unreachable }))
	}
	if total.Failures > 0 {
		return unknown("a task failed in check mode, so the rest is unknown: " + firstMsg(tasks, func(t ansibleTask) bool { return t.Failed }))
	}
	if run.Err != nil {
		why := stderrSummary(run.Stderr)
		if why == "" {
			why = run.Err.Error()
		}
		return unknown("ansible-playbook --check reported an error: " + why)
	}
	var changed []ansibleTask
	for _, t := range tasks {
		if t.Changed {
			changed = append(changed, t)
		}
	}
	if total.Changed == 0 && len(changed) == 0 {
		return ansibleVerdict{State: "compliant"}
	}
	n := max(total.Changed, len(changed))
	names := make([]string, 0, len(changed))
	for _, t := range changed {
		names = append(names, t.Name)
	}
	detail := fmt.Sprintf("%d task%s would change", n, plural(n))
	if len(names) > 0 {
		detail += ": " + strings.Join(names, "; ")
	}
	return ansibleVerdict{State: "drifted", Detail: clipText(detail, ansibleMaxDetail),
		Report: clipText(changeReport(changed, withDiff), ansibleMaxOutput)}
}

// changeReport lists the tasks that would change, one per line, each with
// its diff when the policy asked for diffs.
func changeReport(changed []ansibleTask, withDiff bool) string {
	var b strings.Builder
	for i, t := range changed {
		if i == ansibleMaxListed {
			fmt.Fprintf(&b, "… and %d more\n", len(changed)-i)
			break
		}
		fmt.Fprintf(&b, "would change: %s", t.Name)
		if t.Action != "" && t.Action != t.Name {
			fmt.Fprintf(&b, " (%s)", t.Action)
		}
		b.WriteString("\n")
		if withDiff && strings.TrimSpace(t.Diff) != "" {
			b.WriteString(tidyDiff(t.Diff))
			b.WriteString("\n")
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// summarizeAnsibleApply reads a real run. The error is "" when it finished
// with no failed task; the report lists what changed and what failed.
func summarizeAnsibleApply(run ansibleRun) (string, string) {
	if run.TimedOut {
		return fmt.Sprintf("ansible-playbook did not finish within %s", run.Budget), stderrSummary(run.Stderr)
	}
	report, err := parseAnsibleReport(run.Stdout)
	if err != nil {
		why := stderrSummary(run.Stderr)
		if why == "" && run.Err != nil {
			why = run.Err.Error()
		}
		if why == "" {
			why = err.Error()
		}
		return why, why
	}
	var b strings.Builder
	var failed string
	for _, t := range report.tasks() {
		switch {
		case t.Failed || t.Unreachable:
			fmt.Fprintf(&b, "failed: %s: %s\n", t.Name, t.Msg)
			if failed == "" {
				failed = t.Name + ": " + t.Msg
			}
		case t.Changed:
			fmt.Fprintf(&b, "changed: %s\n", t.Name)
		}
	}
	total := report.total()
	fmt.Fprintf(&b, "recap: ok=%d changed=%d failed=%d unreachable=%d skipped=%d", total.OK, total.Changed, total.Failures, total.Unreachable, total.Skipped)
	if failed == "" && (total.Failures > 0 || total.Unreachable > 0) {
		failed = "a task failed"
	}
	if failed == "" && run.Err != nil {
		failed = run.Err.Error()
	}
	return failed, b.String()
}

// tidyDiff drops the temporary file a module rendered its new content
// into from a diff header ("+++ after: /tmp/mustra-ansible-…/tmpab12"):
// it names nothing on the endpoint and differs on every run.
func tidyDiff(diff string) string {
	lines := strings.Split(strings.TrimRight(diff, "\n"), "\n")
	for i, l := range lines {
		for _, h := range []string{"--- before: ", "+++ after: "} {
			if strings.HasPrefix(l, h) && strings.Contains(l, "/mustra-ansible-") {
				lines[i] = strings.TrimSuffix(h, ": ")
			}
		}
	}
	return strings.Join(lines, "\n")
}

func firstMsg(tasks []ansibleTask, match func(ansibleTask) bool) string {
	for _, t := range tasks {
		if match(t) {
			if t.Msg == "" {
				return t.Name
			}
			return t.Name + ": " + t.Msg
		}
	}
	return "no task reported why"
}

// stderrSummary keeps the part of stderr that explains a failure: from
// the first ERROR line on when there is one, else the last lines.
func stderrSummary(stderr []byte) string {
	lines := strings.Split(strings.TrimSpace(string(stderr)), "\n")
	start := -1
	for i, l := range lines {
		if strings.Contains(l, "ERROR") {
			start = i
			break
		}
	}
	if start < 0 {
		start = max(0, len(lines)-3)
	}
	var kept []string
	for _, l := range lines[start:] {
		if l = strings.TrimSpace(l); l != "" {
			kept = append(kept, l)
		}
	}
	return clipText(strings.Join(kept, " "), 400)
}

// rawText renders a result's msg, which is usually a string and sometimes
// a list or an object.
func rawText(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return strings.TrimSpace(s)
	}
	return string(raw)
}

// clipText cuts s to at most n bytes on a character boundary.
func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := s[:n]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut + "…"
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
