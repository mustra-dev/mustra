package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/scarules"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// Enforce settings made from hardening checks.
//
// A benchmark check already says what must be true, in the dialect Enforce
// runs, so the setting's test is the check's own rules, copied verbatim:
// rewriting them would make the setting and the check disagree about the
// same machine. What the translation adds is knowledge. scarules says which
// rules the endpoint engine cannot read; those are kept (dropping one would
// check less than the benchmark does and pass where it fails) and named, so
// the operator learns before saving that the setting will report unknown
// where they decide.
//
// The fix is the operator's code. A benchmark's remediation is prose
// written for a person, and turning prose into a command that runs as root
// on every targeted machine is not something to guess at, so it is offered
// only as comments to write the command under (runnableFix treats a fix of
// comments as no fix). A check with rules the engine cannot read takes no
// fix at all: the re-check after a fix is what decides "remediated", and it
// cannot decide on a rule it cannot read.
//
// Everything lands in report mode: a new policy is created in it, and only
// a policy still in it can be added to.

// maxChecksPerRequest bounds one request. A whole CIS benchmark is a few
// hundred checks.
const maxChecksPerRequest = 1000

// benchmarkCheckRef names one check in one benchmark (compliance policy).
type benchmarkCheckRef struct {
	BenchmarkID string `json:"benchmark_id"`
	CheckID     string `json:"check_id"`
}

func (r benchmarkCheckRef) key() string { return r.BenchmarkID + "\x00" + r.CheckID }

// unsupportedRule is a check rule the endpoint engine will not evaluate.
type unsupportedRule struct {
	Rule   string `json:"rule"`
	Reason string `json:"reason"`
}

// existingBenchmarkSetting is an Enforce setting already made from a check.
type existingBenchmarkSetting struct {
	PolicyID    string `json:"policy_id"`
	PolicyName  string `json:"policy_name"`
	Mode        string `json:"mode"`
	SettingID   string `json:"setting_id"`
	SettingName string `json:"setting_name"`
}

// benchmarkSettingDraft is the setting a check would become.
type benchmarkSettingDraft struct {
	BenchmarkID   string `json:"benchmark_id"`
	BenchmarkName string `json:"benchmark_name"`
	CheckID       string `json:"check_id"`
	// Platform is the one the rules were judged for: the destination
	// policy's, else the benchmark's.
	Platform string `json:"platform"`
	// Setting is what would be saved. When a fix is allowed, the
	// platform's fix holds the benchmark's remediation as comments.
	Setting proto.EnforceSetting `json:"setting"`
	// Remediation and Rationale are the benchmark's own text.
	Remediation string `json:"remediation,omitempty"`
	Rationale   string `json:"rationale,omitempty"`
	// Unsupported lists the rules the engine cannot read, every one of
	// them; none is left out of Setting.
	Unsupported []unsupportedRule `json:"unsupported"`
	// Effect says, when there are unsupported rules, what they do to the
	// setting's result.
	Effect string `json:"effect,omitempty"`
	// FixAllowed is false when an unsupported rule means a fix could
	// never be confirmed by the re-check.
	FixAllowed bool `json:"fix_allowed"`
	// Existing are the Enforce settings already made from this check.
	Existing []existingBenchmarkSetting `json:"existing"`
}

// enforceDestination is a policy the settings could be added to: custom,
// in report mode, and for a platform that fits.
type enforceDestination struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	OS        string `json:"os"`
	GroupID   string `json:"group_id"`
	GroupName string `json:"group_name,omitempty"`
	Settings  int    `json:"settings"`
}

// enforceFromChecksPreviewRequest is the body of POST
// /api/enforce/from-checks/preview.
type enforceFromChecksPreviewRequest struct {
	// Checks are the benchmark checks to translate.
	Checks []benchmarkCheckRef `json:"checks" api:"required"`
	// PolicyID is the Enforce policy they would be added to, if one is
	// chosen; its platform decides which rules count as unsupported.
	PolicyID string `json:"policy_id"`
}

// enforceFromChecksPreviewResponse is what POST
// /api/enforce/from-checks/preview answers.
type enforceFromChecksPreviewResponse struct {
	Drafts []benchmarkSettingDraft `json:"drafts"`
	// Policies are the existing policies these settings could be added to.
	Policies []enforceDestination `json:"policies"`
	// Platform is the one a new policy would get, or "" when the checks
	// come from benchmarks for different platforms.
	Platform string `json:"platform"`
}

// enforceFromCheck is one check to make a setting from, with the
// operator's name and fixes.
type enforceFromCheck struct {
	BenchmarkID string `json:"benchmark_id"`
	CheckID     string `json:"check_id"`
	// Name replaces the check's title as the setting's name.
	Name             string `json:"name"`
	RemediateLinux   string `json:"remediate_linux"`
	RemediateWindows string `json:"remediate_windows"`
	RemediateDarwin  string `json:"remediate_darwin"`
}

// enforceFromChecksRequest is the body of POST /api/enforce/from-checks.
// PolicyID adds the settings to that policy, which must be a custom one
// in report mode; without it a new report-mode policy is created from
// Name, Description and GroupID.
type enforceFromChecksRequest struct {
	PolicyID    string             `json:"policy_id"`
	Name        string             `json:"name"`
	Description string             `json:"description"`
	GroupID     string             `json:"group_id"`
	Checks      []enforceFromCheck `json:"checks" api:"required"`
}

// benchmarkSettingOutcome is what became of one check.
type benchmarkSettingOutcome struct {
	BenchmarkID string `json:"benchmark_id"`
	CheckID     string `json:"check_id"`
	PolicyID    string `json:"policy_id"`
	PolicyName  string `json:"policy_name"`
	SettingID   string `json:"setting_id"`
	Name        string `json:"name"`
	// Unsupported counts the setting's rules the engine cannot read.
	Unsupported int `json:"unsupported"`
}

// enforceFromChecksResponse is what POST /api/enforce/from-checks answers.
type enforceFromChecksResponse struct {
	// Policy is the policy written, or null when every check was already
	// held and nothing was written.
	Policy *store.EnforcePolicy `json:"policy"`
	// Created are the new settings; Linked the checks that already had
	// one, which was kept rather than copied.
	Created []benchmarkSettingOutcome `json:"created"`
	Linked  []benchmarkSettingOutcome `json:"linked"`
}

// settingFromCheck translates a benchmark check into an Enforce setting
// judged for platform. The rules are kept as they are, all of them.
func settingFromCheck(bench store.CompliancePolicy, c proto.ComplianceCheck, platform string) (proto.EnforceSetting, []unsupportedRule) {
	name := strings.TrimSpace(c.Title)
	if name == "" {
		name = c.ID
	}
	severity := strings.ToLower(strings.TrimSpace(c.Severity))
	if severity == "" {
		severity = "medium"
	}
	// The evaluator reads any condition it does not know as "all", which
	// is how the benchmark check itself is scored; say so explicitly so
	// the setting saves and means the same.
	condition := strings.ToLower(strings.TrimSpace(c.Condition))
	if condition != "any" && condition != "none" {
		condition = "all"
	}
	setting := proto.EnforceSetting{
		Name: name, Severity: severity, Condition: condition,
		Benchmark: &proto.EnforceBenchmarkRef{PolicyID: bench.ID, PolicyName: bench.Name, CheckID: c.ID},
	}
	var unsupported []unsupportedRule
	for _, rule := range c.Rules {
		if strings.TrimSpace(rule) == "" {
			continue
		}
		setting.Rules = append(setting.Rules, rule)
		if why := scarules.Unsupported(rule, platform); why != "" {
			unsupported = append(unsupported, unsupportedRule{Rule: rule, Reason: why})
		}
	}
	return setting, unsupported
}

// unsupportedEffect says what rules the engine cannot read do to a
// setting's result, in the evaluator's terms.
func unsupportedEffect(condition string, unsupported, total int) string {
	if unsupported == 0 {
		return ""
	}
	if unsupported >= total {
		return "The engine can read none of this check's rules, so the setting will always report unknown and never be fixed."
	}
	switch condition {
	case "any":
		return "Where none of the readable rules holds, the setting reports unknown rather than drifted, and is not fixed."
	case "none":
		return "Unless a readable rule holds (which makes it drifted), the setting reports unknown, never compliant."
	default:
		return "Unless a readable rule fails (which makes it drifted), the setting reports unknown, never compliant."
	}
}

// remediationComment is a benchmark's remediation as a starting fix:
// comment lines, which run nothing, for the operator to write under.
func remediationComment(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString("# The benchmark's remediation, as written. Comments run nothing:\n")
	b.WriteString("# write the command that applies it below them.\n#\n")
	for _, para := range strings.Split(text, "\n") {
		line := ""
		for _, word := range strings.Fields(para) {
			if line != "" && len(line)+1+len(word) > 76 {
				b.WriteString("# " + line + "\n")
				line = ""
			}
			if line != "" {
				line += " "
			}
			line += word
		}
		b.WriteString(strings.TrimRight("# "+line, " ") + "\n")
	}
	return b.String()
}

// setFix puts fix on platform's remediation field.
func setFix(s *proto.EnforceSetting, platform, fix string) {
	switch platform {
	case "linux":
		s.RemediateLinux = fix
	case "windows":
		s.RemediateWindows = fix
	case "darwin":
		s.RemediateDarwin = fix
	}
}

// benchmarkSettingsHeld maps each check to the Enforce settings already
// made from it, across every policy.
func benchmarkSettingsHeld(policies []store.EnforcePolicy) map[string][]existingBenchmarkSetting {
	out := map[string][]existingBenchmarkSetting{}
	for _, p := range policies {
		var settings []proto.EnforceSetting
		if json.Unmarshal(p.Settings, &settings) != nil {
			continue
		}
		for _, s := range settings {
			if s.Benchmark == nil {
				continue
			}
			k := benchmarkCheckRef{s.Benchmark.PolicyID, s.Benchmark.CheckID}.key()
			out[k] = append(out[k], existingBenchmarkSetting{PolicyID: p.ID, PolicyName: p.Name,
				Mode: p.Mode, SettingID: s.ID, SettingName: s.Name})
		}
	}
	return out
}

// mergeBenchmarkSettings adds settings made from checks to a policy's
// settings, linking each check the policy already holds to the setting it
// has rather than copying it. A check asked for twice in one request is
// made once.
func mergeBenchmarkSettings(existing, add []proto.EnforceSetting) (merged []proto.EnforceSetting, created, linked []proto.EnforceSetting) {
	held := map[string]proto.EnforceSetting{}
	merged = append(merged, existing...)
	for _, s := range existing {
		if s.Benchmark != nil {
			k := benchmarkCheckRef{s.Benchmark.PolicyID, s.Benchmark.CheckID}.key()
			if _, ok := held[k]; !ok {
				held[k] = s
			}
		}
	}
	for _, s := range add {
		k := benchmarkCheckRef{s.Benchmark.PolicyID, s.Benchmark.CheckID}.key()
		if have, ok := held[k]; ok {
			linked = append(linked, have)
			continue
		}
		if s.ID == "" {
			s.ID = idgen.New("set-")
		}
		held[k] = s
		merged = append(merged, s)
		created = append(created, s)
	}
	return merged, created, linked
}

// resolvedCheck is a requested check found in its benchmark.
type resolvedCheck struct {
	bench store.CompliancePolicy
	check proto.ComplianceCheck
}

// resolveBenchmarkChecks finds each requested check. A benchmark or check
// that does not exist is the caller's mistake, named in the error.
func (s *Server) resolveBenchmarkChecks(ctx context.Context, refs []benchmarkCheckRef) ([]resolvedCheck, error) {
	benches := map[string]*store.CompliancePolicy{}
	checks := map[string]map[string]proto.ComplianceCheck{}
	out := make([]resolvedCheck, 0, len(refs))
	for _, ref := range refs {
		ref.BenchmarkID, ref.CheckID = strings.TrimSpace(ref.BenchmarkID), strings.TrimSpace(ref.CheckID)
		if ref.BenchmarkID == "" || ref.CheckID == "" {
			return nil, httpError{http.StatusBadRequest, "every check needs a benchmark_id and a check_id"}
		}
		b, seen := benches[ref.BenchmarkID]
		if !seen {
			var err error
			b, err = s.store.GetCompliancePolicy(ctx, ref.BenchmarkID)
			if err != nil {
				return nil, err
			}
			benches[ref.BenchmarkID] = b
			if b != nil {
				var list []proto.ComplianceCheck
				_ = json.Unmarshal(b.Checks, &list)
				byID := map[string]proto.ComplianceCheck{}
				for _, c := range list {
					byID[c.ID] = c
				}
				checks[ref.BenchmarkID] = byID
			}
		}
		if b == nil {
			return nil, httpError{http.StatusBadRequest, fmt.Sprintf("no benchmark %q", ref.BenchmarkID)}
		}
		c, ok := checks[ref.BenchmarkID][ref.CheckID]
		if !ok {
			return nil, httpError{http.StatusBadRequest, fmt.Sprintf("%s has no check %q", b.Name, ref.CheckID)}
		}
		out = append(out, resolvedCheck{bench: *b, check: c})
	}
	return out, nil
}

// writeBenchmarkError answers an error from the helpers above.
func writeBenchmarkError(w http.ResponseWriter, err error) {
	var he httpError
	if asHTTPError(err, &he) {
		http.Error(w, he.msg, he.code)
		return
	}
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

// benchmarkDestinationError says why a policy cannot take settings made
// from checks for platform, or "" when it can.
func benchmarkDestinationError(p store.EnforcePolicy, platform string) string {
	switch {
	case p.Kind != "":
		return fmt.Sprintf("%q is a typed policy: its settings are compiled from its form, so settings cannot be added to it", p.Name)
	case p.Mode != "report":
		return fmt.Sprintf("%q is enforcing; settings made from checks start in report mode, so add them to a policy in report mode or a new one", p.Name)
	case p.OS != "" && platform != "" && p.OS != platform:
		return fmt.Sprintf("%q targets %s, and these checks are written for %s", p.Name, osName(p.OS), osName(platform))
	}
	return ""
}

func osName(os string) string {
	switch os {
	case "darwin":
		return "macOS"
	case "windows":
		return "Windows"
	case "linux":
		return "Linux"
	}
	return "any platform"
}

// benchmarkPlatform is the platform shared by every check's benchmark, or
// "" when they differ.
func benchmarkPlatform(checks []resolvedCheck) string {
	platform := ""
	for i, c := range checks {
		if i == 0 {
			platform = c.bench.OS
		} else if c.bench.OS != platform {
			return ""
		}
	}
	return platform
}

// handleEnforceFromChecksPreview shows what checks would become, before
// anything is saved: the setting, the rules the engine cannot read and
// what they do, any setting already made from the check, and the policies
// that could take them.
func (s *Server) handleEnforceFromChecksPreview(w http.ResponseWriter, r *http.Request) {
	var req enforceFromChecksPreviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(req.Checks) == 0 || len(req.Checks) > maxChecksPerRequest {
		http.Error(w, fmt.Sprintf("checks: give between 1 and %d", maxChecksPerRequest), http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	resolved, err := s.resolveBenchmarkChecks(ctx, req.Checks)
	if err != nil {
		writeBenchmarkError(w, err)
		return
	}
	policies, err := s.store.ListEnforcePolicies(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	destOS := ""
	if req.PolicyID != "" {
		found := false
		for _, p := range policies {
			if p.ID == req.PolicyID {
				destOS, found = p.OS, true
			}
		}
		if !found {
			http.Error(w, "no such policy", http.StatusNotFound)
			return
		}
	}
	held := benchmarkSettingsHeld(policies)
	resp := enforceFromChecksPreviewResponse{Drafts: []benchmarkSettingDraft{},
		Policies: []enforceDestination{}, Platform: benchmarkPlatform(resolved)}
	for _, rc := range resolved {
		platform := rc.bench.OS
		if destOS != "" {
			platform = destOS
		}
		setting, unsupported := settingFromCheck(rc.bench, rc.check, platform)
		d := benchmarkSettingDraft{
			BenchmarkID: rc.bench.ID, BenchmarkName: rc.bench.Name, CheckID: rc.check.ID,
			Platform: platform, Remediation: rc.check.Remediation, Rationale: rc.check.Rationale,
			Unsupported: []unsupportedRule{}, FixAllowed: len(unsupported) == 0,
			Effect:   unsupportedEffect(setting.Condition, len(unsupported), len(setting.Rules)),
			Existing: []existingBenchmarkSetting{},
		}
		d.Unsupported = append(d.Unsupported, unsupported...)
		d.Existing = append(d.Existing, held[benchmarkCheckRef{rc.bench.ID, rc.check.ID}.key()]...)
		if d.FixAllowed {
			setFix(&setting, platform, remediationComment(rc.check.Remediation))
		}
		d.Setting = setting
		resp.Drafts = append(resp.Drafts, d)
	}
	for _, p := range policies {
		if benchmarkDestinationError(p, resp.Platform) != "" || (p.OS != "" && resp.Platform == "") {
			continue
		}
		resp.Policies = append(resp.Policies, enforceDestination{ID: p.ID, Name: p.Name, OS: p.OS,
			GroupID: p.GroupID, GroupName: p.GroupName, Settings: p.SettingCount})
	}
	writeJSONResponse(w, resp)
}

// handleEnforceFromChecks makes Enforce settings from benchmark checks,
// in a new report-mode policy or added to one already in report mode.
// Creating from a check that already has a setting links to it: in the
// chosen policy always, and for a new policy wherever it is held.
func (s *Server) handleEnforceFromChecks(w http.ResponseWriter, r *http.Request) {
	var req enforceFromChecksRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(req.Checks) == 0 || len(req.Checks) > maxChecksPerRequest {
		http.Error(w, fmt.Sprintf("checks: give between 1 and %d", maxChecksPerRequest), http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	refs := make([]benchmarkCheckRef, len(req.Checks))
	for i, c := range req.Checks {
		refs[i] = benchmarkCheckRef{c.BenchmarkID, c.CheckID}
	}
	resolved, err := s.resolveBenchmarkChecks(ctx, refs)
	if err != nil {
		writeBenchmarkError(w, err)
		return
	}
	platform := benchmarkPlatform(resolved)

	var dest *store.EnforcePolicy
	if req.PolicyID != "" {
		if dest, err = s.store.GetEnforcePolicy(ctx, req.PolicyID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if dest == nil {
			http.Error(w, "no such policy", http.StatusNotFound)
			return
		}
		for _, rc := range resolved {
			if why := benchmarkDestinationError(*dest, rc.bench.OS); why != "" {
				http.Error(w, why, http.StatusBadRequest)
				return
			}
		}
		if dest.OS != "" {
			platform = dest.OS
		}
	} else {
		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" {
			http.Error(w, "a new policy needs a name", http.StatusBadRequest)
			return
		}
		if platform == "" {
			http.Error(w, "these checks come from benchmarks for different platforms; make a policy for each", http.StatusBadRequest)
			return
		}
		if req.GroupID != "" {
			g, err := s.store.GetComputerGroup(ctx, req.GroupID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if g == nil {
				http.Error(w, "no such computer group", http.StatusBadRequest)
				return
			}
		}
	}

	add := make([]proto.EnforceSetting, 0, len(resolved))
	unsupportedByKey := map[string]int{}
	for i, rc := range resolved {
		judged := rc.bench.OS
		if dest != nil && dest.OS != "" {
			judged = dest.OS
		}
		setting, unsupported := settingFromCheck(rc.bench, rc.check, judged)
		in := req.Checks[i]
		if name := strings.TrimSpace(in.Name); name != "" {
			setting.Name = name
		}
		setting.RemediateLinux, setting.RemediateWindows, setting.RemediateDarwin = in.RemediateLinux, in.RemediateWindows, in.RemediateDarwin
		if len(unsupported) > 0 && remediationForPlatform(setting, "") != "" {
			http.Error(w, fmt.Sprintf("%q has %d rule(s) the engine cannot read, so a fix could never be confirmed by the re-check; save it without one",
				setting.Name, len(unsupported)), http.StatusBadRequest)
			return
		}
		unsupportedByKey[benchmarkCheckRef{rc.bench.ID, rc.check.ID}.key()] = len(unsupported)
		add = append(add, setting)
	}

	who := auth.CurrentUser(ctx).Username
	resp := enforceFromChecksResponse{Created: []benchmarkSettingOutcome{}, Linked: []benchmarkSettingOutcome{}}
	outcome := func(p store.EnforcePolicy, set proto.EnforceSetting) benchmarkSettingOutcome {
		o := benchmarkSettingOutcome{PolicyID: p.ID, PolicyName: p.Name, SettingID: set.ID, Name: set.Name}
		if set.Benchmark != nil {
			o.BenchmarkID, o.CheckID = set.Benchmark.PolicyID, set.Benchmark.CheckID
			o.Unsupported = unsupportedByKey[benchmarkCheckRef{o.BenchmarkID, o.CheckID}.key()]
		}
		return o
	}

	var policy store.EnforcePolicy
	var existing []proto.EnforceSetting
	if dest != nil {
		policy = *dest
		if err := json.Unmarshal(dest.Settings, &existing); err != nil {
			http.Error(w, "this policy's settings could not be read: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		// A new policy from a check somebody has already made a setting
		// from would be a second copy of the same rules on the same
		// machines; link to the one there is. Adding to a chosen policy
		// is the way to hold a check in a second scope on purpose.
		policies, err := s.store.ListEnforcePolicies(ctx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		held := benchmarkSettingsHeld(policies)
		fresh := add[:0:0]
		for _, set := range add {
			k := benchmarkCheckRef{set.Benchmark.PolicyID, set.Benchmark.CheckID}.key()
			if h := held[k]; len(h) > 0 {
				resp.Linked = append(resp.Linked, benchmarkSettingOutcome{BenchmarkID: set.Benchmark.PolicyID,
					CheckID: set.Benchmark.CheckID, PolicyID: h[0].PolicyID, PolicyName: h[0].PolicyName,
					SettingID: h[0].SettingID, Name: h[0].SettingName, Unsupported: unsupportedByKey[k]})
				continue
			}
			fresh = append(fresh, set)
		}
		add = fresh
		policy = store.EnforcePolicy{ID: idgen.New("enf-"), Name: req.Name,
			Description: strings.TrimSpace(req.Description), OS: platform, GroupID: req.GroupID,
			Mode: "report", Enabled: true, Config: json.RawMessage("{}")}
	}

	merged, created, linked := mergeBenchmarkSettings(existing, add)
	for _, set := range linked {
		resp.Linked = append(resp.Linked, outcome(policy, set))
	}
	if len(created) == 0 {
		// Nothing new: the answer is where each check already is.
		if dest != nil {
			resp.Policy = dest
		}
		writeJSONResponse(w, resp)
		return
	}
	settings, err := validateEnforceSettings(merged, policy.Mode, policy.OS)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	encoded, err := json.Marshal(settings)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	policy.Settings, policy.UpdatedBy = encoded, who
	if err := s.store.UpsertEnforcePolicy(ctx, policy); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// The policy's other settings and their history are unchanged, so
	// unlike an edit in the editor this keeps the recorded results: in
	// report mode there is no failure counter to reset anyway.
	fixes := 0
	for _, set := range created {
		resp.Created = append(resp.Created, outcome(policy, set))
		if remediationForPlatform(set, policy.OS) != "" {
			fixes++
		}
	}
	action := "enforce.policy.update"
	if dest == nil {
		action = "enforce.policy.create"
	}
	benchmarks := map[string]bool{}
	for _, rc := range resolved {
		benchmarks[rc.bench.Name] = true
	}
	names := make([]string, 0, len(benchmarks))
	for n := range benchmarks {
		names = append(names, n)
	}
	sort.Strings(names)
	s.audit(ctx, auditEvent{
		Action: action, Actor: who, Target: policy.Name, Severity: "info",
		Detail: map[string]any{"mode": policy.Mode, "settings": len(settings), "platform": policy.OS,
			"group": policy.GroupID, "from_benchmark": names, "created": len(created),
			"linked": len(resp.Linked), "with_fix": fixes},
	})
	saved, err := s.store.GetEnforcePolicy(ctx, policy.ID)
	if err != nil || saved == nil {
		msg := fmt.Sprintf("policy %s was saved but could not be read back", policy.ID)
		if err != nil {
			msg += ": " + err.Error()
		}
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}
	resp.Policy = saved
	writeJSONResponse(w, resp)
}

// resolveEnforceFromChecks is who a request to make settings from checks
// reaches: the chosen policy's targets, or the new policy's group (the
// fleet without one). Checked for reach like saving a policy.
func resolveEnforceFromChecks(s *Server, r *http.Request, body []byte) (endpointAction, error) {
	ids := bodyStrings(body, "policy_id")
	if len(ids) == 0 {
		return bodyAgentsOrFleet(nil, []string{"group_id"}, false)(s, r, body)
	}
	p, err := s.store.GetEnforcePolicy(r.Context(), ids[0])
	if err != nil {
		return endpointAction{}, err
	}
	if p == nil {
		return endpointAction{}, httpError{http.StatusNotFound, "no such policy"}
	}
	pol := *p
	return endpointAction{Summary: "enforce " + pol.Name, Fleet: func(ctx context.Context) ([]string, error) {
		switch {
		case pol.GroupDeleted:
			return nil, nil // targets nothing, never everything
		case pol.GroupID != "":
			return s.groupMembers(ctx, []string{pol.GroupID})
		}
		return s.allAgentIDs(ctx)
	}}, nil
}
