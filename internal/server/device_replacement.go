package server

// Device replacement ("laptop refresh"): the software of an endpoint being
// retired, installed on the endpoint that replaces it.
//
// Nothing here decides how software is recognised or installed. The old
// endpoint's installed-apps snapshot is normalised into products the way
// Inventory & Usage does it; a catalog package matches a product when the
// package's own detection (the same matchInstalled/detectFromInventory the
// catalog's applicability uses) finds it among that product's rows; whether
// it would install on the new endpoint is evaluateApplicability, unchanged.
// Each chosen package then goes through handleDeploySoftware with the new
// endpoint as its only explicit target, so management rights, the deploy
// action group, content sets, parameters, maintenance windows, audit
// attribution and per-device results are the ordinary deployment's. The
// replacement itself only records which run carries which package and
// reads the outcome back from that run's action on the new endpoint.
//
// Server-side only: the agent sees ordinary software deployments.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/deploy"
	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
	"github.com/mustra-dev/mustra/internal/swinventory"
)

// Item statuses. The four outcomes an install can have on the endpoint
// (installed, failed, timed_out, no_response) are kept apart for the same
// reason the Deployments view keeps them apart: each asks something
// different of whoever reads the report.
const (
	replPending          = "pending"
	replRunning          = "running"
	replAwaitingApproval = "awaiting_approval"
	replInstalled        = "installed"
	replFailed           = "failed"
	replTimedOut         = "timed_out"
	replNoResponse       = "no_response"
	replSkipped          = "skipped"
	replRefused          = "refused"
)

func replacementItemFinal(status string) bool {
	switch status {
	case replInstalled, replFailed, replTimedOut, replNoResponse, replSkipped, replRefused:
		return true
	}
	return false
}

// --- requests and responses -------------------------------------------------

// deviceReplacementPreviewRequest names the two endpoints of a device
// replacement. Each is named by exactly one of its agent ID, hostname or
// hardware serial number; a hostname or serial that matches more than one
// endpoint is refused, never guessed at.
type deviceReplacementPreviewRequest struct {
	// OldAgentID names the endpoint being replaced by its agent ID.
	OldAgentID string `json:"old_agent_id,omitempty"`
	// OldHostname names the endpoint being replaced by its hostname
	// (case-insensitive; a short name matches a fully qualified one).
	OldHostname string `json:"old_hostname,omitempty"`
	// OldSerial names the endpoint being replaced by the serial number its
	// hardware sensor reports.
	OldSerial string `json:"old_serial,omitempty"`
	// NewAgentID names the replacement endpoint by its agent ID.
	NewAgentID string `json:"new_agent_id,omitempty"`
	// NewHostname names the replacement endpoint by its hostname. Retired
	// endpoints are not considered.
	NewHostname string `json:"new_hostname,omitempty"`
	// NewSerial names the replacement endpoint by its hardware serial.
	NewSerial string `json:"new_serial,omitempty"`
	// AllowCrossOS permits endpoints of different operating systems
	// (Windows to macOS, say); otherwise that is refused.
	AllowCrossOS bool `json:"allow_cross_os,omitempty"`
}

// deviceReplacementRequest starts a device replacement job.
type deviceReplacementRequest struct {
	deviceReplacementPreviewRequest
	// Ticket is the external ticket this replacement answers: a ServiceNow
	// number (INC…, RITM…, REQ…, SCTASK…, CHG…) or an incident's sys_id.
	// When a ServiceNow integration is enabled, the final report is added
	// to it as a work note.
	Ticket string `json:"ticket,omitempty"`
	// PackageIDs limits the job to these packages, each of which must be in
	// the preview's will_install list. Empty means all of them.
	PackageIDs []string `json:"package_ids,omitempty"`
	// ExcludePackageIDs leaves these packages out.
	ExcludePackageIDs []string `json:"exclude_package_ids,omitempty"`
}

// replacementEndpoint is one side of a device replacement.
type replacementEndpoint struct {
	AgentID  string `json:"agent_id"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Platform string `json:"platform,omitempty"`
	Online   bool   `json:"online"`
	Managed  bool   `json:"managed"`
	// InventoryAt is when the endpoint last reported its installed
	// software; absent when it never has.
	InventoryAt *time.Time `json:"inventory_at,omitempty"`
}

// deviceReplacementPreviewResponse is what a replacement would do, without
// doing it.
type deviceReplacementPreviewResponse struct {
	Old replacementEndpoint `json:"old"`
	New replacementEndpoint `json:"new"`
	// WillInstall are the catalog packages that would be installed on the
	// new endpoint, each with the old endpoint's products it covers.
	WillInstall []store.DeviceReplacementItem `json:"will_install"`
	// AlreadyPresent are the old endpoint's products the new one already
	// has, by inventory or by a package's detection.
	AlreadyPresent []store.DeviceReplacementProduct `json:"already_present"`
	// NoMatch are the old endpoint's products no usable catalog package
	// installs on the new endpoint, each with the reason.
	NoMatch  []store.DeviceReplacementProduct `json:"no_match"`
	Warnings []string                         `json:"warnings"`
}

// deviceReplacementView is a job with its derived state.
type deviceReplacementView struct {
	store.DeviceReplacement
	// Status is running until every item has an outcome, then completed
	// (everything installed), partial, no_response or failed.
	Status string `json:"status"`
	// Counts are the items per status.
	Counts map[string]int `json:"counts"`
}

// listDeviceReplacementsResponse is what GET /api/device-replacements
// answers: the newest 200 jobs.
type listDeviceReplacementsResponse struct {
	Jobs []deviceReplacementView `json:"jobs"`
}

// --- resolving the two endpoints ------------------------------------------

type replacementRef struct{ agentID, hostname, serial string }

func (r replacementRef) count() int {
	n := 0
	for _, v := range []string{r.agentID, r.hostname, r.serial} {
		if strings.TrimSpace(v) != "" {
			n++
		}
	}
	return n
}

// hostShortName is a hostname's first label.
func hostShortName(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.IndexByte(h, '.'); i > 0 {
		return h[:i]
	}
	return h
}

// resolveReplacementDevice finds the one endpoint a reference names. It
// refuses rather than picks: two endpoints with one hostname (an old
// laptop's record and its successor named the same, say) or one serial is
// an error that asks for the agent ID, because guessing wrong installs
// software on, or reads the inventory of, somebody else's machine.
// managedOnly leaves retired endpoints out, for the new endpoint.
func resolveReplacementDevice(agents []store.AgentRecord, serials map[string]string, role string, ref replacementRef, managedOnly bool) (store.AgentRecord, error) {
	if ref.count() != 1 {
		return store.AgentRecord{}, httpError{http.StatusBadRequest,
			"name the " + role + " endpoint by exactly one of " + role + "_agent_id, " + role + "_hostname or " + role + "_serial"}
	}
	var hits []store.AgentRecord
	var what string
	switch {
	case strings.TrimSpace(ref.agentID) != "":
		id := strings.TrimSpace(ref.agentID)
		what = "agent ID " + id
		for _, a := range agents {
			if a.AgentID == id {
				hits = append(hits, a)
			}
		}
		if len(hits) == 1 && managedOnly && !hits[0].Managed {
			return store.AgentRecord{}, httpError{http.StatusConflict, "the " + role + " endpoint " + hits[0].Hostname + " is retired; nothing can be installed on it"}
		}
	case strings.TrimSpace(ref.hostname) != "":
		h := strings.ToLower(strings.TrimSpace(ref.hostname))
		what = "hostname " + strings.TrimSpace(ref.hostname)
		for _, a := range agents {
			if (!managedOnly || a.Managed) && strings.ToLower(strings.TrimSpace(a.Hostname)) == h {
				hits = append(hits, a)
			}
		}
		// A ticket often carries the short name of a machine that reports
		// its fully qualified one, or the other way round. Only then, and
		// only when one side has no domain, are short names compared.
		if len(hits) == 0 {
			for _, a := range agents {
				ah := strings.ToLower(strings.TrimSpace(a.Hostname))
				if (managedOnly && !a.Managed) || ah == "" {
					continue
				}
				if (!strings.Contains(h, ".") && hostShortName(ah) == h) || (!strings.Contains(ah, ".") && hostShortName(h) == ah) {
					hits = append(hits, a)
				}
			}
		}
	default:
		sn := strings.TrimSpace(ref.serial)
		what = "serial number " + sn
		for _, a := range agents {
			if (!managedOnly || a.Managed) && strings.EqualFold(strings.TrimSpace(serials[a.AgentID]), sn) {
				hits = append(hits, a)
			}
		}
	}
	switch len(hits) {
	case 0:
		return store.AgentRecord{}, httpError{http.StatusNotFound, "no endpoint has " + what}
	case 1:
		return hits[0], nil
	}
	names := make([]string, 0, len(hits))
	for _, a := range hits {
		names = append(names, a.Hostname+" ("+a.AgentID+")")
	}
	sort.Strings(names)
	return store.AgentRecord{}, httpError{http.StatusConflict, fmt.Sprintf("%d endpoints have %s: %s. Name the %s endpoint by its agent ID",
		len(hits), what, strings.Join(names, ", "), role)}
}

// checkReplacementPair applies the rules about the two endpoints together.
func checkReplacementPair(oldA, newA store.AgentRecord, allowCrossOS bool) error {
	if oldA.AgentID == newA.AgentID {
		return httpError{http.StatusBadRequest, "the old and new endpoint are the same endpoint"}
	}
	if oldA.OS != newA.OS && !allowCrossOS {
		return httpError{http.StatusBadRequest, fmt.Sprintf("%s runs %s and %s runs %s; allow a different operating system (allow_cross_os) to replace one with the other",
			oldA.Hostname, oldA.OS, newA.Hostname, newA.OS)}
	}
	return nil
}

func (s *Server) resolveReplacementPair(ctx context.Context, req deviceReplacementPreviewRequest) (store.AgentRecord, store.AgentRecord, error) {
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return store.AgentRecord{}, store.AgentRecord{}, err
	}
	var serials map[string]string
	if strings.TrimSpace(req.OldSerial) != "" || strings.TrimSpace(req.NewSerial) != "" {
		if serials, err = s.hardwareSerials(ctx); err != nil {
			return store.AgentRecord{}, store.AgentRecord{}, err
		}
	}
	oldA, err := resolveReplacementDevice(agents, serials, "old", replacementRef{req.OldAgentID, req.OldHostname, req.OldSerial}, false)
	if err != nil {
		return store.AgentRecord{}, store.AgentRecord{}, err
	}
	newA, err := resolveReplacementDevice(agents, serials, "new", replacementRef{req.NewAgentID, req.NewHostname, req.NewSerial}, true)
	if err != nil {
		return store.AgentRecord{}, store.AgentRecord{}, err
	}
	if err := checkReplacementPair(oldA, newA, req.AllowCrossOS); err != nil {
		return store.AgentRecord{}, store.AgentRecord{}, err
	}
	return oldA, newA, nil
}

// hardwareSerials is every endpoint's serial number, from its hardware
// sensor.
func (s *Server) hardwareSerials(ctx context.Context) (map[string]string, error) {
	rows, err := s.store.ListSensorDataForSensor(ctx, string(proto.SensorHardware))
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rows))
	for _, row := range rows {
		var h []proto.HardwareInfo
		if json.Unmarshal(row.Data, &h) == nil && len(h) > 0 && strings.TrimSpace(h[0].Serial) != "" {
			out[row.AgentID] = strings.TrimSpace(h[0].Serial)
		}
	}
	return out, nil
}

// --- the plan -----------------------------------------------------------------

// replacementInventory is one endpoint's installed-apps snapshot, both as
// the sensor's typed rows (for product normalisation) and as the index the
// catalog's detection reads.
type replacementInventory struct {
	apps  []proto.InstalledApp
	index agentApps
}

// replacementCandidate is a catalog package that may carry a product to
// the new endpoint.
type replacementCandidate struct {
	pkg store.SoftwarePackage
	// scope is the package's computer-group scope (nil: every endpoint).
	scope map[string]bool
	// denied is why the caller may not deploy it (content sets), or "".
	denied string
}

type replacementPlan struct {
	WillInstall    []store.DeviceReplacementItem
	AlreadyPresent []store.DeviceReplacementProduct
	NoMatch        []store.DeviceReplacementProduct
}

// replacementPackageUsable is a software package something can be
// installed from: enabled, published (or with legacy commands), and not
// the agent-update package, whose "installed" is a fact about the agent
// rather than an application.
func replacementPackageUsable(p store.SoftwarePackage) bool {
	if p.Kind != store.KindSoftware || !p.Enabled || p.Detect.Fact != "" {
		return false
	}
	if p.DeployRevision != "" {
		return p.DeployDefinition != nil
	}
	return len(p.Commands) > 0
}

// packageDetectsRows reports whether a package's detection, evaluated on
// the old endpoint, finds any of these rows of its inventory: the same
// matching the catalog's applicability does, one row at a time so it says
// which product the package is.
func packageDetectsRows(p store.SoftwarePackage, a store.AgentRecord, inv replacementInventory, rows []int) bool {
	if p.DeployDefinition != nil {
		v, err := deploy.SelectVariant(*p.DeployDefinition, a.OS, a.Arch, a.Platform, a.PlatformVersion)
		if err != nil {
			return false
		}
		for _, i := range rows {
			if i >= len(inv.index.rows) {
				continue
			}
			if installed, _, ok := detectFromInventory(v.Detection, []map[string]any{inv.index.rows[i]}); ok && installed {
				return true
			}
		}
		return false
	}
	for _, i := range rows {
		app := inv.apps[i]
		if matchInstalled(p.Detect, p.Name, map[string]string{strings.ToLower(app.Name): app.Version}) != "" {
			return true
		}
	}
	return false
}

type replacementVerdict struct {
	kind   string // install, present, blocked
	found  string
	reason string
}

// planReplacement compares the two inventories and matches what the new
// endpoint lacks to catalog packages. Pure, so the whole decision can be
// tested without a database.
func planReplacement(oldA, newA store.AgentRecord, oldInv, newInv replacementInventory, cands []replacementCandidate) replacementPlan {
	type product struct {
		p       swinventory.Product
		version string
		rows    []int
	}
	var order []string
	olds := map[string]*product{}
	for i, app := range oldInv.apps {
		if strings.TrimSpace(app.Name) == "" {
			continue
		}
		p := swinventory.Normalize(app.Name, app.Publisher, oldA.OS)
		// Libraries, runtimes, drivers, OS updates: they arrive with the
		// operating system or with the application that needs them.
		if swinventory.IsComponent(p.Name, oldA.OS) || swinventory.IsComponent(app.Name, oldA.OS) {
			continue
		}
		cur := olds[p.Key]
		if cur == nil {
			cur = &product{p: p}
			olds[p.Key] = cur
			order = append(order, p.Key)
		}
		cur.rows = append(cur.rows, i)
		if cur.version == "" || swinventory.CompareVersions(app.Version, cur.version) > 0 {
			cur.version = app.Version
		}
	}
	newVersions := map[string]string{}
	for _, app := range newInv.apps {
		if strings.TrimSpace(app.Name) == "" {
			continue
		}
		k := swinventory.Normalize(app.Name, app.Publisher, newA.OS).Key
		if v, ok := newVersions[k]; !ok || v == "" || swinventory.CompareVersions(app.Version, v) > 0 {
			newVersions[k] = app.Version
		}
	}

	// Published packages first, then by name: when two packages detect the
	// same product, the choice is the same on every preview.
	cands = append([]replacementCandidate(nil), cands...)
	sort.SliceStable(cands, func(i, j int) bool {
		pi, pj := cands[i].pkg.DeployDefinition != nil, cands[j].pkg.DeployDefinition != nil
		if pi != pj {
			return pi
		}
		if !strings.EqualFold(cands[i].pkg.Name, cands[j].pkg.Name) {
			return strings.ToLower(cands[i].pkg.Name) < strings.ToLower(cands[j].pkg.Name)
		}
		return cands[i].pkg.ID < cands[j].pkg.ID
	})
	verdicts := map[string]replacementVerdict{}
	verdictFor := func(c replacementCandidate) replacementVerdict {
		if v, ok := verdicts[c.pkg.ID]; ok {
			return v
		}
		var v replacementVerdict
		state, found, reason := evaluateApplicability(c.pkg, newA, newInv.index, c.scope)
		switch {
		case state == stateInstalled || state == stateUpdateEligible:
			v = replacementVerdict{kind: "present", found: found, reason: c.pkg.Name + " detects it on the new endpoint"}
		case state != stateInstallEligible:
			v = replacementVerdict{kind: "blocked", reason: c.pkg.Name + " does not apply to the new endpoint: " + firstNonEmpty(reason, state)}
		case !hasCommandFor(c.pkg, newA.OS, "install"):
			v = replacementVerdict{kind: "blocked", reason: c.pkg.Name + " has no install action for " + newA.OS}
		case c.denied != "":
			v = replacementVerdict{kind: "blocked", reason: c.denied}
		default:
			v = replacementVerdict{kind: "install", reason: reason}
		}
		verdicts[c.pkg.ID] = v
		return v
	}

	plan := replacementPlan{WillInstall: []store.DeviceReplacementItem{}, AlreadyPresent: []store.DeviceReplacementProduct{}, NoMatch: []store.DeviceReplacementProduct{}}
	itemAt := map[string]int{}
	for _, key := range order {
		op := olds[key]
		rec := store.DeviceReplacementProduct{Key: key, Name: op.p.Name, Vendor: op.p.Vendor, OldVersion: op.version}
		if v, ok := newVersions[key]; ok {
			rec.NewVersion = v
			rec.Reason = "In the new endpoint's inventory"
			plan.AlreadyPresent = append(plan.AlreadyPresent, rec)
			continue
		}
		var chosen *replacementCandidate
		var verdict replacementVerdict
		for i := range cands {
			c := &cands[i]
			if !packageDetectsRows(c.pkg, oldA, oldInv, op.rows) {
				continue
			}
			v := verdictFor(*c)
			// The first that installs wins; otherwise the first that says
			// it is already there; otherwise the first refusal explains.
			if chosen == nil || rank(v.kind) < rank(verdict.kind) {
				chosen, verdict = c, v
			}
			if v.kind == "install" {
				break
			}
		}
		switch {
		case chosen == nil:
			rec.Reason = "No catalog package detects it"
			plan.NoMatch = append(plan.NoMatch, rec)
		case verdict.kind == "present":
			rec.PackageID, rec.PackageName = chosen.pkg.ID, chosen.pkg.Name
			if verdict.found != "installed" {
				rec.NewVersion = verdict.found
			}
			rec.Reason = verdict.reason
			plan.AlreadyPresent = append(plan.AlreadyPresent, rec)
		case verdict.kind == "blocked":
			rec.PackageID, rec.PackageName = chosen.pkg.ID, chosen.pkg.Name
			rec.Reason = verdict.reason
			plan.NoMatch = append(plan.NoMatch, rec)
		default:
			if i, ok := itemAt[chosen.pkg.ID]; ok {
				plan.WillInstall[i].Products = append(plan.WillInstall[i].Products, op.p.Name)
				continue
			}
			itemAt[chosen.pkg.ID] = len(plan.WillInstall)
			version := chosen.pkg.Version
			plan.WillInstall = append(plan.WillInstall, store.DeviceReplacementItem{
				PackageID: chosen.pkg.ID, PackageName: chosen.pkg.Name, Version: version,
				Products: []string{op.p.Name}, Detail: verdict.reason,
			})
		}
	}
	byName := func(a, b string) bool { return strings.ToLower(a) < strings.ToLower(b) }
	sort.SliceStable(plan.WillInstall, func(i, j int) bool { return byName(plan.WillInstall[i].PackageName, plan.WillInstall[j].PackageName) })
	sort.SliceStable(plan.AlreadyPresent, func(i, j int) bool { return byName(plan.AlreadyPresent[i].Name, plan.AlreadyPresent[j].Name) })
	sort.SliceStable(plan.NoMatch, func(i, j int) bool { return byName(plan.NoMatch[i].Name, plan.NoMatch[j].Name) })
	return plan
}

func rank(kind string) int {
	switch kind {
	case "install":
		return 0
	case "present":
		return 1
	}
	return 2
}

// parseAgentApps reads one installed-apps snapshot. installedAppsByAgent
// reads the fleet's through it, so the replacement's index is the
// catalog's.
func parseAgentApps(data []byte) ([]proto.InstalledApp, agentApps, error) {
	var apps []proto.InstalledApp
	if err := json.Unmarshal(data, &apps); err != nil {
		return nil, agentApps{}, err
	}
	byName := make(map[string]string, len(apps))
	for _, app := range apps {
		byName[strings.ToLower(app.Name)] = app.Version
	}
	var raw []map[string]any
	if json.Unmarshal(data, &raw) != nil {
		raw = nil
	}
	return apps, agentApps{byName: byName, rows: raw}, nil
}

func (s *Server) replacementInventory(ctx context.Context, agentID string) (replacementInventory, *time.Time, error) {
	rec, err := s.store.GetSensorData(ctx, agentID, string(proto.SensorInstalledApps))
	if err != nil || rec == nil {
		return replacementInventory{}, nil, err
	}
	apps, idx, err := parseAgentApps(rec.Data)
	if err != nil {
		return replacementInventory{}, nil, fmt.Errorf("the installed software %s reported cannot be read: %w", agentID, err)
	}
	at := rec.CollectedAt
	return replacementInventory{apps: apps, index: idx}, &at, nil
}

func endpointOf(a store.AgentRecord, at *time.Time) replacementEndpoint {
	return replacementEndpoint{AgentID: a.AgentID, Hostname: a.Hostname, OS: a.OS, Platform: a.Platform,
		Online: a.Online, Managed: a.Managed, InventoryAt: at}
}

// replacementPreview gathers what planReplacement needs and runs it.
func (s *Server) replacementPreview(ctx context.Context, oldA, newA store.AgentRecord) (*deviceReplacementPreviewResponse, error) {
	oldInv, oldAt, err := s.replacementInventory(ctx, oldA.AgentID)
	if err != nil {
		return nil, err
	}
	if oldAt == nil {
		return nil, httpError{http.StatusConflict, oldA.Hostname + " has not reported its installed software, so there is nothing to compare"}
	}
	newInv, newAt, err := s.replacementInventory(ctx, newA.AgentID)
	if err != nil {
		return nil, err
	}
	pkgs, err := s.store.ListSoftwarePackages(ctx)
	if err != nil {
		return nil, err
	}
	scopes := map[string]map[string]bool{}
	var cands []replacementCandidate
	for _, p := range pkgs {
		if !replacementPackageUsable(p) {
			continue
		}
		c := replacementCandidate{pkg: p}
		if len(p.GroupIDs) > 0 {
			key := strings.Join(p.GroupIDs, ",")
			scope, ok := scopes[key]
			if !ok {
				if scope, err = s.agentsInGroups(ctx, p.GroupIDs); err != nil {
					return nil, err
				}
				scopes[key] = scope
			}
			c.scope = scope
		}
		if ok, err := s.contentAllowed(ctx, "packages", p.ID); err != nil {
			return nil, err
		} else if !ok {
			c.denied = p.Name + " is not in a content set your roles grant"
		}
		cands = append(cands, c)
	}
	plan := planReplacement(oldA, newA, oldInv, newInv, cands)
	out := &deviceReplacementPreviewResponse{
		Old: endpointOf(oldA, oldAt), New: endpointOf(newA, newAt),
		WillInstall: plan.WillInstall, AlreadyPresent: plan.AlreadyPresent, NoMatch: plan.NoMatch, Warnings: []string{},
	}
	if newAt == nil {
		out.Warnings = append(out.Warnings, newA.Hostname+" has not reported its installed software yet, so nothing counts as already there; each install checks the endpoint again before it runs.")
	}
	if age := time.Since(*oldAt); age > 7*24*time.Hour {
		out.Warnings = append(out.Warnings, fmt.Sprintf("%s's installed software was last reported %d days ago.", oldA.Hostname, int(age.Hours()/24)))
	}
	if !newA.Online {
		out.Warnings = append(out.Warnings, newA.Hostname+" is offline: installs wait for it, and those that cannot wait report no response.")
	}
	return out, nil
}

// selectReplacementItems applies the caller's choice to the preview's
// installs. A package that is not one of them is refused: it would mean
// installing something the comparison did not find on the old endpoint.
func selectReplacementItems(planned []store.DeviceReplacementItem, include, exclude []string) ([]store.DeviceReplacementItem, error) {
	byID := map[string]bool{}
	for _, it := range planned {
		byID[it.PackageID] = true
	}
	want := map[string]bool{}
	for _, id := range include {
		if !byID[id] {
			return nil, httpError{http.StatusBadRequest, "package " + id + " is not one this replacement would install"}
		}
		want[id] = true
	}
	drop := map[string]bool{}
	for _, id := range exclude {
		drop[id] = true
	}
	out := []store.DeviceReplacementItem{}
	for _, it := range planned {
		if (len(want) > 0 && !want[it.PackageID]) || drop[it.PackageID] {
			continue
		}
		it.Status, it.Detail = replPending, ""
		out = append(out, it)
	}
	return out, nil
}

// --- dispatch -----------------------------------------------------------------

// dispatchReplacementItem hands one package to the ordinary software
// deployment, aimed at exactly the new endpoint. deploy is
// handleDeploySoftware; a parameter so a test can see what it is asked.
//
// The agent ID is checked here as well as by the caller because an empty
// agent_ids is how handleDeploySoftware is asked for every eligible
// endpoint in the fleet.
func dispatchReplacementItem(deploy http.HandlerFunc, r *http.Request, agentID string, it store.DeviceReplacementItem) store.DeviceReplacementItem {
	if strings.TrimSpace(agentID) == "" {
		it.Status, it.Detail = replRefused, "no target endpoint"
		return it
	}
	raw, _ := json.Marshal(softwareDeployRequest{PackageID: it.PackageID, Operation: "install", AgentIDs: []string{agentID}})
	sub := r.Clone(r.Context())
	sub.Method = http.MethodPost
	sub.URL.Path = "/api/software/deploy"
	sub.Body = io.NopCloser(bytes.NewReader(raw))
	sub.ContentLength = int64(len(raw))
	rec := &captureWriter{header: http.Header{}}
	deploy(rec, sub)
	body := strings.TrimSpace(rec.body.String())
	switch rec.status {
	case http.StatusOK:
		var out struct {
			RunID string `json:"run_id"`
		}
		if json.Unmarshal([]byte(body), &out) != nil || out.RunID == "" {
			it.Status, it.Detail = replRefused, "the deployment answered without a run: "+safeTruncate(body, 300)
			return it
		}
		it.RunID, it.Status, it.Detail = out.RunID, replPending, ""
	case http.StatusAccepted:
		var out struct {
			RequestID string `json:"request_id"`
		}
		_ = json.Unmarshal([]byte(body), &out)
		it.ApprovalID, it.Status, it.Detail = out.RequestID, replAwaitingApproval, "Parked for approval"
	default:
		it.Status, it.Detail = replRefused, safeTruncate(body, 500)
	}
	return it
}

// --- outcome ------------------------------------------------------------------

// replacementItemStatus derives one dispatched item's status from the run's
// action on the new endpoint and, for a catalog release, its deploy job.
// Pure: given the same records, the same answer.
func replacementItemStatus(act *store.AgentAction, job *store.DeployJobRecord, dispatchedAt, now time.Time) (status, detail string) {
	if act == nil {
		if now.Sub(dispatchedAt) > deploymentStallAfter {
			return replNoResponse, "The deployment never reached the endpoint"
		}
		return replPending, "Waiting for the endpoint"
	}
	switch act.Status {
	case "succeeded":
		return replInstalled, ""
	case "pending_restart":
		return replInstalled, "Installed; a restart is pending"
	case "failed", "degraded", "cancelled", "interrupted", "unsupported":
		return replFailed, firstNonEmpty(act.Detail, act.Status)
	case "timed_out":
		return replTimedOut, act.Detail
	case "no_response":
		return replNoResponse, act.Detail
	case "expired":
		// Nothing ran: the endpoint never took the job before it expired.
		return replNoResponse, firstNonEmpty(act.Detail, "Expired before the endpoint accepted it")
	case "skipped":
		return replSkipped, act.Detail
	}
	// Still open. A catalog job waiting in the queue (for the endpoint, or
	// for a maintenance window) with an expiry is left to expire: that is
	// the deployment's own answer, and it becomes "no response" then.
	if job != nil && (job.Status == "queued" || job.Status == "held") && !job.Job.ExpiresAt.IsZero() {
		return replPending, job.Detail
	}
	if now.Sub(act.StartedAt) > deploymentStallAfter {
		if act.Status == "started" {
			return replNoResponse, "No result from the endpoint in " + deploymentStallAfter.String()
		}
		return replTimedOut, "Still " + act.Status + " on the endpoint after " + deploymentStallAfter.String() + " with no result"
	}
	if act.Status == "started" {
		return replPending, firstNonEmpty(jobDetail(job), "Sent to the endpoint")
	}
	return replRunning, act.Status
}

func jobDetail(job *store.DeployJobRecord) string {
	if job == nil {
		return ""
	}
	return job.Detail
}

// refreshReplacement brings a running job's items up to date and reports
// whether every one has an outcome. A run ID learnt from an approval is
// stored, so it is looked up once.
func (s *Server) refreshReplacement(ctx context.Context, job *store.DeviceReplacement) (bool, error) {
	if job.FinishedAt != nil {
		return true, nil
	}
	now := time.Now()
	learnt := false
	done := true
	for i := range job.Items {
		it := &job.Items[i]
		if it.Status == replRefused {
			continue
		}
		if it.RunID == "" && it.ApprovalID != "" {
			apr, err := s.store.GetApprovalRequest(ctx, it.ApprovalID)
			if err != nil {
				return false, err
			}
			switch {
			case apr == nil:
				it.Status, it.Detail = replRefused, "The approval request no longer exists"
			case apr.State == "approved":
				var out struct {
					RunID string `json:"run_id"`
				}
				if json.Unmarshal([]byte(apr.Outcome), &out) == nil && out.RunID != "" {
					it.RunID, learnt = out.RunID, true
				} else {
					it.Status, it.Detail = replRefused, "Approved, but the deployment did not start: "+safeTruncate(apr.Outcome, 300)
				}
			case apr.State == "pending" || apr.State == "approving":
				it.Status, it.Detail = replAwaitingApproval, "Waiting for approval under "+apr.PolicyName
			default:
				it.Status, it.Detail = replRefused, "Approval "+apr.State+firstNonEmpty(": "+apr.DecisionNote, "")
			}
			if it.RunID == "" {
				if !replacementItemFinal(it.Status) {
					done = false
				}
				continue
			}
		}
		if it.RunID == "" {
			if !replacementItemFinal(it.Status) {
				done = false
			}
			continue
		}
		actions, err := s.store.ActionsForRun(ctx, it.RunID)
		if err != nil {
			return false, err
		}
		var act *store.AgentAction
		for j := range actions {
			// The run names exactly this endpoint; anything else on it
			// would not be this replacement's, and is not read.
			if actions[j].AgentID == job.NewAgentID {
				a := actions[j].AgentAction
				act = &a
			}
		}
		it.Status, it.Detail = replacementItemStatus(act, nil, job.CreatedAt, now)
		// Still open: a catalog release's queued job may be waiting for a
		// window or an expiry, which only its deploy job says.
		if act != nil && !replacementItemFinal(it.Status) {
			dj, err := s.store.GetDeployJob(ctx, act.ID)
			if err != nil {
				return false, err
			}
			it.Status, it.Detail = replacementItemStatus(act, dj, job.CreatedAt, now)
		}
		it.Detail = safeTruncate(it.Detail, 1000)
		if !replacementItemFinal(it.Status) {
			done = false
		}
	}
	if learnt {
		if err := s.store.SetDeviceReplacementItems(ctx, job.ID, job.Items); err != nil {
			return false, err
		}
	}
	return done, nil
}

func replacementView(job store.DeviceReplacement) deviceReplacementView {
	counts := map[string]int{}
	for _, it := range job.Items {
		counts[it.Status]++
	}
	return deviceReplacementView{DeviceReplacement: job, Status: replacementJobStatus(job), Counts: counts}
}

// replacementJobStatus summarises a job: running until it finishes, then
// completed when everything chosen was installed, partial when some was,
// no_response when the endpoint never answered for any, failed otherwise.
func replacementJobStatus(job store.DeviceReplacement) string {
	if job.FinishedAt == nil {
		return "running"
	}
	installed, silent := 0, 0
	for _, it := range job.Items {
		switch it.Status {
		case replInstalled:
			installed++
		case replNoResponse:
			silent++
		}
	}
	switch {
	case installed == len(job.Items):
		return "completed"
	case installed > 0:
		return "partial"
	case silent == len(job.Items):
		// Nothing ran anywhere: the new endpoint was never there to ask,
		// which is not the packages failing.
		return "no_response"
	}
	return "failed"
}

// finishReplacementIfDone records a job's outcome once every item has one
// and reports it to the job's ticket; noteLater sends that report in the
// background, so a page load does not wait on ServiceNow.
func (s *Server) finishReplacementIfDone(ctx context.Context, job store.DeviceReplacement, noteLater bool) {
	done, err := s.refreshReplacement(ctx, &job)
	if err != nil {
		s.logger.Warn("device replacement refresh failed", "id", job.ID, "error", err)
		return
	}
	if !done {
		return
	}
	noteStatus := ""
	if job.Ticket != "" {
		noteStatus = "pending"
	}
	claimed, err := s.store.FinishDeviceReplacement(ctx, job.ID, job.Items, noteStatus)
	if err != nil || !claimed {
		if err != nil {
			s.logger.Warn("finishing device replacement failed", "id", job.ID, "error", err)
		}
		return
	}
	now := time.Now().UTC()
	job.FinishedAt = &now
	view := replacementView(job)
	s.audit(ctx, auditEvent{Action: "device_replacement.finish", Actor: job.RequestedBy,
		Target: job.OldHostname + " → " + job.NewHostname, AgentID: job.NewAgentID, Severity: "info",
		Detail: map[string]any{"id": job.ID, "status": view.Status, "counts": view.Counts, "ticket": job.Ticket}})
	if job.Ticket == "" {
		return
	}
	if noteLater {
		go s.noteReplacement(context.WithoutCancel(ctx), job)
		return
	}
	s.noteReplacement(ctx, job)
}

func (s *Server) noteReplacement(ctx context.Context, job store.DeviceReplacement) {
	status, detail := s.postReplacementNote(ctx, job, replacementReportText(job, s.eventLink(ctx, integrationEvent{Link: "/device-replacement#" + job.ID})))
	if err := s.store.SetDeviceReplacementNote(ctx, job.ID, status, detail); err != nil {
		s.logger.Warn("recording the device replacement's ticket note failed", "id", job.ID, "error", err)
	}
}

// deviceReplacementLoop finishes jobs whose installs have all reported.
func (s *Server) deviceReplacementLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		jobs, err := s.store.ListDeviceReplacements(ctx, 500, true)
		if err != nil {
			s.logger.Warn("listing device replacements failed", "error", err)
			continue
		}
		for _, job := range jobs {
			s.finishReplacementIfDone(ctx, job, false)
		}
	}
}

// replacementReportText is the report as plain text, for a ticket's work
// notes.
func replacementReportText(job store.DeviceReplacement, link string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Mustra device replacement %s: software from %s installed on %s.\n", job.ID, job.OldHostname, job.NewHostname)
	fmt.Fprintf(&b, "Requested by %s.\n", firstNonEmpty(job.RequestedBy, "unknown"))
	groups := []struct{ status, label string }{
		{replInstalled, "Installed"}, {replFailed, "Failed"}, {replTimedOut, "Timed out"},
		{replNoResponse, "No response"}, {replSkipped, "Skipped"}, {replRefused, "Not started"},
	}
	for _, g := range groups {
		var lines []string
		for _, it := range job.Items {
			if it.Status != g.status {
				continue
			}
			line := it.PackageName
			if it.Detail != "" && g.status != replInstalled {
				line += " — " + safeTruncate(strings.ReplaceAll(it.Detail, "\n", " "), 200)
			}
			lines = append(lines, line)
		}
		if len(lines) > 0 {
			fmt.Fprintf(&b, "\n%s (%d):\n- %s\n", g.label, len(lines), strings.Join(lines, "\n- "))
		}
	}
	if len(job.Items) == 0 {
		b.WriteString("\nNothing was installed: no catalog package matched software missing from the new endpoint.\n")
	}
	if len(job.NoMatch) > 0 {
		var names []string
		for _, p := range job.NoMatch {
			n := p.Name
			if p.OldVersion != "" {
				n += " " + p.OldVersion
			}
			names = append(names, n)
		}
		fmt.Fprintf(&b, "\nNo matching package, to install by hand (%d):\n- %s\n", len(names), strings.Join(names, "\n- "))
	}
	if len(job.AlreadyPresent) > 0 {
		fmt.Fprintf(&b, "\nAlready on the new endpoint: %d.\n", len(job.AlreadyPresent))
	}
	if link != "" {
		fmt.Fprintf(&b, "\n%s\n", link)
	}
	return safeTruncate(b.String(), 30000)
}

// --- handlers -----------------------------------------------------------------

// replyError answers with the status an httpError carries. The statuses
// this file's helpers use are spelt out so the API reference can see them.
func replyError(w http.ResponseWriter, err error) {
	var he httpError
	if !asHTTPError(err, &he) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	switch he.code {
	case http.StatusNotFound:
		http.Error(w, he.msg, http.StatusNotFound)
	case http.StatusConflict:
		http.Error(w, he.msg, http.StatusConflict)
	default:
		http.Error(w, he.msg, http.StatusBadRequest)
	}
}

// POST /api/device-replacements/preview
func (s *Server) handleDeviceReplacementPreview(w http.ResponseWriter, r *http.Request) {
	var req deviceReplacementPreviewRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	oldA, newA, err := s.resolveReplacementPair(r.Context(), req)
	if err != nil {
		replyError(w, err)
		return
	}
	// Said now rather than at the run: an operator who may not deploy to
	// the new endpoint should not be shown a list of what would go there.
	if !s.checkTargets(w, r, "deploy", []string{newA.AgentID}) {
		return
	}
	p, err := s.replacementPreview(r.Context(), oldA, newA)
	if err != nil {
		replyError(w, err)
		return
	}
	writeJSONResponse(w, p)
}

// POST /api/device-replacements starts a job. The route gate has already
// checked the new endpoint against the caller's management rights and the
// deploy action group, and parked the request if an approval policy covers
// it; approving it replays this handler.
func (s *Server) handleStartDeviceReplacement(w http.ResponseWriter, r *http.Request) {
	var req deviceReplacementRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	ticket, err := normalizeTicket(req.Ticket)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	oldA, newA, err := s.resolveReplacementPair(ctx, req.deviceReplacementPreviewRequest)
	if err != nil {
		replyError(w, err)
		return
	}
	if !s.checkTargets(w, r, "deploy", []string{newA.AgentID}) {
		return
	}
	p, err := s.replacementPreview(ctx, oldA, newA)
	if err != nil {
		replyError(w, err)
		return
	}
	items, err := selectReplacementItems(p.WillInstall, req.PackageIDs, req.ExcludePackageIDs)
	if err != nil {
		replyError(w, err)
		return
	}
	u := auth.CurrentUser(ctx)
	source := "console"
	if _, isToken := auth.Token(ctx); isToken || u.ID == auth.APITokenUserID {
		source = "api"
	}
	job := store.DeviceReplacement{
		ID: idgen.New("drp-"), OldAgentID: oldA.AgentID, OldHostname: oldA.Hostname, OldOS: oldA.OS,
		NewAgentID: newA.AgentID, NewHostname: newA.Hostname, NewOS: newA.OS, Ticket: ticket,
		AllowCrossOS: req.AllowCrossOS, RequestedBy: u.Username, Source: source,
		Items: items, AlreadyPresent: p.AlreadyPresent, NoMatch: p.NoMatch, CreatedAt: time.Now().UTC(),
	}
	if ticket != "" {
		job.NoteStatus = "pending"
	}
	packages := make([]string, 0, len(items))
	for _, it := range items {
		packages = append(packages, it.PackageName)
	}
	// Fail closed, as a deployment does: work that cannot be written to
	// the audit log is not started.
	if err := s.auditStrict(ctx, auditEvent{Action: "device_replacement.start", Actor: u.Username,
		Target: oldA.Hostname + " → " + newA.Hostname, AgentID: newA.AgentID, Severity: "notice",
		Detail: map[string]any{"id": job.ID, "old_agent_id": oldA.AgentID, "new_agent_id": newA.AgentID,
			"ticket": ticket, "packages": packages, "no_match": len(p.NoMatch), "source": source}}); err != nil {
		http.Error(w, "the device replacement could not be recorded in the audit log, so it was not started", http.StatusServiceUnavailable)
		return
	}
	if err := s.store.CreateDeviceReplacement(ctx, job); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for i := range job.Items {
		job.Items[i] = dispatchReplacementItem(s.handleDeploySoftware, r, newA.AgentID, job.Items[i])
	}
	if err := s.store.SetDeviceReplacementItems(ctx, job.ID, job.Items); err != nil {
		s.logger.Warn("recording device replacement items failed", "id", job.ID, "error", err)
	}
	// A job with nothing left to wait for (nothing to install, or every
	// install refused) finishes now, and its ticket hears about it without
	// this request waiting on ServiceNow.
	bg := context.WithoutCancel(ctx)
	go s.finishReplacementIfDone(bg, job, false)
	writeJSONResponse(w, replacementView(job))
}

// GET /api/device-replacements
func (s *Server) handleListDeviceReplacements(w http.ResponseWriter, r *http.Request) {
	jobs, err := s.store.ListDeviceReplacements(r.Context(), 200, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := listDeviceReplacementsResponse{Jobs: make([]deviceReplacementView, 0, len(jobs))}
	for _, job := range jobs {
		done, err := s.refreshReplacement(r.Context(), &job)
		if err != nil {
			s.logger.Warn("device replacement refresh failed", "id", job.ID, "error", err)
		}
		// Finished since the last sweep: record it now rather than show
		// it running until the loop comes round.
		if done && job.FinishedAt == nil {
			s.finishReplacementIfDone(r.Context(), job, true)
			if fresh, err := s.store.GetDeviceReplacement(r.Context(), job.ID); err == nil && fresh != nil {
				job = *fresh
			}
		}
		out.Jobs = append(out.Jobs, replacementView(job))
	}
	writeJSONResponse(w, out)
}

// GET /api/device-replacements/{id}
func (s *Server) handleGetDeviceReplacement(w http.ResponseWriter, r *http.Request) {
	job, err := s.store.GetDeviceReplacement(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if job == nil {
		http.Error(w, "no such device replacement", http.StatusNotFound)
		return
	}
	done, err := s.refreshReplacement(r.Context(), job)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if done && job.FinishedAt == nil {
		s.finishReplacementIfDone(r.Context(), *job, true)
		if fresh, err := s.store.GetDeviceReplacement(r.Context(), job.ID); err == nil && fresh != nil {
			job = fresh
		}
	}
	writeJSONResponse(w, replacementView(*job))
}

// resolveDeviceReplacement is the route gate's reading of a start request:
// its one target is the new endpoint.
func resolveDeviceReplacement(s *Server, r *http.Request, body []byte) (endpointAction, error) {
	var req deviceReplacementRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return endpointAction{}, httpError{http.StatusBadRequest, "invalid JSON body"}
	}
	oldA, newA, err := s.resolveReplacementPair(r.Context(), req.deviceReplacementPreviewRequest)
	if err != nil {
		return endpointAction{}, err
	}
	return endpointAction{Explicit: []string{newA.AgentID},
		Summary: "device replacement: " + oldA.Hostname + "'s software to " + newA.Hostname}, nil
}
