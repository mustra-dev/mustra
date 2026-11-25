package server

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/mustra-dev/mustra/internal/deploy"
	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// The remediation gallery: curated fixes for common endpoint problems,
// maintained in mustra's source (internal/server/remediations, one
// directory per entry) and reviewed like any other code that runs as
// administrator on endpoints.
//
// An entry is not a second way of running things. Importing one creates an
// ordinary action package with a published version, and a one-step
// playbook that runs it, so approvals, management rights, content sets,
// audit attribution and outcome tracking are the same code paths an
// operator's own package and playbook go through. Running one from the
// gallery opens the existing deploy window on that package. Everything is
// behind deploy.manage, because it is operator-chosen code executing on
// endpoints, like a custom package.
//
// Each directory holds remediation.json (what it does, per platform, and
// how risky that is) and one script per platform it supports:
// windows.ps1 (Windows PowerShell 5.1), linux.sh and darwin.sh (POSIX sh,
// run by /bin/sh). Parameters reach a script as MUSTRA_PARAM_<name>, the
// action-package convention. TestRemediationGallery holds every entry to
// the publish rules and to the conventions below.

//go:embed remediations
var remediationFS embed.FS

// remediationScripts maps a script's file name to its platform and
// language.
var remediationScripts = []struct{ file, os, language string }{
	{"windows.ps1", "windows", "powershell"},
	{"linux.sh", "linux", "shell"},
	{"darwin.sh", "darwin", "shell"},
}

var remediationRisks = map[string]bool{"low": true, "medium": true, "high": true}

var remediationIDRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// remediationEntry is one gallery entry as remediation.json describes it,
// plus the scripts beside it.
type remediationEntry struct {
	ID       string `json:"-"`
	Name     string `json:"name"`
	Version  int    `json:"version"`
	Category string `json:"category"`
	Summary  string `json:"summary"`
	Risk     string `json:"risk"`
	RiskNote string `json:"risk_note"`
	// TimeoutSeconds bounds the script on the endpoint.
	TimeoutSeconds int `json:"timeout_seconds"`
	// Changes lists, per platform, exactly what the script changes.
	Changes    map[string][]string     `json:"changes"`
	Parameters []proto.DeployParameter `json:"parameters,omitempty"`
	scripts    map[string]proto.DeployScript
}

func (e remediationEntry) platforms() []string {
	var out []string
	for _, s := range remediationScripts {
		if _, ok := e.scripts[s.os]; ok {
			out = append(out, s.os)
		}
	}
	return out
}

// loadRemediations reads and checks every entry. A malformed entry is an
// error rather than skipped: the gallery is part of the build, and the
// test that loads it is what keeps a broken one from shipping.
func loadRemediations(fsys fs.FS) ([]remediationEntry, error) {
	dirs, err := fs.ReadDir(fsys, "remediations")
	if err != nil {
		return nil, err
	}
	var out []remediationEntry
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		e, err := loadRemediation(fsys, d.Name())
		if err != nil {
			return nil, fmt.Errorf("remediation %s: %w", d.Name(), err)
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, nil
}

func loadRemediation(fsys fs.FS, id string) (remediationEntry, error) {
	var e remediationEntry
	if !remediationIDRe.MatchString(id) {
		return e, errors.New("directory names are lower-case slugs")
	}
	dir := path.Join("remediations", id)
	raw, err := fs.ReadFile(fsys, path.Join(dir, "remediation.json"))
	if err != nil {
		return e, err
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return e, fmt.Errorf("remediation.json: %w", err)
	}
	e.ID = id
	e.scripts = map[string]proto.DeployScript{}
	for _, s := range remediationScripts {
		src, err := fs.ReadFile(fsys, path.Join(dir, s.file))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return e, err
		}
		e.scripts[s.os] = proto.DeployScript{Language: s.language, Source: string(src), TimeoutSeconds: e.TimeoutSeconds}
	}
	switch {
	case strings.TrimSpace(e.Name) == "" || strings.TrimSpace(e.Summary) == "" || strings.TrimSpace(e.Category) == "":
		return e, errors.New("needs a name, a category and a summary")
	case e.Version < 1:
		return e, errors.New("version starts at 1 and only goes up")
	case !remediationRisks[e.Risk] || strings.TrimSpace(e.RiskNote) == "":
		return e, errors.New("risk is low, medium or high, with a note saying why")
	case e.TimeoutSeconds < 30 || e.TimeoutSeconds > 86400:
		return e, errors.New("timeout_seconds is 30 to 86400")
	case len(e.scripts) == 0:
		return e, errors.New("no script for any platform")
	}
	for os := range e.Changes {
		if _, ok := e.scripts[os]; !ok {
			return e, fmt.Errorf("describes changes on %s, which it has no script for", os)
		}
	}
	for os := range e.scripts {
		if len(e.Changes[os]) == 0 {
			return e, fmt.Errorf("has a %s script but does not say what it changes there", os)
		}
	}
	return e, nil
}

var remediationGallery = sync.OnceValues(func() ([]remediationEntry, error) { return loadRemediations(remediationFS) })

func findRemediation(id string) (*remediationEntry, error) {
	all, err := remediationGallery()
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].ID == id {
			return &all[i], nil
		}
	}
	return nil, nil
}

// definition builds the entry's action-package definition: one variant per
// platform, each a single command run as administrator.
func (e remediationEntry) definition() proto.DeployDefinition {
	d := proto.DeployDefinition{Version: proto.DeployVersion, Kind: store.KindAction,
		Parameters: append([]proto.DeployParameter(nil), e.Parameters...)}
	for _, os := range e.platforms() {
		script := e.scripts[os]
		d.Variants = append(d.Variants, proto.DeployVariant{ID: os, OS: os, Actions: map[string]proto.DeployAction{
			"run": {Identity: "administrator", Steps: []proto.DeployStep{{ID: "remediate", Name: e.Name, Script: &script}}},
		}})
	}
	return d
}

// revisionLabel is the action-package version an entry's gallery version
// is published as.
func (e remediationEntry) revisionLabel() string { return strconv.Itoa(e.Version) }

// playbookOS narrows the imported playbook to the entry's one platform,
// when it has only one, so it does not walk endpoints it can only skip.
func (e remediationEntry) playbookOS() string {
	if p := e.platforms(); len(p) == 1 {
		return p[0]
	}
	return ""
}

// remediationOrigin is the line an imported package and playbook carry in
// their description, so whoever opens one sees where it came from.
func remediationOrigin(id string) string {
	return "Imported from the mustra remediation gallery (" + id + ")."
}

// remediationItem is one gallery entry as GET /api/remediations lists it.
type remediationItem struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Version  int    `json:"version"`
	Category string `json:"category"`
	Summary  string `json:"summary"`
	// Risk is low, medium or high; RiskNote says what can go wrong.
	Risk           string                  `json:"risk"`
	RiskNote       string                  `json:"risk_note"`
	Platforms      []string                `json:"platforms"`
	Changes        map[string][]string     `json:"changes"`
	Parameters     []proto.DeployParameter `json:"parameters"`
	TimeoutSeconds int                     `json:"timeout_seconds"`
	// Scripts is the source each platform runs, so it can be read before
	// anything is imported.
	Scripts map[string]proto.DeployScript `json:"scripts"`
	// Imported is set once the entry has been imported.
	Imported *remediationImportState `json:"imported,omitempty"`
}

// remediationImportState is what became of an imported entry.
type remediationImportState struct {
	store.RemediationImport
	// UpdateAvailable: the gallery has a newer version than the one
	// imported, or the imported package has since been deleted.
	UpdateAvailable bool `json:"update_available"`
}

// remediationsResponse is what GET /api/remediations answers.
type remediationsResponse struct {
	Items []remediationItem `json:"items"`
}

func (s *Server) handleListRemediations(w http.ResponseWriter, r *http.Request) {
	all, err := remediationGallery()
	if err != nil {
		http.Error(w, "the remediation gallery could not be read: "+err.Error(), http.StatusInternalServerError)
		return
	}
	imports, err := s.store.ListRemediationImports(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	byID := map[string]store.RemediationImport{}
	for _, imp := range imports {
		byID[imp.GalleryID] = imp
	}
	out := remediationsResponse{Items: []remediationItem{}}
	for _, e := range all {
		item := remediationItem{ID: e.ID, Name: e.Name, Version: e.Version, Category: e.Category, Summary: e.Summary,
			Risk: e.Risk, RiskNote: e.RiskNote, Platforms: e.platforms(), Changes: e.Changes,
			Parameters: e.Parameters, TimeoutSeconds: e.TimeoutSeconds, Scripts: e.scripts}
		if item.Parameters == nil {
			item.Parameters = []proto.DeployParameter{}
		}
		if imp, ok := byID[e.ID]; ok {
			item.Imported = &remediationImportState{RemediationImport: imp,
				UpdateAvailable: imp.Version < e.Version || imp.PackageID == ""}
		}
		out.Items = append(out.Items, item)
	}
	writeJSONResponse(w, out)
}

// remediationImportRequest is the body of POST
// /api/remediations/{id}/import. Every field is optional.
type remediationImportRequest struct {
	// GroupID is the computer group the imported playbook targets. Empty
	// means every endpoint (narrowed, as always, by the caller's
	// management rights and any approval policy when it runs).
	GroupID string `json:"group_id"`
	// Params are the playbook step's inputs; required when the entry has
	// a required parameter, since a playbook runs without asking.
	Params map[string]string `json:"params"`
	// PackageOnly imports or updates the action package and creates no
	// playbook: what the gallery's Run does before opening the deploy
	// window, which asks for targets and inputs itself.
	PackageOnly bool `json:"package_only"`
}

// remediationImportResponse is what POST /api/remediations/{id}/import
// answers.
type remediationImportResponse struct {
	// Status: imported (something was created), updated (a newer gallery
	// version was published to the existing package) or unchanged.
	Status     string `json:"status"`
	Version    int    `json:"version"`
	PackageID  string `json:"package_id"`
	RevisionID string `json:"revision_id"`
	PlaybookID string `json:"playbook_id,omitempty"`
}

// errRemediationInput is a request the caller can fix.
type errRemediationInput struct{ error }

// handleImportRemediation copies a gallery entry into the operator's
// packages and playbooks. It is idempotent: importing again creates only
// what is missing (the package or playbook was deleted), publishes a newer
// gallery version to the existing package when there is one, and otherwise
// changes nothing. It never deploys anything.
func (s *Server) handleImportRemediation(w http.ResponseWriter, r *http.Request) {
	entry, err := findRemediation(r.PathValue("id"))
	if err != nil {
		http.Error(w, "the remediation gallery could not be read: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if entry == nil {
		http.Error(w, "no such remediation", http.StatusNotFound)
		return
	}
	var req remediationImportRequest
	if r.ContentLength != 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
			http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	var resp remediationImportResponse
	err = s.store.WithAdvisoryLock(r.Context(), "remediation-import:"+entry.ID, func() error {
		var e error
		resp, e = s.importRemediation(r, *entry, req)
		return e
	})
	var bad errRemediationInput
	switch {
	case errors.As(err, &bad):
		http.Error(w, bad.Error(), http.StatusBadRequest)
		return
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, resp)
}

func (s *Server) importRemediation(r *http.Request, e remediationEntry, req remediationImportRequest) (remediationImportResponse, error) {
	ctx := r.Context()
	who := auth.CurrentUser(ctx).Username
	resp := remediationImportResponse{Status: "unchanged", Version: e.Version}

	rec, err := s.store.GetRemediationImport(ctx, e.ID)
	if err != nil {
		return resp, err
	}
	if rec == nil {
		rec = &store.RemediationImport{GalleryID: e.ID, ImportedBy: who}
	}
	var pkg *store.SoftwarePackage
	if rec.PackageID != "" {
		if pkg, err = s.store.GetSoftwarePackage(ctx, rec.PackageID); err != nil {
			return resp, err
		}
	}
	var pb *store.Playbook
	if rec.PlaybookID != "" {
		if pb, err = s.store.GetPlaybook(ctx, rec.PlaybookID); err != nil {
			return resp, err
		}
	}
	createPlaybook := pb == nil && !req.PackageOnly

	// Everything the caller supplied is checked before anything is
	// written, so a bad request leaves no half-imported package behind.
	def := e.definition()
	if err := deploy.ValidateDefinition(def, true); err != nil {
		return resp, fmt.Errorf("gallery entry does not validate: %w", err)
	}
	if createPlaybook {
		if req.GroupID != "" {
			if g, err := s.store.GetComputerGroup(ctx, req.GroupID); err != nil || g == nil {
				return resp, errRemediationInput{errors.New("no such computer group")}
			}
		}
		if err := validateRevisionInputs(def, "run", e.playbookOS(), req.Params); err != nil {
			return resp, errRemediationInput{fmt.Errorf("%s: %w", e.Name, err)}
		}
	}

	audit := map[string]any{"remediation": e.ID, "version": e.Version}
	switch {
	case pkg == nil:
		pkg, err = s.store.UpsertSoftwarePackage(ctx, store.SoftwarePackage{
			ID: idgen.New("sw-"), Name: e.Name, Vendor: "mustra", Category: "Remediation", Kind: store.KindAction,
			Description: e.Summary + " " + remediationOrigin(e.ID), Commands: map[string]store.SoftwareOps{},
			// One click must not mean the whole fleet: a run names its
			// endpoints or groups.
			RequireExplicitTargets: true, Enabled: true, CreatedBy: who, UpdatedBy: who,
		})
		if err != nil {
			return resp, err
		}
		if resp.RevisionID, err = s.publishRemediation(r, e, pkg.ID, def, who); err != nil {
			// Nothing refers to the new package yet; leaving it would make
			// the next attempt create a second one.
			_ = s.store.DeleteSoftwarePackage(ctx, pkg.ID)
			return resp, err
		}
		resp.Status = "imported"
		audit["package_id"] = pkg.ID
	case rec.Version < e.Version:
		if resp.RevisionID, err = s.publishRemediation(r, e, pkg.ID, def, who); err != nil {
			return resp, err
		}
		resp.Status = "updated"
		audit["package_id"], audit["from_version"] = pkg.ID, rec.Version
	default:
		resp.RevisionID = pkg.DeployRevision
	}
	rec.PackageID = pkg.ID
	if resp.Status != "unchanged" {
		rec.Version = e.Version
	}

	if createPlaybook {
		// Following the latest version, so a gallery update published to
		// the package is what the playbook runs next time.
		steps, err := s.validatePlaybookSteps(r, []playbookStep{{
			Kind: "package", Name: e.Name, PackageID: pkg.ID, FollowLatest: true, Operation: "run",
			Params: req.Params, RunIf: "always", OnFailure: "stop",
		}}, e.playbookOS())
		if err != nil {
			return resp, errRemediationInput{err}
		}
		encoded, err := json.Marshal(steps)
		if err != nil {
			return resp, err
		}
		id := idgen.New("pb-")
		if err := s.store.UpsertPlaybook(ctx, store.Playbook{
			ID: id, Name: e.Name, Description: e.Summary + " " + remediationOrigin(e.ID), OS: e.playbookOS(),
			GroupID: req.GroupID, Steps: encoded, Enabled: true, UpdatedBy: who,
		}, nil); err != nil {
			return resp, err
		}
		rec.PlaybookID = id
		if resp.Status == "unchanged" {
			resp.Status = "imported"
		}
		audit["playbook_id"], audit["group"] = id, req.GroupID
	}
	resp.PackageID, resp.PlaybookID = rec.PackageID, rec.PlaybookID
	if resp.Status == "unchanged" {
		return resp, nil
	}
	if err := s.store.SaveRemediationImport(ctx, *rec); err != nil {
		return resp, err
	}
	s.audit(ctx, auditEvent{Action: "remediation." + map[string]string{"imported": "import", "updated": "update"}[resp.Status],
		Actor: who, Target: e.Name, Severity: "notice", Detail: audit})
	return resp, nil
}

// publishRemediation adds the entry's definition to the package as a new
// version and publishes it, through the same checks the editor's Publish
// applies.
func (s *Server) publishRemediation(r *http.Request, e remediationEntry, packageID string, def proto.DeployDefinition, who string) (string, error) {
	ctx := r.Context()
	rev, err := s.store.SaveDeployDraft(ctx, proto.DeployRevision{ID: idgen.New("rev-"), PackageID: packageID,
		Label: e.revisionLabel(), Definition: def, CreatedBy: who})
	if err != nil {
		return "", err
	}
	if err := s.snapshotDeployChecks(ctx, &rev.Definition); err != nil {
		return "", err
	}
	if err := s.store.PublishDeployRevision(ctx, *rev); err != nil {
		// Most likely somebody published their own version with this
		// label on the imported package.
		_, _, _ = s.store.DeleteDeployDraft(ctx, rev.ID)
		return "", fmt.Errorf("publishing gallery version %s of %s: %w", rev.Label, e.Name, err)
	}
	s.audit(ctx, auditEvent{Action: "deploy.publish", Actor: who, Target: packageID, Severity: "notice",
		Detail: map[string]any{"revision": rev.ID, "remediation": e.ID}})
	return rev.ID, nil
}
