package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// The console's side of OS provisioning: settings and the image catalog
// (settings.manage), machines and installs (deploy.manage). Reimaging an
// existing endpoint is provisioning_reimage.go.

// provisioningSettingsResponse is what GET and PUT /api/provisioning/settings
// answer.
type provisioningSettingsResponse struct {
	Config provisioningConfig `json:"config"`
	// BootListener is "console" when the boot endpoints share the
	// console's listener, or the separate address they listen on.
	BootListener string `json:"boot_listener"`
	// PublicURLSet says whether the console's public URL, which the
	// installed systems enroll against, is configured.
	PublicURLSet bool `json:"public_url_set"`
	// ChainScript is the iPXE script to embed in (or chain from) the iPXE
	// binary DHCP hands out, so it asks this server for its script.
	ChainScript string `json:"chain_script"`
}

func (s *Server) provisioningSettingsResponse(r *http.Request, c provisioningConfig) provisioningSettingsResponse {
	out := provisioningSettingsResponse{Config: c, BootListener: "console"}
	if s.cfg.BootHTTPAddr != "" {
		out.BootListener = s.cfg.BootHTTPAddr
	}
	if u, err := s.agentPublicURLOrEmpty(r.Context()); err == nil && u != "" {
		out.PublicURLSet = true
	}
	base := c.BootURL
	if base == "" {
		base = "http://<boot-url>"
	}
	// For an iPXE build with this script embedded, or a DHCP server that
	// can hand iPXE a script; one that can only hand out a URL gives
	// base/boot/ipxe, which answers with the same chain.
	out.ChainScript = "#!ipxe\ndhcp\nchain " + base + "/boot/ipxe?mac=${netX/mac} || exit\n"
	return out
}

// GET /api/provisioning/settings
func (s *Server) handleGetProvisioningSettings(w http.ResponseWriter, r *http.Request) {
	c, err := s.provisioningConfig(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, s.provisioningSettingsResponse(r, c))
}

// PUT /api/provisioning/settings
func (s *Server) handlePutProvisioningSettings(w http.ResponseWriter, r *http.Request) {
	var c provisioningConfig
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	c.applyDefaults()
	if c.BootURL != "" {
		u, err := normalizeBootURL(c.BootURL)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		c.BootURL = u
	}
	if err := c.validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	raw, _ := json.Marshal(c)
	who := auth.CurrentUser(r.Context()).Username
	if err := s.store.SetSetting(r.Context(), settingProvisioning, string(raw), who); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "provisioning.settings", Actor: who, Target: "OS provisioning", Severity: "notice",
		Detail: map[string]any{"enabled": c.Enabled, "boot_url": c.BootURL, "allowed_networks": c.AllowedNetworks}})
	writeJSONResponse(w, s.provisioningSettingsResponse(r, c))
}

// --- images ------------------------------------------------------------------

// provisioningImageRow is an image as the console lists it.
type provisioningImageRow struct {
	store.ProvisioningImage
	// Missing says what the image lacks before a machine can boot it, or
	// is empty when it is ready.
	Missing string `json:"missing"`
}

// listProvisioningImagesResponse is what GET /api/provisioning/images
// answers.
type listProvisioningImagesResponse struct {
	Images []provisioningImageRow `json:"images"`
	// Roles are the boot files each family needs.
	Roles map[string][]string `json:"roles"`
	// DefaultTemplates are the built-in answer templates, by family.
	DefaultTemplates map[string]string `json:"default_templates"`
	// Variables are the answer variables machines and images may set.
	Variables []string `json:"variables"`
}

// GET /api/provisioning/images
func (s *Server) handleListProvisioningImages(w http.ResponseWriter, r *http.Request) {
	images, err := s.store.ListProvisioningImages(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rows := make([]provisioningImageRow, 0, len(images))
	for i := range images {
		rows = append(rows, provisioningImageRow{images[i], imageReady(&images[i])})
	}
	writeJSONResponse(w, listProvisioningImagesResponse{Images: rows, Roles: provisioningAssetRoles,
		DefaultTemplates: defaultAnswerTemplates, Variables: variableNames()})
}

// provisioningImageRequest is the body of POST and PUT
// /api/provisioning/images. Secrets are write-only: empty keeps the one
// stored, and the clear_ flags remove it.
type provisioningImageRequest struct {
	Name   string `json:"name" api:"required"`
	Family string `json:"family" api:"required"` // ubuntu | debian | windows
	// Assets are the boot files by role, each {"url": ...}; an uploaded
	// file is kept by naming its {"file_id": ...}, and a role left out is
	// removed.
	Assets              map[string]store.ProvisioningAsset `json:"assets"`
	InstallSource       string                             `json:"install_source"`
	SourceUser          string                             `json:"source_user"`
	SourcePassword      string                             `json:"source_password" api:"writeonly"`
	ClearSourcePassword bool                               `json:"clear_source_password"`
	KernelArgs          string                             `json:"kernel_args"`
	Defaults            map[string]string                  `json:"defaults"`
	AdminPassword       string                             `json:"admin_password" api:"writeonly"`
	ClearAdminPassword  bool                               `json:"clear_admin_password"`
	// AnswerTemplate replaces the family's built-in answer file; empty
	// uses the built-in one.
	AnswerTemplate string `json:"answer_template"`
}

// POST /api/provisioning/images and PUT /api/provisioning/images/{id}
func (s *Server) handleSaveProvisioningImage(w http.ResponseWriter, r *http.Request) {
	var req provisioningImageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Name) == "" || req.Family == "" {
		http.Error(w, "an image needs a name and a family", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	who := auth.CurrentUser(ctx).Username
	var existing *store.ProvisioningImage
	id := r.PathValue("id")
	if id != "" {
		var err error
		if existing, err = s.store.GetProvisioningImage(ctx, id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if existing == nil {
			http.Error(w, "no such image", http.StatusNotFound)
			return
		}
	} else {
		id = idgen.New("pim-")
	}
	im := store.ProvisioningImage{
		ID: id, Name: req.Name, Family: req.Family, Assets: map[string]store.ProvisioningAsset{},
		InstallSource: req.InstallSource, SourceUser: strings.TrimSpace(req.SourceUser), KernelArgs: strings.TrimSpace(req.KernelArgs),
		Defaults: req.Defaults, AnswerTemplate: req.AnswerTemplate, CreatedBy: who,
	}
	if strings.TrimSpace(im.AnswerTemplate) == "" {
		im.AnswerTemplate = ""
	}
	// Uploaded files are kept only by naming the file the role already has.
	var dropped []string
	for role, a := range req.Assets {
		switch {
		case a.FileID != "":
			if existing == nil || existing.Assets[role].FileID != a.FileID {
				http.Error(w, "the "+role+" file "+a.FileID+" is not this image's; upload it to the image instead", http.StatusBadRequest)
				return
			}
			im.Assets[role] = existing.Assets[role]
		case strings.TrimSpace(a.URL) != "":
			im.Assets[role] = store.ProvisioningAsset{URL: strings.TrimSpace(a.URL)}
		}
	}
	if existing != nil {
		for role, a := range existing.Assets {
			if a.FileID != "" && im.Assets[role].FileID != a.FileID {
				dropped = append(dropped, a.FileID)
			}
		}
		im.SourceSecret, im.AdminSecret = existing.SourceSecret, existing.AdminSecret
	}
	if err := validateImage(&im); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if im.Family != "windows" {
		im.SourceSecret = nil
	}
	switch {
	case req.ClearSourcePassword:
		im.SourceSecret = nil
	case req.SourcePassword != "":
		if im.Family != "windows" {
			http.Error(w, "a share password applies to Windows images only", http.StatusBadRequest)
			return
		}
		if err := validShareSecret(req.SourcePassword); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		sealed, err := s.sealProvisioningSecret(req.SourcePassword, "image-source", im.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		im.SourceSecret = sealed
	}
	switch {
	case req.ClearAdminPassword:
		im.AdminSecret = nil
	case req.AdminPassword != "":
		if err := validAdminPassword(req.AdminPassword); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		sealed, err := s.sealProvisioningSecret(req.AdminPassword, "image-admin", im.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		im.AdminSecret = sealed
	}
	saved, err := s.store.SaveProvisioningImage(ctx, im)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, f := range dropped {
		removeProvisioningFile(f)
	}
	action := "provisioning.image.update"
	if existing == nil {
		action = "provisioning.image.create"
	}
	s.audit(ctx, auditEvent{Action: action, Actor: who, Target: saved.Name, Severity: "notice",
		Detail: map[string]any{"id": saved.ID, "family": saved.Family, "custom_template": saved.AnswerTemplate != ""}})
	writeJSONResponse(w, provisioningImageRow{*saved, imageReady(saved)})
}

// DELETE /api/provisioning/images/{id}
func (s *Server) handleDeleteProvisioningImage(w http.ResponseWriter, r *http.Request) {
	im, err := s.store.DeleteProvisioningImage(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if im == nil {
		http.Error(w, "no such image", http.StatusNotFound)
		return
	}
	for _, a := range im.Assets {
		if a.FileID != "" {
			removeProvisioningFile(a.FileID)
		}
	}
	s.audit(r.Context(), auditEvent{Action: "provisioning.image.delete", Actor: auth.CurrentUser(r.Context()).Username,
		Target: im.Name, Severity: "notice", Detail: map[string]any{"id": im.ID}})
	w.WriteHeader(http.StatusNoContent)
}

func removeProvisioningFile(id string) {
	if p, err := provisioningFilePath(id); err == nil {
		_ = os.Remove(p)
	}
}

// POST /api/provisioning/images/{id}/files: upload one boot file (multipart
// "role" and "file"). Boot files are served without authentication to
// anything that network-boots, so they must not contain anything secret.
func (s *Server) handleUploadProvisioningFile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	im, err := s.store.GetProvisioningImage(ctx, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if im == nil {
		http.Error(w, "no such image", http.StatusNotFound)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxPackageFileBytes+1<<20)
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "expected a multipart upload with \"role\" and \"file\"", http.StatusBadRequest)
		return
	}
	role := ""
	var rec store.ProvisioningAsset
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			http.Error(w, "upload interrupted: "+err.Error(), http.StatusBadRequest)
			return
		}
		switch part.FormName() {
		case "role":
			b, _ := io.ReadAll(io.LimitReader(part, 64))
			role = strings.TrimSpace(string(b))
		case "file":
			// The role comes first so a wrong one is refused before
			// gigabytes are written.
			if !containsString(provisioningAssetRoles[im.Family], role) {
				http.Error(w, "send \"role\" before \"file\": one of "+strings.Join(provisioningAssetRoles[im.Family], ", "), http.StatusBadRequest)
				return
			}
			rec, err = storeProvisioningFile(part)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		part.Close()
	}
	if rec.FileID == "" {
		http.Error(w, "no file was uploaded", http.StatusBadRequest)
		return
	}
	old := im.Assets[role].FileID
	im.Assets[role] = rec
	saved, err := s.store.SaveProvisioningImage(ctx, *im)
	if err != nil {
		removeProvisioningFile(rec.FileID)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if old != "" {
		removeProvisioningFile(old)
	}
	s.audit(ctx, auditEvent{Action: "provisioning.image.file", Actor: auth.CurrentUser(ctx).Username, Target: im.Name, Severity: "notice",
		Detail: map[string]any{"role": role, "file": rec.Name, "bytes": rec.SizeBytes, "sha256": rec.SHA256}})
	writeJSONResponse(w, provisioningImageRow{*saved, imageReady(saved)})
}

func storeProvisioningFile(part interface {
	io.Reader
	FileName() string
}) (store.ProvisioningAsset, error) {
	if err := os.MkdirAll(provisioningFileDir(), 0o750); err != nil {
		return store.ProvisioningAsset{}, errors.New("could not prepare storage: " + err.Error())
	}
	id := idgen.New("pbf-")
	dst, err := provisioningFilePath(id)
	if err != nil {
		return store.ProvisioningAsset{}, err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return store.ProvisioningAsset{}, errors.New("could not store the file: " + err.Error())
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), part)
	closeErr := out.Close()
	if err != nil || closeErr != nil {
		os.Remove(dst)
		return store.ProvisioningAsset{}, errors.New("could not store the file")
	}
	name := filepath.Base(strings.ReplaceAll(part.FileName(), "\\", "/"))
	return store.ProvisioningAsset{FileID: id, Name: name, SizeBytes: n, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

// --- machines ------------------------------------------------------------------

// provisioningMachineRow is a machine as the console lists it.
type provisioningMachineRow struct {
	store.ProvisioningMachine
	ImageName string `json:"image_name"`
	// Armed is install_next_boot that has not expired.
	Armed bool `json:"armed"`
	// Hostname is the endpoint the machine was reimaged from, if any.
	Hostname string `json:"hostname,omitempty"`
}

// listProvisioningMachinesResponse is what GET /api/provisioning/machines
// answers.
type listProvisioningMachinesResponse struct {
	Machines []provisioningMachineRow `json:"machines"`
}

// GET /api/provisioning/machines
func (s *Server) handleListProvisioningMachines(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	machines, err := s.store.ListProvisioningMachines(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	images, err := s.store.ListProvisioningImages(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	names := map[string]string{}
	for _, im := range images {
		names[im.ID] = im.Name
	}
	now := time.Now()
	rows := make([]provisioningMachineRow, 0, len(machines))
	for _, m := range machines {
		row := provisioningMachineRow{ProvisioningMachine: m, ImageName: names[m.ImageID], Armed: m.Armed(now)}
		if m.AgentID != "" {
			row.Hostname, _ = s.store.GetAgentHostname(ctx, m.AgentID)
		}
		rows = append(rows, row)
	}
	writeJSONResponse(w, listProvisioningMachinesResponse{Machines: rows})
}

// provisioningMachineRequest is the body of POST and PUT
// /api/provisioning/machines.
type provisioningMachineRequest struct {
	MAC       string            `json:"mac" api:"required"`
	Name      string            `json:"name"`
	ImageID   string            `json:"image_id"`
	Variables map[string]string `json:"variables"`
	// AdminPassword is write-only: empty keeps the stored one, and
	// ClearAdminPassword removes it (the image's then applies).
	AdminPassword      string `json:"admin_password" api:"writeonly"`
	ClearAdminPassword bool   `json:"clear_admin_password"`
}

// POST /api/provisioning/machines and PUT /api/provisioning/machines/{id}
func (s *Server) handleSaveProvisioningMachine(w http.ResponseWriter, r *http.Request) {
	var req provisioningMachineRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	who := auth.CurrentUser(ctx).Username
	mac := normalizeMAC(req.MAC)
	if mac == "" {
		http.Error(w, "mac must be a MAC address such as 52:54:00:12:34:56", http.StatusBadRequest)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if len(req.Name) > 120 {
		http.Error(w, "the name is too long", http.StatusBadRequest)
		return
	}
	vars, err := validateVariables(req.Variables)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.ImageID != "" {
		im, err := s.store.GetProvisioningImage(ctx, req.ImageID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if im == nil {
			http.Error(w, "no such image", http.StatusBadRequest)
			return
		}
	}
	m := store.ProvisioningMachine{ID: r.PathValue("id"), MAC: mac, Name: req.Name, ImageID: req.ImageID, Variables: vars, CreatedBy: who}
	var existing *store.ProvisioningMachine
	if m.ID != "" {
		if existing, err = s.store.GetProvisioningMachine(ctx, m.ID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if existing == nil {
			http.Error(w, "no such machine", http.StatusNotFound)
			return
		}
		m.AdminSecret, m.AgentID = existing.AdminSecret, existing.AgentID
		// Changing what an armed machine would install is a new decision:
		// it has to be armed again, so nobody arms one image and gets
		// another.
		if existing.Armed(time.Now()) && (existing.ImageID != m.ImageID || existing.MAC != m.MAC) {
			http.Error(w, "disarm the machine before changing its image or MAC", http.StatusConflict)
			return
		}
	} else {
		m.ID = idgen.New("pmc-")
	}
	switch {
	case req.ClearAdminPassword:
		m.AdminSecret = nil
	case req.AdminPassword != "":
		if err := validAdminPassword(req.AdminPassword); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if m.AdminSecret, err = s.sealProvisioningSecret(req.AdminPassword, "machine-admin", m.ID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	saved, err := s.store.SaveProvisioningMachine(ctx, m)
	if errors.Is(err, store.ErrMACTaken) {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	action := "provisioning.machine.update"
	if existing == nil {
		action = "provisioning.machine.create"
	}
	s.audit(ctx, auditEvent{Action: action, Actor: who, Target: firstNonEmptyString(saved.Name, saved.MAC), Severity: "notice",
		Detail: map[string]any{"id": saved.ID, "mac": saved.MAC, "image": saved.ImageID}})
	writeJSONResponse(w, provisioningMachineRow{ProvisioningMachine: *saved, Armed: saved.Armed(time.Now())})
}

// DELETE /api/provisioning/machines/{id}
func (s *Server) handleDeleteProvisioningMachine(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	m, err := s.store.DeleteProvisioningMachine(ctx, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if m == nil {
		http.Error(w, "no such machine", http.StatusNotFound)
		return
	}
	_ = s.store.CancelPendingProvisioningInstalls(ctx, m.ID, "withdrawn: the machine was deleted")
	s.audit(ctx, auditEvent{Action: "provisioning.machine.delete", Actor: auth.CurrentUser(ctx).Username,
		Target: firstNonEmptyString(m.Name, m.MAC), Severity: "notice", Detail: map[string]any{"id": m.ID, "mac": m.MAC}})
	w.WriteHeader(http.StatusNoContent)
}

// armProvisioningRequest is the body of POST
// /api/provisioning/machines/{id}/arm.
type armProvisioningRequest struct {
	InstallNextBoot bool `json:"install_next_boot"`
}

// POST /api/provisioning/machines/{id}/arm: set or clear "install next
// boot" for a machine that is not a managed endpoint. A MAC an endpoint
// reports is refused here: wiping an endpoint is a reimage, which needs
// its hostname typed and a second person's approval.
func (s *Server) handleArmProvisioningMachine(w http.ResponseWriter, r *http.Request) {
	var req armProvisioningRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	who := auth.CurrentUser(ctx).Username
	m, err := s.store.GetProvisioningMachine(ctx, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if m == nil {
		http.Error(w, "no such machine", http.StatusNotFound)
		return
	}
	if !req.InstallNextBoot {
		out, err := s.store.SetProvisioningArmed(ctx, m.ID, false, who, time.Time{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.audit(ctx, auditEvent{Action: "provisioning.machine.disarm", Actor: who, Target: firstNonEmptyString(m.Name, m.MAC), Severity: "notice",
			Detail: map[string]any{"mac": m.MAC}})
		writeJSONResponse(w, provisioningMachineRow{ProvisioningMachine: *out})
		return
	}
	cfg, err := s.provisioningConfig(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !cfg.Enabled {
		http.Error(w, "OS provisioning is turned off (Provisioning → Settings)", http.StatusConflict)
		return
	}
	owner, err := s.endpointWithMAC(ctx, m.MAC)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if owner != "" {
		host, _ := s.store.GetAgentHostname(ctx, owner)
		s.audit(ctx, auditEvent{Action: "provisioning.machine.arm", Actor: who, Target: firstNonEmptyString(host, owner), AgentID: owner,
			Outcome: "denied", Severity: "warning", Detail: map[string]any{"mac": m.MAC, "reason": "MAC belongs to a managed endpoint"}})
		http.Error(w, "the managed endpoint "+firstNonEmptyString(host, owner)+" reports this MAC address: reimage it instead (Provisioning → Reimage), which asks for its hostname and a second person's approval", http.StatusConflict)
		return
	}
	if err := s.checkMachineInstallable(ctx, m); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	until := time.Now().Add(time.Duration(cfg.ArmHours) * time.Hour)
	out, err := s.store.SetProvisioningArmed(ctx, m.ID, true, who, until)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(ctx, auditEvent{Action: "provisioning.machine.arm", Actor: who, Target: firstNonEmptyString(m.Name, m.MAC), Severity: "warning",
		Detail: map[string]any{"mac": m.MAC, "image": m.ImageID, "until": until}})
	writeJSONResponse(w, provisioningMachineRow{ProvisioningMachine: *out, Armed: true})
}

// checkMachineInstallable refuses to arm a machine whose next boot would
// fail: no image, an image missing boot files, or no way to sign in.
func (s *Server) checkMachineInstallable(ctx context.Context, m *store.ProvisioningMachine) error {
	if m.ImageID == "" {
		return errors.New("assign an image first")
	}
	im, err := s.store.GetProvisioningImage(ctx, m.ImageID)
	if err != nil {
		return err
	}
	if im == nil {
		return errors.New("the machine's image no longer exists")
	}
	if why := imageReady(im); why != "" {
		return errors.New("the image is not ready: " + why)
	}
	vars, err := validateVariables(mergedVariables(im, m))
	if err != nil {
		return err
	}
	hasPassword := len(m.AdminSecret) > 0 || len(im.AdminSecret) > 0
	switch im.Family {
	case "windows":
		if !hasPassword {
			return errors.New("a Windows install needs an administrator password, on the machine or the image")
		}
		if h := hostnameFor(vars, m); len(h) > 15 {
			return errors.New("a Windows computer name is at most 15 characters; set the hostname variable")
		}
	default:
		if !hasPassword && vars["ssh_key"] == "" {
			return errors.New("a Linux install needs an administrator password or an ssh_key variable")
		}
	}
	return nil
}

// endpointWithMAC returns the managed endpoint whose network sensor
// reports mac, or "".
func (s *Server) endpointWithMAC(ctx context.Context, mac string) (string, error) {
	rows, err := s.store.ListSensorDataForSensor(ctx, "network")
	if err != nil {
		return "", err
	}
	for _, row := range rows {
		for _, m := range macsInNetworkSnapshot(row.Data) {
			if m == mac {
				return row.AgentID, nil
			}
		}
	}
	return "", nil
}

// --- installs ------------------------------------------------------------------

// provisioningInstallRow is one install as the console lists it.
type provisioningInstallRow struct {
	store.ProvisioningInstall
	// State is Status with time applied: a script whose answer file was
	// never fetched in time is "expired", and an install whose agent has
	// enrolled is "enrolled".
	State string `json:"state"`
	// EnrolledHostname is the new agent's hostname, once it enrolled.
	EnrolledHostname string `json:"enrolled_hostname,omitempty"`
}

// listProvisioningInstallsResponse is what GET /api/provisioning/installs
// answers.
type listProvisioningInstallsResponse struct {
	Installs []provisioningInstallRow `json:"installs"`
}

func installState(in store.ProvisioningInstall, now time.Time) string {
	switch {
	case in.AgentID != "":
		return "enrolled"
	case in.Status == "script_served" && now.After(in.AnswerExpiresAt):
		return "expired"
	}
	return in.Status
}

// GET /api/provisioning/installs
func (s *Server) handleListProvisioningInstalls(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	installs, err := s.store.ListProvisioningInstalls(ctx, 200)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	now := time.Now()
	rows := make([]provisioningInstallRow, 0, len(installs))
	for _, in := range installs {
		row := provisioningInstallRow{ProvisioningInstall: in, State: installState(in, now)}
		if in.AgentID != "" {
			row.EnrolledHostname, _ = s.store.GetAgentHostname(ctx, in.AgentID)
		}
		rows = append(rows, row)
	}
	writeJSONResponse(w, listProvisioningInstallsResponse{Installs: rows})
}
