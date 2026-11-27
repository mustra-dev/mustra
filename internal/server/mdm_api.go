package server

// Apple MDM in the console: enrolled devices, their command queues and
// history, the profile library, and the page. Reading devices is open to
// anyone who can see the fleet; sending a command is deploy.manage and
// goes through the endpoint-action gate (module "mdm") like every other
// act on an endpoint. Locking and erasing a Mac additionally always wait
// for a second person, whatever approval policies say (mdmParkForApproval).

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/mdm"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// mdmCommandRoute is the command route's pattern: the gate's key, and the
// handler an approved lock or erase is replayed through.
const mdmCommandRoute = "POST /api/mdm/devices/{id}/commands"

// mdmCommandMaxAge is how long a command may wait for its device.
const mdmCommandMaxAge = 30 * 24 * time.Hour

// mdmEnqueue builds, stores and pushes one command. A command that needs
// a PIN gets a fresh one, sealed with its payload.
func (s *Server) mdmEnqueue(ctx context.Context, dev *store.MDMDevice, requestType string, p mdm.CommandParams, profileID, requestedBy, approvalID string) (*store.MDMCommand, error) {
	info, ok := mdm.LookupCommand(requestType)
	if !ok {
		return nil, errors.New("unsupported command " + requestType)
	}
	uuid := mdm.NewCommandUUID()
	pin := ""
	if info.NeedsPIN {
		var err error
		if pin, err = mdm.NewPIN(); err != nil {
			return nil, err
		}
	}
	payload, err := mdm.BuildCommand(uuid, requestType, p, pin)
	if err != nil {
		return nil, err
	}
	params, _ := json.Marshal(p)
	c := store.MDMCommand{UUID: uuid, UDID: dev.UDID, RequestType: requestType, Params: params, ProfileID: profileID,
		Payload: payload, RequestedBy: requestedBy, ApprovalID: approvalID}
	if pin != "" {
		sealedPayload, err := s.mdmSeal(mdmPayloadAAD(uuid), string(payload))
		if err != nil {
			return nil, err
		}
		if c.PINSealed, err = s.mdmSeal(mdmPINAAD(uuid), pin); err != nil {
			return nil, err
		}
		c.Payload, c.PayloadSealed = []byte(sealedPayload), true
	}
	if err := s.store.EnqueueMDMCommand(ctx, c); err != nil {
		return nil, err
	}
	c.HasPIN = pin != ""
	c.State = mdm.StateQueued
	c.CreatedAt = time.Now()
	c.Payload = nil
	return &c, nil
}

// mdmPush wakes a device so it fetches its queue.
func (s *Server) mdmPush(ctx context.Context, udid string) {
	cfg := s.mdmActiveConfig(ctx)
	if cfg == nil {
		return
	}
	dev, err := s.store.GetMDMDevice(ctx, udid)
	if err != nil || dev == nil || !dev.Enrolled || !dev.HasPushToken {
		return
	}
	p, err := s.mdmPusher(cfg)
	if err != nil {
		_ = s.store.SetMDMPushResult(ctx, udid, err.Error())
		return
	}
	pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, err = p.Push(pctx, dev.PushToken, dev.PushMagic)
	msg := ""
	if err != nil {
		msg = err.Error()
		s.logger.Warn("apple mdm: push failed", "udid", udid, "error", err)
	}
	_ = s.store.SetMDMPushResult(ctx, udid, msg)
}

// mdmLoop retires commands that waited too long, pushes devices whose
// commands still wait, and keeps device-to-endpoint links current.
func (s *Server) mdmLoop(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if s.mdmActiveConfig(ctx) == nil {
			continue
		}
		if n, err := s.store.ExpireMDMCommands(ctx, mdmCommandMaxAge); err == nil && n > 0 {
			s.logger.Info("apple mdm: commands expired unanswered", "count", n)
		}
		// A device that missed its push (asleep, offline) is pushed again,
		// at most every four hours, while something waits for it.
		if udids, err := s.store.MDMDevicesToPush(ctx, time.Now().Add(-4*time.Hour)); err == nil {
			for _, u := range udids {
				s.mdmPush(ctx, u)
			}
		}
		if devs, err := s.store.ListMDMDevices(ctx, ""); err == nil {
			bySerial := s.mdmAgentsBySerial(ctx)
			for _, d := range devs {
				if want := bySerial[strings.ToUpper(d.SerialNumber)]; want != d.AgentID {
					_ = s.store.SetMDMDeviceAgent(ctx, d.UDID, want)
				}
			}
		}
	}
}

// --- devices ----------------------------------------------------------------

// mdmDevicesResponse is what GET /api/mdm/devices answers.
type mdmDevicesResponse struct {
	Devices []store.MDMDevice `json:"devices"`
	// Active says whether the MDM is on and complete.
	Active bool `json:"active"`
}

// GET /api/mdm/devices
func (s *Server) handleListMDMDevices(w http.ResponseWriter, r *http.Request) {
	devs, err := s.store.ListMDMDevices(r.Context(), r.URL.Query().Get("agent_id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, mdmDevicesResponse{Devices: devs, Active: s.mdmActiveConfig(r.Context()) != nil})
}

// mdmDeviceResponse is what GET /api/mdm/devices/{id} answers.
type mdmDeviceResponse struct {
	Device   store.MDMDevice    `json:"device"`
	Commands []store.MDMCommand `json:"commands"`
	// CommandTypes are the commands this server can send.
	CommandTypes []mdm.CommandInfo `json:"command_types"`
}

// GET /api/mdm/devices/{id}
func (s *Server) handleGetMDMDevice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	dev, err := s.store.GetMDMDevice(ctx, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if dev == nil {
		http.Error(w, "no such device", http.StatusNotFound)
		return
	}
	cmds, err := s.store.ListMDMCommands(ctx, dev.UDID, 200)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, mdmDeviceResponse{Device: *dev, Commands: cmds, CommandTypes: mdm.Commands})
}

// mdmCommandRequest is the body of POST /api/mdm/devices/{id}/commands.
type mdmCommandRequest struct {
	// RequestType is one of DeviceInformation, SecurityInfo,
	// InstalledApplicationList, ProfileList, InstallProfile, RemoveProfile,
	// RestartDevice, DeviceLock and EraseDevice.
	RequestType string `json:"request_type" api:"required"`
	// ProfileID names a library profile: the one InstallProfile installs,
	// or the one whose identifier RemoveProfile removes.
	ProfileID string `json:"profile_id,omitempty"`
	// Identifier is the PayloadIdentifier RemoveProfile removes, for a
	// profile not in the library.
	Identifier string `json:"identifier,omitempty"`
	// Message and PhoneNumber are shown on a locked Mac's screen.
	Message     string `json:"message,omitempty"`
	PhoneNumber string `json:"phone_number,omitempty"`
	// NotifyUser lets the person at the Mac postpone a restart (macOS 11.3+).
	NotifyUser bool `json:"notify_user,omitempty"`
	// Confirm must repeat the Mac's serial number for EraseDevice.
	Confirm string `json:"confirm,omitempty"`
}

// mdmCommandResponse is what POST /api/mdm/devices/{id}/commands answers
// when the command is queued.
type mdmCommandResponse struct {
	Command store.MDMCommand `json:"command"`
	Message string           `json:"message"`
}

// mdmParkedResponse is the 202 answer when a lock or erase waits for
// approval.
type mdmParkedResponse struct {
	ApprovalRequired bool      `json:"approval_required"`
	RequestID        string    `json:"request_id"`
	Policy           string    `json:"policy"`
	Summary          string    `json:"summary"`
	ExpiresAt        time.Time `json:"expires_at"`
	Message          string    `json:"message"`
}

// resolveMDMDevice is the gate's view of an MDM command: the endpoint the
// Mac is linked to. A Mac with no mustra agent belongs to no computer
// group, so somebody whose management rights are limited to groups may
// not act on it; only an unrestricted account may.
func resolveMDMDevice(s *Server, r *http.Request, _ []byte) (endpointAction, error) {
	udid := r.PathValue("id")
	dev, err := s.store.GetMDMDevice(r.Context(), udid)
	if err != nil {
		return endpointAction{}, err
	}
	if dev == nil {
		return endpointAction{}, httpError{http.StatusNotFound, "no such device"}
	}
	summary := "Apple MDM " + r.Method + " on " + mdmDeviceLabel(dev)
	if dev.AgentID != "" {
		return endpointAction{Explicit: []string{dev.AgentID}, Summary: summary}, nil
	}
	scope, err := s.endpointScope(r.Context())
	if err != nil {
		return endpointAction{}, err
	}
	if scope != nil {
		return endpointAction{}, httpError{http.StatusForbidden, "this Mac is not linked to a mustra endpoint, so it is in none of the computer groups your management rights cover"}
	}
	return endpointAction{Summary: summary}, nil
}

// POST /api/mdm/devices/{id}/commands
func (s *Server) handleMDMCommand(w http.ResponseWriter, r *http.Request) {
	var req mdmCommandRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.RequestType == "" {
		http.Error(w, "request_type is required", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	if s.mdmActiveConfig(ctx) == nil {
		http.Error(w, "Apple MDM is off", http.StatusConflict)
		return
	}
	dev, err := s.store.GetMDMDevice(ctx, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if dev == nil {
		http.Error(w, "no such device", http.StatusNotFound)
		return
	}
	if !dev.Enrolled {
		http.Error(w, "this Mac is not enrolled", http.StatusConflict)
		return
	}
	info, ok := mdm.LookupCommand(req.RequestType)
	if !ok {
		http.Error(w, "unsupported request_type", http.StatusBadRequest)
		return
	}
	p := mdm.CommandParams{Identifier: strings.TrimSpace(req.Identifier), Message: strings.TrimSpace(req.Message),
		PhoneNumber: strings.TrimSpace(req.PhoneNumber), NotifyUser: req.NotifyUser}
	profileName := ""
	if req.ProfileID != "" {
		if req.RequestType != mdm.CmdInstallProfile && req.RequestType != mdm.CmdRemoveProfile {
			http.Error(w, "only InstallProfile and RemoveProfile take a profile_id", http.StatusBadRequest)
			return
		}
		prof, err := s.store.GetMDMProfile(ctx, req.ProfileID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if prof == nil {
			http.Error(w, "no such profile in the library", http.StatusNotFound)
			return
		}
		profileName = prof.Name
		if req.RequestType == mdm.CmdInstallProfile {
			p.Profile = prof.Content
		} else if p.Identifier == "" {
			p.Identifier = prof.Identifier
		}
	}
	if err := p.Validate(req.RequestType); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.RequestType == mdm.CmdEraseDevice {
		// Typed confirmation: the erase names the Mac it is for.
		want := firstNonEmptyString(dev.SerialNumber, dev.UDID)
		if !strings.EqualFold(strings.TrimSpace(req.Confirm), want) {
			http.Error(w, "type the Mac's serial number ("+want+") in confirm to erase it", http.StatusBadRequest)
			return
		}
	}
	summary := info.Label + " on " + mdmDeviceLabel(dev)
	approvalID, approved := approvalGranted(ctx)
	if info.Destructive && !approved {
		s.mdmParkForApproval(w, r, dev, req, summary)
		return
	}
	u := auth.CurrentUser(ctx)
	// Recorded before anything is queued: a command that changes a Mac
	// and is missing from the audit log must not happen.
	if err := s.auditStrict(ctx, auditEvent{Action: "mdm.command", Actor: u.Username, Target: summary, AgentID: dev.AgentID,
		Severity: map[bool]string{true: "warning", false: "notice"}[info.Destructive],
		Detail: map[string]any{"udid": dev.UDID, "serial": dev.SerialNumber, "request_type": req.RequestType, "profile": profileName,
			"identifier": p.Identifier, "approval_id": approvalID}}); err != nil {
		http.Error(w, "the command could not be recorded in the audit log, so it was not sent", http.StatusServiceUnavailable)
		return
	}
	cmd, err := s.mdmEnqueue(ctx, dev, req.RequestType, p, req.ProfileID, u.Username, approvalID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	go s.mdmPush(context.WithoutCancel(ctx), dev.UDID)
	msg := "Queued; the Mac has been asked to check in."
	if cmd.HasPIN {
		msg += " Its PIN can be read on the device's page by someone with enforce.recovery_keys."
	}
	writeJSONResponse(w, mdmCommandResponse{Command: *cmd, Message: msg})
}

// mdmApprovalPolicyID names the built-in rule on approval requests: lock
// and erase always need a second person.
const mdmApprovalPolicyID = "builtin:mdm-destructive"

// mdmParkForApproval parks a lock or erase for a second person. It is the
// same approval request every gated operation makes (access.go), replayed
// through the same gate and permission check as the requester when
// approved; only the policy is fixed rather than configured. A token
// cannot wait for a decision, and not even an approval-exempt token is
// let past this one: erasing a Mac is not an automation.
func (s *Server) mdmParkForApproval(w http.ResponseWriter, r *http.Request, dev *store.MDMDevice, req mdmCommandRequest, summary string) {
	ctx := r.Context()
	u := auth.CurrentUser(ctx)
	if _, isToken := auth.Token(ctx); isToken || u.ID == auth.APITokenUserID {
		s.audit(ctx, auditEvent{Action: "mdm.denied", Actor: u.Username, Target: summary, AgentID: dev.AgentID, Outcome: "denied",
			Severity: "warning", Detail: map[string]any{"reason": "api token; lock and erase need a second person's approval"}})
		http.Error(w, "locking or erasing a Mac needs a second person's approval, which an API token cannot wait for; ask from the console", http.StatusForbidden)
		return
	}
	if _, ok := s.replayable()[mdmCommandRoute]; !ok {
		http.Error(w, "this operation cannot be parked for approval", http.StatusForbidden)
		return
	}
	body, err := json.Marshal(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	parked, _ := json.Marshal(parkedRequest{Handler: mdmCommandRoute, Body: body, PathValues: map[string]string{"id": dev.UDID}})
	var agents []string
	if dev.AgentID != "" {
		agents = []string{dev.AgentID}
	}
	expires := time.Now().Add(approvalWindow)
	ar := store.ApprovalRequest{ID: idgen.New("apr-"), PolicyID: mdmApprovalPolicyID, PolicyName: "Apple MDM: lock and erase",
		Module: "mdm", Summary: summary, Method: r.Method, Path: r.URL.Path, Body: parked, AgentIDs: agents, DeviceCount: 1,
		RequestedBy: u.Username, ExpiresAt: &expires}
	if err := s.store.CreateApprovalRequest(ctx, ar); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(ctx, auditEvent{Action: "mdm.approval_requested", Actor: u.Username, Target: summary, AgentID: dev.AgentID, Severity: "notice",
		Detail: map[string]any{"request_id": ar.ID, "udid": dev.UDID, "request_type": req.RequestType}})
	s.notifyRequest(ctx, "warning", "Approvals", u.Username+" is asking for approval: "+summary,
		"Apple MDM · 1 Mac · locking and erasing always need a second person", "/access#approvals", "approval", ar.ID, true)
	w.WriteHeader(http.StatusAccepted)
	writeJSONResponse(w, mdmParkedResponse{ApprovalRequired: true, RequestID: ar.ID, Policy: ar.PolicyName, Summary: summary,
		ExpiresAt: expires, Message: "Parked for approval. It is queued for the Mac once somebody with approvals.decide approves it."})
}

// mdmCancelResponse is what POST /api/mdm/devices/{id}/commands/{command}/cancel answers.
type mdmCancelResponse struct {
	Cancelled bool `json:"cancelled"`
}

// POST /api/mdm/devices/{id}/commands/{command}/cancel
func (s *Server) handleCancelMDMCommand(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ok, err := s.store.CancelMDMCommand(ctx, r.PathValue("id"), r.PathValue("command"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "that command is not waiting: it has been delivered, finished or does not exist", http.StatusConflict)
		return
	}
	s.audit(ctx, auditEvent{Action: "mdm.command_cancelled", Actor: auth.CurrentUser(ctx).Username, Target: r.PathValue("command"),
		Severity: "notice", Detail: map[string]any{"udid": r.PathValue("id")}})
	writeJSONResponse(w, mdmCancelResponse{Cancelled: true})
}

// mdmPINResponse is what POST /api/mdm/commands/{id}/reveal-pin answers.
type mdmPINResponse struct {
	Command     string `json:"command"`
	RequestType string `json:"request_type"`
	PIN         string `json:"pin"`
}

// POST /api/mdm/commands/{id}/reveal-pin
func (s *Server) handleRevealMDMPIN(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cmd, err := s.store.GetMDMCommand(ctx, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if cmd == nil || cmd.PINSealed == "" {
		http.Error(w, "no such command with a PIN", http.StatusNotFound)
		return
	}
	if s.vault == nil {
		http.Error(w, errMDMNoVault.Error(), http.StatusServiceUnavailable)
		return
	}
	pin, err := s.mdmOpen(mdmPINAAD(cmd.UUID), cmd.PINSealed)
	if err != nil {
		http.Error(w, "the PIN could not be decrypted with the current credential encryption key", http.StatusInternalServerError)
		return
	}
	dev, _ := s.store.GetMDMDevice(ctx, cmd.UDID)
	target, agentID := cmd.UDID, ""
	if dev != nil {
		target, agentID = mdmDeviceLabel(dev), dev.AgentID
	}
	s.audit(ctx, auditEvent{Action: "mdm.pin_view", Actor: auth.CurrentUser(ctx).Username, Target: target, AgentID: agentID, Severity: "warning",
		Detail: map[string]any{"command": cmd.UUID, "request_type": cmd.RequestType}})
	writeJSONResponse(w, mdmPINResponse{Command: cmd.UUID, RequestType: cmd.RequestType, PIN: pin})
}

// mdmDeleteResponse is what DELETE /api/mdm/devices/{id} answers.
type mdmDeleteResponse struct {
	Deleted bool `json:"deleted"`
}

// DELETE /api/mdm/devices/{id}
func (s *Server) handleDeleteMDMDevice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	dev, err := s.store.GetMDMDevice(ctx, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if dev == nil {
		http.Error(w, "no such device", http.StatusNotFound)
		return
	}
	if _, err := s.store.DeleteMDMDevice(ctx, dev.UDID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(ctx, auditEvent{Action: "mdm.device_deleted", Actor: auth.CurrentUser(ctx).Username, Target: mdmDeviceLabel(dev), AgentID: dev.AgentID,
		Severity: "warning", Detail: map[string]any{"udid": dev.UDID, "was_enrolled": dev.Enrolled}})
	writeJSONResponse(w, mdmDeleteResponse{Deleted: true})
}

// --- profile library --------------------------------------------------------

// mdmProfilesResponse is what GET /api/mdm/profiles answers.
type mdmProfilesResponse struct {
	Profiles []store.MDMProfile `json:"profiles"`
}

// GET /api/mdm/profiles
func (s *Server) handleListMDMProfiles(w http.ResponseWriter, r *http.Request) {
	ps, err := s.store.ListMDMProfiles(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, mdmProfilesResponse{Profiles: ps})
}

// mdmUploadProfileRequest is the body of POST /api/mdm/profiles.
type mdmUploadProfileRequest struct {
	// Name is the library's name for it; the profile's own display name
	// when empty.
	Name string `json:"name"`
	// Content is the .mobileconfig, signed or not, base64.
	Content string `json:"content" api:"required"`
}

// POST /api/mdm/profiles
func (s *Server) handleUploadMDMProfile(w http.ResponseWriter, r *http.Request) {
	var req mdmUploadProfileRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2*mdm.MaxProfileBytes)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Content) == "" {
		http.Error(w, "content is required", http.StatusBadRequest)
		return
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.Content))
	if err != nil {
		http.Error(w, "content is not base64", http.StatusBadRequest)
		return
	}
	info, err := mdm.ParseProfile(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(firstNonEmptyString(req.Name, info.DisplayName))
	if len(name) > 200 {
		http.Error(w, "the name is limited to 200 characters", http.StatusBadRequest)
		return
	}
	sum := sha256.Sum256(data)
	ctx := r.Context()
	p := store.MDMProfile{ID: newID("mdmp-"), Name: name, Identifier: info.Identifier, DisplayName: info.DisplayName,
		Description: info.Description, Organization: info.Organization, PayloadTypes: info.PayloadTypes, Signed: info.Signed,
		Content: data, SHA256: hex.EncodeToString(sum[:]), Size: len(data), CreatedBy: auth.CurrentUser(ctx).Username, CreatedAt: time.Now()}
	if err := s.store.CreateMDMProfile(ctx, p); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(ctx, auditEvent{Action: "mdm.profile_added", Actor: p.CreatedBy, Target: p.Name, Severity: "notice",
		Detail: map[string]any{"id": p.ID, "identifier": p.Identifier, "payload_types": p.PayloadTypes, "sha256": p.SHA256}})
	w.WriteHeader(http.StatusCreated)
	writeJSONResponse(w, p)
}

// GET /api/mdm/profiles/{id}/download
func (s *Server) handleDownloadMDMProfile(w http.ResponseWriter, r *http.Request) {
	p, err := s.store.GetMDMProfile(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if p == nil {
		http.Error(w, "no such profile", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", `attachment; filename="`+mdmSafeFilename(p.Identifier)+`.mobileconfig"`)
	_, _ = w.Write(p.Content)
}

func mdmSafeFilename(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '.' || r == '-' || r == '_' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			return r
		}
		return '_'
	}, s)
}

// DELETE /api/mdm/profiles/{id}
func (s *Server) handleDeleteMDMProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ok, err := s.store.DeleteMDMProfile(ctx, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "no such profile", http.StatusNotFound)
		return
	}
	s.audit(ctx, auditEvent{Action: "mdm.profile_deleted", Actor: auth.CurrentUser(ctx).Username, Target: r.PathValue("id"), Severity: "notice"})
	writeJSONResponse(w, mdmDeleteResponse{Deleted: true})
}

// mdmPageHandler serves the Apple MDM page.
func mdmPageHandler() http.Handler { return staticPageHandler("static/mdm.html") }
