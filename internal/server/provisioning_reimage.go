package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// Reimaging an existing endpoint: assign an image to its MAC, arm it, and
// ask the agent to boot from the network once.
//
// It erases the endpoint, so it is held to more than any other action:
//   - one endpoint, named in the URL; the body cannot name others (unknown
//     fields are refused, so agent_ids or group_ids cannot ride along);
//   - the operator types the endpoint's hostname;
//   - it always waits for a second person's approval: an approval policy
//     for the provisioning module applies if one matches, and when none
//     does a built-in one does. An API token cannot wait for approval, so
//     a token is refused, approval-exempt or not;
//   - it is audited before the endpoint is told anything.

const reimageHandlerKey = "POST /api/agents/{id}/reimage"

// builtinReimagePolicy is the approval policy a reimage waits under when no
// configured policy covers it.
var builtinReimagePolicy = store.ApprovalPolicy{ID: "builtin-reimage", Name: "Reimage (always needs a second person)", Module: "provisioning", Enabled: true}

// reimageRequest is the body of POST /api/agents/{id}/reimage.
type reimageRequest struct {
	ImageID string `json:"image_id" api:"required"`
	// MAC is the endpoint's network interface to boot from; it must be
	// one the endpoint reports.
	MAC string `json:"mac" api:"required"`
	// ConfirmHostname must be the endpoint's hostname, typed.
	ConfirmHostname string `json:"confirm_hostname" api:"required"`
	// Variables override the image's defaults for this machine. The
	// hostname defaults to the endpoint's.
	Variables map[string]string `json:"variables"`
	// Restart, default true, restarts the endpoint once its next boot is
	// set. False only sets it, for a restart at a time of somebody's
	// choosing.
	Restart *bool `json:"restart"`
}

// reimageResponse is what POST /api/agents/{id}/reimage answers once the
// approved request ran.
type reimageResponse struct {
	OK        bool   `json:"ok"`
	MachineID string `json:"machine_id"`
	RunID     string `json:"run_id"`
	// Method is how the endpoint was set to boot from the network:
	// "efibootmgr", "bcdedit", or "manual" when it could not be, with
	// Instructions.
	Method       string `json:"method"`
	Entry        string `json:"entry,omitempty"`
	Restarting   bool   `json:"restarting"`
	Instructions string `json:"instructions,omitempty"`
	Message      string `json:"message"`
}

// manualNetBootInstructions is the fallback when the agent cannot choose
// the next boot itself.
const manualNetBootInstructions = "Restart the computer and choose network (PXE) boot from the firmware's boot menu " +
	"(usually F12, F11, F8 or Esc at power-on). The machine is armed: its next network boot installs the image."

// resolveReimage is the route gate's view: exactly the endpoint in the
// URL. The handler applies the approval itself, which a reimage always
// needs.
func resolveReimage(s *Server, r *http.Request, body []byte) (endpointAction, error) {
	a, err := pathAgent("id")(s, r, body)
	if err != nil {
		return a, err
	}
	a.Module = "provisioning"
	a.Summary = "Reimage " + r.PathValue("id")
	a.ApprovalByCaller = true
	return a, nil
}

func (s *Server) handleReimage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID := r.PathValue("id")
	var req reimageRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid body: "+err.Error()+" (a reimage names one endpoint, in the URL)", http.StatusBadRequest)
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
	hostname, err := s.store.GetAgentHostname(ctx, agentID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if hostname == "" {
		http.Error(w, "no endpoint with that id is in inventory", http.StatusNotFound)
		return
	}
	if !strings.EqualFold(strings.TrimSpace(req.ConfirmHostname), hostname) {
		http.Error(w, "confirm_hostname does not match the endpoint's hostname: type "+hostname+" to confirm", http.StatusBadRequest)
		return
	}
	mac := normalizeMAC(req.MAC)
	macs, err := s.agentMACs(ctx, agentID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if mac == "" || !containsString(macs, mac) {
		http.Error(w, "mac must be one of the endpoint's network interfaces ("+strings.Join(macs, ", ")+")", http.StatusBadRequest)
		return
	}
	im, err := s.store.GetProvisioningImage(ctx, req.ImageID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if im == nil {
		http.Error(w, "no such image", http.StatusBadRequest)
		return
	}
	vars, err := validateVariables(req.Variables)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if vars["hostname"] == "" {
		// The endpoint reported its hostname; it is held to the same
		// pattern as anything an operator types before it goes anywhere.
		short, _, _ := strings.Cut(hostname, ".")
		if !provisioningVariables["hostname"].MatchString(short) {
			http.Error(w, "the endpoint's hostname is not usable as one for the installed system; set the hostname variable", http.StatusBadRequest)
			return
		}
		vars["hostname"] = short
	}
	existing, err := s.store.GetProvisioningMachineByMAC(ctx, mac)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	m := store.ProvisioningMachine{ID: idgen.New("pmc-"), MAC: mac, Name: hostname, ImageID: im.ID, Variables: vars,
		AgentID: agentID, CreatedBy: auth.CurrentUser(ctx).Username}
	if existing != nil {
		m.ID, m.AdminSecret, m.CreatedBy = existing.ID, existing.AdminSecret, existing.CreatedBy
		merged := map[string]string{}
		for k, v := range existing.Variables {
			merged[k] = v
		}
		for k, v := range vars {
			merged[k] = v
		}
		m.Variables = merged
	}
	if err := s.checkMachineInstallable(ctx, &m); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	summary := fmt.Sprintf("Reimage %s with %s (erases it)", hostname, im.Name)
	if s.requireReimageApproval(w, r, summary, agentID, req) {
		return
	}

	// Approved: from here on this is the replay, as the requester.
	who := auth.CurrentUser(ctx).Username
	approvalID, _ := approvalGranted(ctx)
	saved, err := s.store.SaveProvisioningMachine(ctx, m)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := s.store.SetProvisioningArmed(ctx, saved.ID, true, who, time.Now().Add(time.Duration(cfg.ArmHours)*time.Hour)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	restart := req.Restart == nil || *req.Restart
	runID, actionID := idgen.New("run-"), idgen.New("act-")
	label := "Reimage with " + im.Name
	if err := s.store.RecordPatchJobRun(ctx, store.PatchJobRun{ID: runID, TargetDesc: "device: " + hostname, AgentCount: 1,
		ScheduleName: label, TriggeredBy: who}); err != nil {
		s.logger.Warn("record reimage run failed", "error", err)
	}
	if err := s.store.StartAgentAction(ctx, store.AgentAction{ID: actionID, RunID: runID, AgentID: agentID, Kind: "reimage",
		Summary: label, RequestedBy: who}); err != nil {
		s.logger.Warn("record reimage action failed", "error", err)
	}
	// Audited before the endpoint is told anything, like Direct Connect.
	s.audit(ctx, auditEvent{Action: "provisioning.reimage", Actor: who, Target: hostname, AgentID: agentID, Severity: "warning",
		Detail: map[string]any{"image": im.Name, "mac": mac, "machine": saved.ID, "approval": approvalID, "restart": restart, "run_id": runID}})

	resp := reimageResponse{OK: true, MachineID: saved.ID, RunID: runID}
	res, sendErr := s.sendNetBoot(ctx, agentID, proto.NetBootJob{MAC: mac, Restart: restart, RestartMinutes: 1}, runID, actionID)
	switch {
	case sendErr != nil:
		resp.Method, resp.Instructions = "manual", manualNetBootInstructions
		resp.Message = "The machine is armed, but the endpoint could not be told to boot from the network: " + sendErr.Error()
	case res.NetBoot == nil || res.NetBoot.Method == "manual":
		resp.Method = "manual"
		resp.Instructions = manualNetBootInstructions
		if res.NetBoot != nil && res.NetBoot.Instructions != "" {
			resp.Instructions = res.NetBoot.Instructions
		}
		resp.Message = "The machine is armed; the endpoint cannot choose its next boot itself."
	default:
		resp.Method, resp.Entry, resp.Restarting = res.NetBoot.Method, res.NetBoot.Entry, res.NetBoot.Restarting
		resp.Message = "Next boot set to the network with " + res.NetBoot.Method
		if res.NetBoot.Restarting {
			resp.Message += "; the endpoint restarts in a minute and installs " + im.Name
		} else {
			resp.Message += "; it installs " + im.Name + " at its next restart"
		}
	}
	outcome := "succeeded"
	if resp.Method == "manual" {
		outcome = "failed"
	}
	_ = s.store.FinishAgentAction(ctx, agentID, actionID, outcome, resp.Message+"\n"+resp.Instructions)
	writeJSONResponse(w, resp)
}

// sendNetBoot asks the agent to boot from the network once. An agent that
// predates the command answers "unknown command", which is reported as
// having no method rather than as a failure: the machine is armed and a
// person at the console can still pick network boot.
func (s *Server) sendNetBoot(ctx context.Context, agentID string, job proto.NetBootJob, runID, actionID string) (proto.AgentCommandResult, error) {
	payload, err := json.Marshal(proto.AgentCommand{Cmd: "net_boot_once", NetBoot: &job, RunID: runID, ActionID: actionID})
	if err != nil {
		return proto.AgentCommandResult{}, err
	}
	if s.nc == nil {
		return proto.AgentCommandResult{}, fmt.Errorf("the message bus is not connected")
	}
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	msg, err := s.nc.RequestWithContext(rctx, bnats.Cmd(agentID), payload)
	if err != nil {
		return proto.AgentCommandResult{}, fmt.Errorf("the endpoint did not respond: %w", err)
	}
	var res proto.AgentCommandResult
	if err := json.Unmarshal(msg.Data, &res); err != nil {
		return res, fmt.Errorf("malformed response from the endpoint")
	}
	if !res.OK {
		if strings.HasPrefix(res.Error, "unknown command") {
			return proto.AgentCommandResult{OK: true, NetBoot: &proto.NetBootResult{Method: "manual",
				Instructions: "This agent is too old to set the next boot (update it). " + manualNetBootInstructions}}, nil
		}
		return res, fmt.Errorf("%s", res.Error)
	}
	return res, nil
}

// requireReimageApproval parks a reimage for a second person's decision:
// under an approval policy for the provisioning module when one covers
// it, else under the built-in one. It returns true when the caller must
// stop (the response is written).
func (s *Server) requireReimageApproval(w http.ResponseWriter, r *http.Request, summary, agentID string, body reimageRequest) bool {
	p := builtinReimagePolicy
	return s.requireApproval(w, r.WithContext(withMandatoryApproval(r.Context(), &p)), "provisioning", reimageHandlerKey, summary, []string{agentID}, body)
}

// agentMACs are the MAC addresses an endpoint's network sensor reports.
func (s *Server) agentMACs(ctx context.Context, agentID string) ([]string, error) {
	rec, err := s.store.GetSensorData(ctx, agentID, string(proto.SensorNetwork))
	if err != nil || rec == nil {
		return nil, err
	}
	return macsInNetworkSnapshot(rec.Data), nil
}

// macsInNetworkSnapshot reads the normalized MACs out of a network sensor
// snapshot, skipping all-zero and duplicate ones.
func macsInNetworkSnapshot(data []byte) []string {
	var ifaces []proto.NetworkInterfaceInfo
	if json.Unmarshal(bytes.TrimSpace(data), &ifaces) != nil {
		return nil
	}
	var out []string
	for _, i := range ifaces {
		m := normalizeMAC(i.MAC)
		if m == "" || m == "00:00:00:00:00:00" || containsString(out, m) {
			continue
		}
		out = append(out, m)
	}
	return out
}
