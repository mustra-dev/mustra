package server

// The device-facing half of Apple MDM: the enrollment profile download and
// the two endpoints an enrolled Mac talks to (Apple's "check-in" and
// "server" URLs). None of them has a console session; each authenticates
// differently:
//
//   - GET /mdm/enroll/{token}: the enrollment token in the path, which an
//     administrator minted and which runs out (mdm_setup_api.go).
//   - PUT /mdm/checkin and PUT /mdm/connect: the device identity the
//     enrollment profile installed, proven per request by the Mdm-Signature
//     header (or a TLS client certificate when mustra terminates TLS
//     itself; see internal/mdm/identity.go), and then matched to the UDID
//     the message names. An identity speaks for one device only.
//
// Every refusal of a device answers 401 with the same text, so nobody
// probing the endpoints learns which check failed; the server log says.
// With the MDM off all three answer 404, as if the feature were absent.

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/mdm"
	"github.com/mustra-dev/mustra/internal/store"
)

const mdmDeviceActor = "apple-mdm"

// mdmActiveConfig returns the configuration when the MDM is on and
// complete, or nil.
func (s *Server) mdmActiveConfig(ctx context.Context) *store.MDMConfig {
	if s.store == nil {
		return nil
	}
	cfg, err := s.store.GetMDMConfig(ctx)
	if err != nil || !cfg.Enabled || cfg.CACertPEM == "" || cfg.PushTopic == "" {
		return nil
	}
	return cfg
}

// GET /mdm/enroll/{token}
func (s *Server) handleMDMEnroll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cfg := s.mdmActiveConfig(ctx)
	token := r.PathValue("token")
	if cfg == nil || !strings.HasPrefix(token, mdmTokenPrefix) || len(token) > 100 {
		http.NotFound(w, r)
		return
	}
	base, err := s.agentPublicURL(ctx)
	if err != nil || !strings.HasPrefix(base, "https://") {
		http.NotFound(w, r)
		return
	}
	tokenID, err := s.store.UseMDMEnrollToken(ctx, hashToken(token))
	if err != nil {
		http.Error(w, "enrollment is unavailable right now", http.StatusServiceUnavailable)
		return
	}
	if tokenID == "" {
		// Unknown, revoked, expired and used up all look the same.
		http.NotFound(w, r)
		return
	}
	ca, err := s.mdmCA(cfg, true)
	if err != nil {
		s.logger.Error("apple mdm: the CA cannot be opened", "error", err)
		http.Error(w, "enrollment is unavailable right now", http.StatusServiceUnavailable)
		return
	}
	id, err := ca.Issue(tokenID)
	if err != nil {
		http.Error(w, "enrollment is unavailable right now", http.StatusServiceUnavailable)
		return
	}
	if err := s.store.CreateMDMIdentity(ctx, store.MDMIdentity{Serial: mdm.SerialHex(id.Cert), Fingerprint: mdm.Fingerprint(id.Cert),
		TokenID: tokenID, NotAfter: id.Cert.NotAfter}); err != nil {
		http.Error(w, "enrollment is unavailable right now", http.StatusServiceUnavailable)
		return
	}
	profile, err := mdm.EnrollmentProfile(mdm.EnrollmentOptions{ServerURL: base + "/mdm/connect", CheckInURL: base + "/mdm/checkin",
		Topic: cfg.PushTopic, Identity: id, Organization: cfg.Organization})
	if err != nil {
		http.Error(w, "enrollment is unavailable right now", http.StatusServiceUnavailable)
		return
	}
	signed := false
	if cfg.SignCertPEM != "" {
		if out, serr := s.mdmSignProfile(cfg, profile); serr != nil {
			// An unsigned profile still enrolls; the Mac shows it as
			// unverified. Better than no enrollment over a lapsed signer.
			s.logger.Warn("apple mdm: signing the enrollment profile failed; serving it unsigned", "error", serr)
		} else {
			profile, signed = out, true
		}
	}
	s.audit(ctx, auditEvent{Action: "mdm.enrollment_profile", Actor: mdmDeviceActor, Target: "enrollment token " + tokenID, Severity: "notice",
		Detail: map[string]any{"token_id": tokenID, "identity_serial": mdm.SerialHex(id.Cert), "signed": signed, "from": clientAddr(r)}})
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", `attachment; filename="enroll.mobileconfig"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(profile)
}

func (s *Server) mdmSignProfile(cfg *store.MDMConfig, profile []byte) ([]byte, error) {
	certs, err := mdm.ParseCertsPEM(cfg.SignCertPEM)
	if err != nil {
		return nil, err
	}
	keyPEM, err := s.mdmOpen(mdmAADSignKey, cfg.SignKeySealed)
	if err != nil {
		return nil, err
	}
	key, err := mdm.ParseKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	return mdm.SignProfile(profile, certs[0], key, certs[1:])
}

// clientAddr is the requester's address for an audit row: the proxy's
// forwarded address when there is one, as it is only a record.
func clientAddr(r *http.Request) string {
	if f := r.Header.Get("X-Forwarded-For"); f != "" {
		return strings.TrimSpace(strings.Split(f, ",")[0])
	}
	return r.RemoteAddr
}

var errMDMRefused = errors.New("refused")

// mdmAuthenticate reads and authenticates a device request. It returns
// the body and the issued identity that signed it, or writes the refusal.
func (s *Server) mdmAuthenticate(w http.ResponseWriter, r *http.Request, cfg *store.MDMConfig) ([]byte, *store.MDMIdentity, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, mdm.MaxMessageBytes))
	if err != nil {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return nil, nil, false
	}
	ca, err := s.mdmCA(cfg, false)
	if err != nil {
		http.NotFound(w, r)
		return nil, nil, false
	}
	var peer []*x509.Certificate
	if r.TLS != nil {
		peer = r.TLS.PeerCertificates
	}
	leaf, err := mdm.VerifyRequest(ca.Cert, body, r.Header.Get("Mdm-Signature"), peer, time.Now())
	if err != nil {
		s.mdmRefuse(w, r, "", err)
		return nil, nil, false
	}
	ident, err := s.store.GetMDMIdentity(r.Context(), mdm.SerialHex(leaf))
	if err != nil {
		http.Error(w, "try again later", http.StatusServiceUnavailable)
		return nil, nil, false
	}
	if ident == nil || ident.RevokedAt != nil || ident.Fingerprint != mdm.Fingerprint(leaf) {
		s.mdmRefuse(w, r, "", errors.New("the identity is unknown to this server or revoked"))
		return nil, nil, false
	}
	return body, ident, true
}

// mdmRefuse logs why a device request was refused and answers 401.
func (s *Server) mdmRefuse(w http.ResponseWriter, r *http.Request, udid string, why error) {
	s.logger.Warn("apple mdm: device request refused", "path", r.URL.Path, "udid", udid, "from", clientAddr(r), "reason", why)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// mdmDeviceFor returns the device the identity speaks for, when it is the
// one the message names; nil (refused) otherwise.
func (s *Server) mdmDeviceFor(ctx context.Context, ident *store.MDMIdentity, udid string) (*store.MDMDevice, error) {
	if ident.UDID == "" || ident.UDID != udid {
		return nil, errors.New("the identity does not belong to the device the message names")
	}
	dev, err := s.store.GetMDMDevice(ctx, udid)
	if err != nil {
		return nil, err
	}
	if dev == nil || dev.IdentitySerial != ident.Serial {
		return nil, errors.New("the device is unknown or enrolled under another identity")
	}
	return dev, nil
}

// PUT /mdm/checkin
func (s *Server) handleMDMCheckin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cfg := s.mdmActiveConfig(ctx)
	if cfg == nil {
		http.NotFound(w, r)
		return
	}
	body, ident, ok := s.mdmAuthenticate(w, r, cfg)
	if !ok {
		return
	}
	msg, err := mdm.ParseCheckin(body)
	if errors.Is(err, mdm.ErrUserChannel) {
		// Apple: a server that does not support the user channel answers
		// UserAuthenticate with 410, and the Mac stops asking.
		http.Error(w, "user channel not supported", http.StatusGone)
		return
	}
	if err != nil {
		s.logger.Warn("apple mdm: malformed check-in", "error", err, "from", clientAddr(r))
		http.Error(w, "malformed check-in", http.StatusBadRequest)
		return
	}
	switch msg.MessageType {
	case mdm.MsgAuthenticate:
		s.mdmCheckinAuthenticate(w, r, cfg, ident, msg)
	case mdm.MsgTokenUpdate:
		s.mdmCheckinTokenUpdate(w, r, cfg, ident, msg)
	case mdm.MsgCheckOut:
		dev, err := s.mdmDeviceFor(ctx, ident, msg.UDID)
		if err != nil || dev == nil {
			s.mdmRefuse(w, r, msg.UDID, firstErr(err, errMDMRefused))
			return
		}
		if err := s.store.MDMCheckOut(ctx, msg.UDID); err != nil {
			http.Error(w, "try again later", http.StatusServiceUnavailable)
			return
		}
		s.audit(ctx, auditEvent{Action: "mdm.device_checked_out", Actor: mdmDeviceActor, Target: mdmDeviceLabel(dev), AgentID: dev.AgentID,
			Severity: "notice", Detail: map[string]any{"udid": dev.UDID, "serial": dev.SerialNumber}})
		w.WriteHeader(http.StatusOK)
	}
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

func (s *Server) mdmCheckinAuthenticate(w http.ResponseWriter, r *http.Request, cfg *store.MDMConfig, ident *store.MDMIdentity, msg *mdm.CheckinMessage) {
	ctx := r.Context()
	if err := msg.CheckTopic(cfg.PushTopic); err != nil {
		s.mdmRefuse(w, r, msg.UDID, err)
		return
	}
	prev, err := s.store.GetMDMDevice(ctx, msg.UDID)
	if err != nil {
		http.Error(w, "try again later", http.StatusServiceUnavailable)
		return
	}
	// A UDID is not a secret. Anyone holding a fresh identity (any
	// enrollment link) could otherwise claim an enrolled Mac's UDID, take
	// over its record and revoke the real Mac's identity. A Mac enrolling
	// again normally checked out when its profile was removed; one that
	// did not (erased, say) is forgotten in the console first.
	if prev != nil && prev.Enrolled && prev.IdentitySerial != "" && prev.IdentitySerial != ident.Serial {
		if old, err := s.store.GetMDMIdentity(ctx, prev.IdentitySerial); err != nil {
			http.Error(w, "try again later", http.StatusServiceUnavailable)
			return
		} else if old != nil && old.RevokedAt == nil && time.Now().Before(old.NotAfter) {
			s.mdmRefuse(w, r, msg.UDID, errors.New("this UDID is enrolled under another identity; forget the Mac in the console before enrolling it again"))
			return
		}
	}
	// First use binds the identity to this UDID; afterwards it can only
	// ever authenticate that device again.
	bound, err := s.store.BindMDMIdentity(ctx, ident.Serial, msg.UDID)
	if err != nil {
		http.Error(w, "try again later", http.StatusServiceUnavailable)
		return
	}
	if !bound {
		s.mdmRefuse(w, r, msg.UDID, errors.New("the identity already belongs to another device"))
		return
	}
	if err := s.store.MDMAuthenticate(ctx, msg, ident.Serial); err != nil {
		http.Error(w, "try again later", http.StatusServiceUnavailable)
		return
	}
	// Enrolling again replaces the identity: the old one stops working.
	if err := s.store.RevokeMDMIdentities(ctx, msg.UDID, ident.Serial); err != nil {
		s.logger.Warn("apple mdm: revoking a re-enrolled device's old identities failed", "udid", msg.UDID, "error", err)
	}
	s.mdmLinkAgent(ctx, msg.UDID, msg.SerialNumber)
	dev := &store.MDMDevice{UDID: msg.UDID, SerialNumber: msg.SerialNumber, DeviceName: msg.DeviceName}
	if prev != nil {
		dev.AgentID = prev.AgentID
	}
	s.audit(ctx, auditEvent{Action: "mdm.device_authenticated", Actor: mdmDeviceActor, Target: mdmDeviceLabel(dev), AgentID: dev.AgentID,
		Severity: "notice", Detail: map[string]any{"udid": msg.UDID, "serial": msg.SerialNumber, "model": msg.Model,
			"os_version": msg.OSVersion, "re_enrollment": prev != nil, "token_id": ident.TokenID}})
	w.WriteHeader(http.StatusOK)
}

func (s *Server) mdmCheckinTokenUpdate(w http.ResponseWriter, r *http.Request, cfg *store.MDMConfig, ident *store.MDMIdentity, msg *mdm.CheckinMessage) {
	ctx := r.Context()
	if err := msg.CheckTopic(cfg.PushTopic); err != nil {
		s.mdmRefuse(w, r, msg.UDID, err)
		return
	}
	dev, err := s.mdmDeviceFor(ctx, ident, msg.UDID)
	if err != nil || dev == nil {
		s.mdmRefuse(w, r, msg.UDID, firstErr(err, errMDMRefused))
		return
	}
	if err := s.store.MDMTokenUpdate(ctx, msg.UDID, msg.Token, msg.PushMagic); err != nil {
		http.Error(w, "try again later", http.StatusServiceUnavailable)
		return
	}
	if !dev.Enrolled {
		// The first TokenUpdate completes enrollment. Ask the Mac about
		// itself straight away, so its page is not empty.
		s.audit(ctx, auditEvent{Action: "mdm.device_enrolled", Actor: mdmDeviceActor, Target: mdmDeviceLabel(dev), AgentID: dev.AgentID,
			Severity: "notice", Detail: map[string]any{"udid": dev.UDID, "serial": dev.SerialNumber}})
		dev.Enrolled = true
		for _, rt := range []string{mdm.CmdDeviceInformation, mdm.CmdSecurityInfo, mdm.CmdProfileList} {
			if _, err := s.mdmEnqueue(ctx, dev, rt, mdm.CommandParams{}, "", mdmDeviceActor, ""); err != nil {
				s.logger.Warn("apple mdm: queueing the first inventory failed", "udid", dev.UDID, "error", err)
			}
		}
		go s.mdmPush(context.WithoutCancel(ctx), dev.UDID)
	}
	w.WriteHeader(http.StatusOK)
}

// maxStoredResult bounds one command's stored answer.
const maxStoredResult = 4 << 20

// PUT /mdm/connect
func (s *Server) handleMDMConnect(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cfg := s.mdmActiveConfig(ctx)
	if cfg == nil {
		http.NotFound(w, r)
		return
	}
	body, ident, ok := s.mdmAuthenticate(w, r, cfg)
	if !ok {
		return
	}
	rep, err := mdm.ParseReport(body)
	if err != nil {
		s.logger.Warn("apple mdm: malformed command report", "error", err, "from", clientAddr(r))
		http.Error(w, "malformed report", http.StatusBadRequest)
		return
	}
	dev, err := s.mdmDeviceFor(ctx, ident, rep.UDID)
	if err != nil || dev == nil || !dev.Enrolled {
		s.mdmRefuse(w, r, rep.UDID, firstErr(err, errors.New("the device is not enrolled")))
		return
	}
	_ = s.store.TouchMDMDevice(ctx, dev.UDID)
	if rep.Status == mdm.StatusIdle {
		if err := s.store.MDMIdle(ctx, dev.UDID); err != nil {
			http.Error(w, "try again later", http.StatusServiceUnavailable)
			return
		}
	} else if err := s.mdmTakeReport(ctx, dev, rep); err != nil {
		http.Error(w, "try again later", http.StatusServiceUnavailable)
		return
	}
	s.mdmSendNext(w, r, dev)
}

// mdmTakeReport records a device's report about one command.
func (s *Server) mdmTakeReport(ctx context.Context, dev *store.MDMDevice, rep *mdm.CommandReport) error {
	cmd, err := s.store.GetMDMCommand(ctx, rep.CommandUUID)
	if err != nil {
		return err
	}
	if cmd == nil || cmd.UDID != dev.UDID {
		// Not one of ours for this device (another MDM's, or deleted with
		// its history): nothing to record, and the device moves on.
		s.logger.Info("apple mdm: report for an unknown command", "udid", dev.UDID, "command", rep.CommandUUID, "status", rep.Status)
		return nil
	}
	var result json.RawMessage
	if key := mdm.ResultKey(cmd.RequestType); key != "" && rep.Status == mdm.StatusAcknowledged {
		if v, ok := rep.Raw[key]; ok {
			b, err := json.Marshal(mdm.JSONValue(v, 512))
			if err == nil && len(b) <= maxStoredResult {
				result = b
			}
		}
	}
	var chain json.RawMessage
	if len(rep.ErrorChain) > 0 {
		chain, _ = json.Marshal(rep.ErrorChain)
	}
	updated, err := s.store.MDMRecordReport(ctx, dev.UDID, cmd.UUID, rep.Status, result, chain)
	if errors.Is(err, mdm.ErrAlreadyFinal) {
		return nil
	}
	if err != nil {
		return err
	}
	if updated == nil {
		return nil
	}
	if result != nil {
		if err := s.store.SetMDMDeviceResult(ctx, dev.UDID, cmd.RequestType, result); err != nil {
			s.logger.Warn("apple mdm: storing a command's answer on the device failed", "udid", dev.UDID, "error", err)
		}
		if cmd.RequestType == mdm.CmdDeviceInformation {
			var info struct {
				SerialNumber string
			}
			if json.Unmarshal(result, &info) == nil && info.SerialNumber != "" {
				s.mdmLinkAgent(ctx, dev.UDID, info.SerialNumber)
			}
		}
	}
	info, _ := mdm.LookupCommand(cmd.RequestType)
	if !info.Query && mdm.Final(updated.State) {
		// What changed the Mac is on the audit trail with its outcome,
		// next to who asked for it.
		outcome, sev := "ok", "notice"
		if updated.State != mdm.StateAcknowledged {
			outcome, sev = "failed", "warning"
		}
		s.audit(ctx, auditEvent{Action: "mdm.command_result", Actor: mdmDeviceActor, Target: cmd.RequestType + " on " + mdmDeviceLabel(dev),
			AgentID: dev.AgentID, Outcome: outcome, Severity: sev,
			Detail: map[string]any{"udid": dev.UDID, "command": cmd.UUID, "state": updated.State, "requested_by": cmd.RequestedBy, "errors": rep.ErrorChain}})
		// Keep the installed-profile list current after a change to it.
		if (cmd.RequestType == mdm.CmdInstallProfile || cmd.RequestType == mdm.CmdRemoveProfile) && updated.State == mdm.StateAcknowledged {
			if _, err := s.mdmEnqueue(ctx, dev, mdm.CmdProfileList, mdm.CommandParams{}, "", mdmDeviceActor, ""); err != nil {
				s.logger.Warn("apple mdm: queueing a profile list refresh failed", "udid", dev.UDID, "error", err)
			}
		}
	}
	return nil
}

// mdmSendNext answers a connect request with the device's next command,
// or an empty 200 when its queue is empty.
func (s *Server) mdmSendNext(w http.ResponseWriter, r *http.Request, dev *store.MDMDevice) {
	ctx := r.Context()
	cmd, err := s.store.MDMNextCommand(ctx, dev.UDID)
	if err != nil {
		http.Error(w, "try again later", http.StatusServiceUnavailable)
		return
	}
	if cmd == nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	payload := cmd.Payload
	if cmd.PayloadSealed {
		plain, err := s.mdmOpen(mdmPayloadAAD(cmd.UUID), string(cmd.Payload))
		if err != nil {
			s.logger.Error("apple mdm: a sealed command cannot be opened; failing it", "command", cmd.UUID, "error", err)
			_, _ = s.store.MDMRecordReport(ctx, dev.UDID, cmd.UUID, mdm.StatusError, nil,
				json.RawMessage(`[{"code":0,"domain":"mustra","description":"the command could not be decrypted on the server"}]`))
			w.WriteHeader(http.StatusOK)
			return
		}
		payload = []byte(plain)
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(payload)
}

func mdmDeviceLabel(d *store.MDMDevice) string {
	switch {
	case d.DeviceName != "" && d.SerialNumber != "":
		return d.DeviceName + " (" + d.SerialNumber + ")"
	case d.DeviceName != "":
		return d.DeviceName
	case d.SerialNumber != "":
		return d.SerialNumber
	}
	return d.UDID
}

// mdmLinkAgent ties the device to the mustra agent on the same Mac, by
// serial number. A serial number reported by more than one endpoint links
// to none: guessing would put one Mac's commands on another's page.
func (s *Server) mdmLinkAgent(ctx context.Context, udid, serial string) {
	agentID := s.mdmAgentsBySerial(ctx)[strings.ToUpper(strings.TrimSpace(serial))]
	if err := s.store.SetMDMDeviceAgent(ctx, udid, agentID); err != nil {
		s.logger.Warn("apple mdm: linking a device to its endpoint failed", "udid", udid, "error", err)
	}
}

// mdmAgentsBySerial maps each Mac's serial number (from the hardware
// sensor) to its agent, leaving out serials more than one agent reports.
func (s *Server) mdmAgentsBySerial(ctx context.Context) map[string]string {
	out := map[string]string{}
	rows, err := s.store.ListSensorDataForSensor(ctx, "hardware")
	if err != nil {
		return out
	}
	dup := map[string]bool{}
	for _, row := range rows {
		if row.OS != "darwin" {
			continue
		}
		var hw []struct {
			Serial string `json:"serial"`
		}
		if json.Unmarshal(row.Data, &hw) != nil || len(hw) == 0 {
			continue
		}
		serial := strings.ToUpper(strings.TrimSpace(hw[0].Serial))
		if serial == "" {
			continue
		}
		if prev, ok := out[serial]; ok && prev != row.AgentID {
			dup[serial] = true
		}
		out[serial] = row.AgentID
	}
	for k := range dup {
		delete(out, k)
	}
	return out
}
