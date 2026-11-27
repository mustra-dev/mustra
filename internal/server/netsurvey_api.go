package server

// Network surveys: the opt-in, active half of Discover. An operator names
// endpoints, the subnets they sit on and the read-only protocols to use;
// each endpoint probes within those bounds (internal/agent/netsurvey) and
// reports what answered. Discover itself still sends nothing.
//
// SNMP secrets are sealed by the credential vault, bound to the survey,
// sent to an endpoint only inside a run's command (core request/reply,
// never a stream), and never returned by the API: a read says only
// whether each secret is set.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/server/vault"
	"github.com/mustra-dev/mustra/internal/store"
)

const (
	netSurveyMaxAgents   = 20
	netSurveyMaxInterval = 24 * 30 // hours
	// netSurveyGrace is how long past its budget a run may stay silent
	// before it is recorded as timed out.
	netSurveyGrace = 5 * time.Minute
)

// netSurveySNMPRequest is the SNMP part of a survey. A secret field left
// out keeps the stored value; an empty string clears it.
type netSurveySNMPRequest struct {
	// Version is "2c" or "3".
	Version   string  `json:"version"`
	Community *string `json:"community,omitempty" api:"writeonly"`
	// User, SecurityLevel (noAuthNoPriv, authNoPriv, authPriv), and the
	// protocols are SNMPv3's.
	User           string  `json:"user,omitempty"`
	SecurityLevel  string  `json:"security_level,omitempty"`
	AuthProtocol   string  `json:"auth_protocol,omitempty"`
	AuthPassphrase *string `json:"auth_passphrase,omitempty" api:"writeonly"`
	PrivProtocol   string  `json:"priv_protocol,omitempty"`
	PrivPassphrase *string `json:"priv_passphrase,omitempty" api:"writeonly"`
}

// netSurveyRequest is the body of POST /api/discover/surveys and
// PUT /api/discover/surveys/{id}.
type netSurveyRequest struct {
	Name string `json:"name"`
	// Enabled is false by default: a disabled survey never sends a packet,
	// on schedule or on request.
	Enabled bool `json:"enabled"`
	// AgentIDs are the endpoints that survey, each from its own networks.
	AgentIDs []string `json:"agent_ids"`
	// Subnets are IPv4 CIDRs, each no larger than /22, and each a network
	// every surveying endpoint is directly attached to unless
	// AllowOffLink is set.
	Subnets      []string `json:"subnets"`
	AllowOffLink bool     `json:"allow_off_link"`
	// Protocols: snmp, ipp, modbus, bacnet, enip, profinet.
	Protocols []string `json:"protocols"`
	// IntervalHours repeats the survey; 0 runs it only when asked.
	IntervalHours int `json:"interval_hours"`
	// PacketsPerSecond (1-200, default 20) caps every probe the endpoint
	// sends; Concurrency (1-32, default 8) caps hosts probed at once.
	PacketsPerSecond int `json:"packets_per_second"`
	Concurrency      int `json:"concurrency"`
	// TimeoutMillis (200-10000, default 1500) is one probe's wait for an
	// answer; BudgetSeconds (10-3600, default 900) ends the whole run.
	TimeoutMillis int                   `json:"timeout_ms"`
	BudgetSeconds int                   `json:"budget_seconds"`
	SNMP          *netSurveySNMPRequest `json:"snmp,omitempty"`
}

// netSurveySecrets is what the vault seals for a survey.
type netSurveySecrets struct {
	Community string `json:"community,omitempty"`
	Auth      string `json:"auth,omitempty"`
	Priv      string `json:"priv,omitempty"`
}

func (s netSurveySecrets) empty() bool { return s == netSurveySecrets{} }

// netSurveySNMPView is a survey's SNMP settings as the API shows them:
// which secrets are set, never what they are.
type netSurveySNMPView struct {
	Version           string `json:"version"`
	User              string `json:"user,omitempty"`
	SecurityLevel     string `json:"security_level,omitempty"`
	AuthProtocol      string `json:"auth_protocol,omitempty"`
	PrivProtocol      string `json:"priv_protocol,omitempty"`
	CommunitySet      bool   `json:"community_set"`
	AuthPassphraseSet bool   `json:"auth_passphrase_set"`
	PrivPassphraseSet bool   `json:"priv_passphrase_set"`
}

type netSurveyAgentView struct {
	AgentID  string `json:"agent_id"`
	Hostname string `json:"hostname"`
	Online   bool   `json:"online"`
}

// netSurveyView is one survey in GET /api/discover/surveys.
type netSurveyView struct {
	ID               string               `json:"id"`
	Name             string               `json:"name"`
	Enabled          bool                 `json:"enabled"`
	AgentIDs         []string             `json:"agent_ids"`
	Agents           []netSurveyAgentView `json:"agents"`
	Subnets          []string             `json:"subnets"`
	AllowOffLink     bool                 `json:"allow_off_link"`
	Protocols        []string             `json:"protocols"`
	IntervalHours    int                  `json:"interval_hours"`
	PacketsPerSecond int                  `json:"packets_per_second"`
	Concurrency      int                  `json:"concurrency"`
	TimeoutMillis    int                  `json:"timeout_ms"`
	BudgetSeconds    int                  `json:"budget_seconds"`
	SNMP             *netSurveySNMPView   `json:"snmp,omitempty"`
	CreatedBy        string               `json:"created_by"`
	CreatedAt        time.Time            `json:"created_at"`
	UpdatedAt        time.Time            `json:"updated_at"`
	LastRunAt        *time.Time           `json:"last_run_at,omitempty"`
	// NextRunAt is when the schedule runs it next; absent when it only
	// runs on request or is disabled.
	NextRunAt *time.Time `json:"next_run_at,omitempty"`
}

// netSurveyRunView is one endpoint's run, with names for display.
type netSurveyRunView struct {
	store.NetworkSurveyRun
	Hostname   string `json:"hostname"`
	SurveyName string `json:"survey_name"`
}

// listNetSurveysResponse is what GET /api/discover/surveys answers.
type listNetSurveysResponse struct {
	Surveys []netSurveyView `json:"surveys"`
	// Runs are the 50 newest runs across every survey.
	Runs      []netSurveyRunView `json:"runs"`
	Protocols []string           `json:"protocols"`
	// SecretsAvailable is false when the server has no credential
	// encryption key, so SNMP secrets cannot be stored.
	SecretsAvailable bool `json:"secrets_available"`
}

// saveNetSurveyResponse answers a survey's create or update.
type saveNetSurveyResponse struct {
	ID string `json:"id"`
}

// runNetSurveyResponse answers POST /api/discover/surveys/{id}/run: the
// runs it started, one per endpoint, as each endpoint first answered.
type runNetSurveyResponse struct {
	Runs []netSurveyRunView `json:"runs"`
}

var (
	snmpSecurityLevels = []string{"noAuthNoPriv", "authNoPriv", "authPriv"}
	snmpAuthProtocols  = []string{"MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512"}
	snmpPrivProtocols  = []string{"DES", "AES", "AES192", "AES256", "AES192C", "AES256C"}
)

// buildNetSurvey validates a request into a survey and its secrets. prev
// is the stored survey on an update (nil on create) and prevSecrets its
// opened secrets: a secret the request leaves out is kept.
func buildNetSurvey(req netSurveyRequest, prev *store.NetworkSurvey, prevSecrets netSurveySecrets) (store.NetworkSurvey, netSurveySecrets, error) {
	var n store.NetworkSurvey
	if prev != nil {
		n = *prev
	}
	bad := func(format string, a ...any) (store.NetworkSurvey, netSurveySecrets, error) {
		return store.NetworkSurvey{}, netSurveySecrets{}, fmt.Errorf(format, a...)
	}
	n.Name = strings.TrimSpace(req.Name)
	if n.Name == "" || len(n.Name) > 80 {
		return bad("a survey needs a name of up to 80 characters")
	}
	n.Enabled = req.Enabled

	n.AgentIDs = nil
	for _, id := range req.AgentIDs {
		id = strings.TrimSpace(id)
		if !bnats.ValidAgentID(id) {
			return bad("%q is not an endpoint id", id)
		}
		if !slices.Contains(n.AgentIDs, id) {
			n.AgentIDs = append(n.AgentIDs, id)
		}
	}
	if len(n.AgentIDs) == 0 || len(n.AgentIDs) > netSurveyMaxAgents {
		return bad("name between 1 and %d endpoints to survey from", netSurveyMaxAgents)
	}

	n.Subnets = nil
	for _, raw := range req.Subnets {
		pfx, err := proto.ParseNetSurveySubnet(raw)
		if err != nil {
			return bad("subnet %q: %v", strings.TrimSpace(raw), err)
		}
		if !slices.Contains(n.Subnets, pfx.String()) {
			n.Subnets = append(n.Subnets, pfx.String())
		}
	}
	if len(n.Subnets) == 0 || len(n.Subnets) > proto.NetSurveyMaxSubnets {
		return bad("name between 1 and %d subnets", proto.NetSurveyMaxSubnets)
	}
	n.AllowOffLink = req.AllowOffLink

	n.Protocols = nil
	for _, p := range req.Protocols {
		p = strings.ToLower(strings.TrimSpace(p))
		if !slices.Contains(proto.NetSurveyProtocols, p) {
			return bad("unknown protocol %q (one of %s)", p, strings.Join(proto.NetSurveyProtocols, ", "))
		}
		if !slices.Contains(n.Protocols, p) {
			n.Protocols = append(n.Protocols, p)
		}
	}
	if len(n.Protocols) == 0 {
		return bad("choose at least one protocol")
	}

	rng := func(name string, v, lo, hi, def int) (int, error) {
		if v == 0 {
			return def, nil
		}
		if v < lo || v > hi {
			return 0, fmt.Errorf("%s must be between %d and %d", name, lo, hi)
		}
		return v, nil
	}
	var err error
	if req.IntervalHours < 0 || req.IntervalHours > netSurveyMaxInterval {
		return bad("interval_hours must be between 0 (on request only) and %d", netSurveyMaxInterval)
	}
	n.IntervalHours = req.IntervalHours
	if n.PacketsPerSecond, err = rng("packets_per_second", req.PacketsPerSecond, 1, proto.NetSurveyMaxPacketsPerSecond, 20); err != nil {
		return store.NetworkSurvey{}, netSurveySecrets{}, err
	}
	if n.Concurrency, err = rng("concurrency", req.Concurrency, 1, proto.NetSurveyMaxConcurrency, 8); err != nil {
		return store.NetworkSurvey{}, netSurveySecrets{}, err
	}
	if n.TimeoutMillis, err = rng("timeout_ms", req.TimeoutMillis, 200, 10000, 1500); err != nil {
		return store.NetworkSurvey{}, netSurveySecrets{}, err
	}
	if n.BudgetSeconds, err = rng("budget_seconds", req.BudgetSeconds, 10, 3600, 900); err != nil {
		return store.NetworkSurvey{}, netSurveySecrets{}, err
	}

	sec := prevSecrets
	if req.SNMP == nil {
		n.SNMPVersion, n.SNMPUser, n.SNMPSecurityLevel, n.SNMPAuthProtocol, n.SNMPPrivProtocol = "", "", "", "", ""
		sec = netSurveySecrets{}
	} else {
		c := req.SNMP
		set := func(dst *string, v *string) {
			if v != nil {
				*dst = *v
			}
		}
		set(&sec.Community, c.Community)
		set(&sec.Auth, c.AuthPassphrase)
		set(&sec.Priv, c.PrivPassphrase)
		n.SNMPVersion = c.Version
		switch c.Version {
		case "2c":
			n.SNMPUser, n.SNMPSecurityLevel, n.SNMPAuthProtocol, n.SNMPPrivProtocol = "", "", "", ""
			sec.Auth, sec.Priv = "", ""
		case "3":
			sec.Community = ""
			n.SNMPUser = strings.TrimSpace(c.User)
			n.SNMPSecurityLevel = c.SecurityLevel
			if n.SNMPUser == "" || !slices.Contains(snmpSecurityLevels, n.SNMPSecurityLevel) {
				return bad("SNMPv3 needs a user and a security level (%s)", strings.Join(snmpSecurityLevels, ", "))
			}
			n.SNMPAuthProtocol, n.SNMPPrivProtocol = "", ""
			if n.SNMPSecurityLevel != "noAuthNoPriv" {
				n.SNMPAuthProtocol = strings.ToUpper(c.AuthProtocol)
				if !slices.Contains(snmpAuthProtocols, n.SNMPAuthProtocol) || sec.Auth == "" {
					return bad("SNMPv3 authentication needs a protocol (%s) and a passphrase", strings.Join(snmpAuthProtocols, ", "))
				}
				if len(sec.Auth) < 8 {
					return bad("an SNMPv3 passphrase has at least 8 characters")
				}
			} else {
				sec.Auth = ""
			}
			if n.SNMPSecurityLevel == "authPriv" {
				n.SNMPPrivProtocol = strings.ToUpper(c.PrivProtocol)
				if !slices.Contains(snmpPrivProtocols, n.SNMPPrivProtocol) || sec.Priv == "" {
					return bad("SNMPv3 privacy needs a protocol (%s) and a passphrase", strings.Join(snmpPrivProtocols, ", "))
				}
				if len(sec.Priv) < 8 {
					return bad("an SNMPv3 passphrase has at least 8 characters")
				}
			} else {
				sec.Priv = ""
			}
		default:
			return bad(`SNMP version is "2c" or "3"`)
		}
	}
	if slices.Contains(n.Protocols, proto.NetSurveySNMP) {
		switch {
		case n.SNMPVersion == "":
			return bad("the snmp protocol needs SNMP settings")
		case n.SNMPVersion == "2c" && sec.Community == "":
			return bad("SNMP v2c needs a community")
		}
	}
	return n, sec, nil
}

// offLinkSubnets returns the subnets that lie in none of an endpoint's
// interface networks (as its network sensor reported them).
func offLinkSubnets(subnets []string, ifaces []proto.NetworkInterfaceInfo) []string {
	var nets []netip.Prefix
	for _, ifc := range ifaces {
		for _, a := range ifc.Addresses {
			if p, err := netip.ParsePrefix(a); err == nil && p.Addr().Unmap().Is4() {
				nets = append(nets, netip.PrefixFrom(p.Addr().Unmap(), p.Bits()).Masked())
			}
		}
	}
	var out []string
	for _, s := range subnets {
		sp, err := netip.ParsePrefix(s)
		if err != nil {
			continue
		}
		in := false
		for _, n := range nets {
			if n.Bits() <= sp.Bits() && n.Contains(sp.Addr()) {
				in = true
				break
			}
		}
		if !in {
			out = append(out, s)
		}
	}
	return out
}

// checkSurveyAgents refuses endpoints that do not exist, and (unless the
// survey allows off-link subnets) subnets an endpoint is known not to be
// attached to. An endpoint with no network data yet is left to refuse
// them itself when it runs.
func (s *Server) checkSurveyAgents(ctx context.Context, n store.NetworkSurvey) (problem string, err error) {
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return "", err
	}
	known := map[string]store.AgentRecord{}
	for _, a := range agents {
		known[a.AgentID] = a
	}
	for _, id := range n.AgentIDs {
		a, ok := known[id]
		if !ok || !a.Managed {
			return fmt.Sprintf("no managed endpoint %s", id), nil
		}
		if n.AllowOffLink {
			continue
		}
		rec, err := s.store.GetSensorData(ctx, id, string(proto.SensorNetwork))
		if err != nil || rec == nil {
			continue
		}
		var ifaces []proto.NetworkInterfaceInfo
		if json.Unmarshal(rec.Data, &ifaces) != nil {
			continue
		}
		if off := offLinkSubnets(n.Subnets, ifaces); len(off) > 0 {
			return fmt.Sprintf("%s is not attached to %s; survey only networks the endpoint is on, or allow off-link subnets explicitly",
				a.Hostname, strings.Join(off, ", ")), nil
		}
	}
	return "", nil
}

func (s *Server) openSurveySecrets(n *store.NetworkSurvey) (netSurveySecrets, error) {
	var sec netSurveySecrets
	if n == nil || len(n.SNMPSecretEnc) == 0 {
		return sec, nil
	}
	if s.vault == nil {
		return sec, errors.New("the survey's SNMP secrets are encrypted but no credential encryption key is configured (MUSTRA_CREDENTIAL_ENCRYPTION_KEY)")
	}
	plain, _, err := s.vault.Open(n.SNMPSecretEnc, vault.NetworkSurveyAAD(n.ID))
	if err != nil {
		return sec, fmt.Errorf("open the survey's SNMP secrets: %w", err)
	}
	if err := json.Unmarshal([]byte(plain), &sec); err != nil {
		return sec, fmt.Errorf("open the survey's SNMP secrets: %w", err)
	}
	return sec, nil
}

func (s *Server) sealSurveySecrets(id string, sec netSurveySecrets) ([]byte, error) {
	if sec.empty() {
		return nil, nil
	}
	if s.vault == nil {
		return nil, errNoVault
	}
	raw, _ := json.Marshal(sec)
	return s.vault.Seal(string(raw), vault.NetworkSurveyAAD(id))
}

var (
	errNoVault         = errors.New("SNMP secrets are stored encrypted, and this server has no credential encryption key (MUSTRA_CREDENTIAL_ENCRYPTION_KEY)")
	errSurveyDisabled  = errors.New("the survey is disabled; enable it before running it")
	errSurveyBusy      = errors.New("this survey is still running")
	errSurveyNoTargets = errors.New("none of the survey's endpoints can run it")
	errSurveyNoBus     = errors.New("no message bus")
)

// GET /api/discover/surveys
func (s *Server) handleListNetSurveys(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	surveys, err := s.store.ListNetworkSurveys(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	runs, err := s.store.ListNetworkSurveyRuns(ctx, 50)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	byID := map[string]store.AgentRecord{}
	for _, a := range agents {
		byID[a.AgentID] = a
	}
	out := listNetSurveysResponse{Surveys: []netSurveyView{}, Runs: []netSurveyRunView{}, Protocols: proto.NetSurveyProtocols, SecretsAvailable: s.vault != nil}
	names := map[string]string{}
	for _, n := range surveys {
		names[n.ID] = n.Name
		v := netSurveyView{ID: n.ID, Name: n.Name, Enabled: n.Enabled, AgentIDs: n.AgentIDs, Agents: []netSurveyAgentView{},
			Subnets: n.Subnets, AllowOffLink: n.AllowOffLink, Protocols: n.Protocols, IntervalHours: n.IntervalHours,
			PacketsPerSecond: n.PacketsPerSecond, Concurrency: n.Concurrency, TimeoutMillis: n.TimeoutMillis, BudgetSeconds: n.BudgetSeconds,
			CreatedBy: n.CreatedBy, CreatedAt: n.CreatedAt, UpdatedAt: n.UpdatedAt, LastRunAt: n.LastRunAt}
		for _, id := range n.AgentIDs {
			a := byID[id]
			v.Agents = append(v.Agents, netSurveyAgentView{AgentID: id, Hostname: firstNonEmpty(a.Hostname, id), Online: a.Online})
		}
		if n.SNMPVersion != "" {
			// Which secrets are set comes from the sealed blob's
			// presence and the security level, without opening it.
			sealed := len(n.SNMPSecretEnc) > 0
			v.SNMP = &netSurveySNMPView{Version: n.SNMPVersion, User: n.SNMPUser, SecurityLevel: n.SNMPSecurityLevel,
				AuthProtocol: n.SNMPAuthProtocol, PrivProtocol: n.SNMPPrivProtocol,
				CommunitySet:      sealed && n.SNMPVersion == "2c",
				AuthPassphraseSet: sealed && n.SNMPVersion == "3" && n.SNMPSecurityLevel != "noAuthNoPriv",
				PrivPassphraseSet: sealed && n.SNMPVersion == "3" && n.SNMPSecurityLevel == "authPriv"}
		}
		if next := nextSurveyRun(n); next != nil {
			v.NextRunAt = next
		}
		out.Surveys = append(out.Surveys, v)
	}
	for _, run := range runs {
		out.Runs = append(out.Runs, netSurveyRunView{NetworkSurveyRun: run, Hostname: firstNonEmpty(byID[run.AgentID].Hostname, run.AgentID), SurveyName: names[run.SurveyID]})
	}
	writeJSONResponse(w, out)
}

// nextSurveyRun is when the scheduler will start the survey next.
func nextSurveyRun(n store.NetworkSurvey) *time.Time {
	if !n.Enabled || n.IntervalHours <= 0 {
		return nil
	}
	if n.LastRunAt == nil {
		now := time.Now().UTC()
		return &now
	}
	t := n.LastRunAt.Add(time.Duration(n.IntervalHours) * time.Hour)
	return &t
}

// POST /api/discover/surveys, PUT /api/discover/surveys/{id}
func (s *Server) handleSaveNetSurvey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	who := auth.CurrentUser(ctx).Username
	var req netSurveyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	id := r.PathValue("id")
	var prev *store.NetworkSurvey
	if id != "" {
		var err error
		if prev, err = s.store.GetNetworkSurvey(ctx, id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if prev == nil {
			http.Error(w, "no such survey", http.StatusNotFound)
			return
		}
	}
	prevSecrets, err := s.openSurveySecrets(prev)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	n, sec, err := buildNetSurvey(req, prev, prevSecrets)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if prev == nil {
		n.ID, n.CreatedBy = idgen.New("nsv-"), who
	}
	problem, err := s.checkSurveyAgents(ctx, n)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if problem != "" {
		http.Error(w, problem, http.StatusBadRequest)
		return
	}
	if !sec.empty() && s.vault == nil {
		http.Error(w, errNoVault.Error(), http.StatusBadRequest)
		return
	}
	if n.SNMPSecretEnc, err = s.sealSurveySecrets(n.ID, sec); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.store.SaveNetworkSurvey(ctx, n); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	action := "discover.survey_create"
	if prev != nil {
		action = "discover.survey_update"
	}
	// The audit row says which secrets were changed, never their values.
	var changed []string
	if req.SNMP != nil {
		for name, v := range map[string]*string{"community": req.SNMP.Community, "auth_passphrase": req.SNMP.AuthPassphrase, "priv_passphrase": req.SNMP.PrivPassphrase} {
			if v != nil {
				changed = append(changed, name)
			}
		}
		slices.Sort(changed)
	}
	s.audit(ctx, auditEvent{Action: action, Actor: who, Target: n.Name, Severity: "notice",
		Detail: map[string]any{"id": n.ID, "enabled": n.Enabled, "agent_ids": n.AgentIDs, "subnets": n.Subnets,
			"allow_off_link": n.AllowOffLink, "protocols": n.Protocols, "interval_hours": n.IntervalHours,
			"packets_per_second": n.PacketsPerSecond, "snmp_version": n.SNMPVersion, "snmp_secrets_changed": changed}})
	if prev == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(saveNetSurveyResponse{ID: n.ID})
		return
	}
	writeJSONResponse(w, saveNetSurveyResponse{ID: n.ID})
}

// DELETE /api/discover/surveys/{id}
func (s *Server) handleDeleteNetSurvey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	n, err := s.store.GetNetworkSurvey(ctx, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if n == nil {
		http.Error(w, "no such survey", http.StatusNotFound)
		return
	}
	if _, err := s.store.DeleteNetworkSurvey(ctx, n.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(ctx, auditEvent{Action: "discover.survey_delete", Actor: auth.CurrentUser(ctx).Username, Target: n.Name, Severity: "notice",
		Detail: map[string]any{"id": n.ID}})
	w.WriteHeader(http.StatusNoContent)
}

// resolveNetSurveyRun: a run reaches exactly the survey's endpoints.
func resolveNetSurveyRun(s *Server, r *http.Request, _ []byte) (endpointAction, error) {
	n, err := s.store.GetNetworkSurvey(r.Context(), r.PathValue("id"))
	if err != nil {
		return endpointAction{}, err
	}
	if n == nil {
		return endpointAction{}, httpError{http.StatusNotFound, "no such survey"}
	}
	return endpointAction{Explicit: n.AgentIDs, Summary: "network survey " + n.Name}, nil
}

// resolveNetSurveySave: saving a survey targets the endpoints it names.
func resolveNetSurveySave(_ *Server, r *http.Request, body []byte) (endpointAction, error) {
	ids := bodyStrings(body, "agent_ids")
	if len(ids) == 0 {
		return endpointAction{}, httpError{http.StatusBadRequest, "name the endpoints that survey (agent_ids)"}
	}
	return endpointAction{Explicit: ids, Summary: r.Method + " " + r.URL.Path}, nil
}

// POST /api/discover/surveys/{id}/run
func (s *Server) handleRunNetSurvey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	n, err := s.store.GetNetworkSurvey(ctx, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if n == nil {
		http.Error(w, "no such survey", http.StatusNotFound)
		return
	}
	who := auth.CurrentUser(ctx).Username
	runs, err := s.dispatchNetSurvey(ctx, *n, who)
	switch {
	case errors.Is(err, errSurveyDisabled), errors.Is(err, errSurveyBusy), errors.Is(err, errSurveyNoTargets):
		http.Error(w, err.Error(), http.StatusConflict)
		return
	case errors.Is(err, errSurveyNoBus):
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(ctx, auditEvent{Action: "discover.survey_run", Actor: who, Target: n.Name, Severity: "notice",
		Detail: map[string]any{"id": n.ID, "agent_ids": n.AgentIDs, "subnets": n.Subnets, "protocols": n.Protocols}})
	writeJSONResponse(w, runNetSurveyResponse{Runs: runs})
}

// dispatchNetSurvey starts one run per endpoint of the survey. Asked for
// by a person, it acts with their reach (the route's gate already checked
// it); started by the schedule, with the reach of whoever created the
// survey, narrowed by the deploy action group, and not at all once that
// account is gone.
func (s *Server) dispatchNetSurvey(ctx context.Context, n store.NetworkSurvey, requestedBy string) ([]netSurveyRunView, error) {
	if !n.Enabled {
		return nil, errSurveyDisabled
	}
	if s.nc == nil {
		return nil, errSurveyNoBus
	}
	if active, err := s.store.SurveyRunActive(ctx, n.ID); err != nil {
		return nil, err
	} else if active {
		return nil, errSurveyBusy
	}
	var cred *proto.NetSurveyCred
	if slices.Contains(n.Protocols, proto.NetSurveySNMP) {
		sec, err := s.openSurveySecrets(&n)
		if err != nil {
			return nil, err
		}
		cred = &proto.NetSurveyCred{Version: n.SNMPVersion, Community: sec.Community, User: n.SNMPUser,
			SecurityLevel: n.SNMPSecurityLevel, AuthProtocol: n.SNMPAuthProtocol, AuthPassphrase: sec.Auth,
			PrivProtocol: n.SNMPPrivProtocol, PrivPassphrase: sec.Priv}
	}
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return nil, err
	}
	byID := map[string]store.AgentRecord{}
	for _, a := range agents {
		byID[a.AgentID] = a
	}
	var targets []string
	for _, id := range n.AgentIDs {
		if a, ok := byID[id]; ok && a.Managed {
			targets = append(targets, id)
		}
	}
	if auth.CurrentUser(ctx) == nil {
		pctx, ok := s.endpointActionPrincipal(ctx, n.CreatedBy)
		if !ok {
			return nil, fmt.Errorf("the survey's creator %q can no longer act on endpoints", n.CreatedBy)
		}
		kept, dropped, err := s.narrowTargets(pctx, "deploy", targets)
		if err != nil {
			return nil, err
		}
		if dropped > 0 {
			s.logger.Info("network survey: endpoints narrowed by access control", "survey", n.Name, "dropped", dropped)
		}
		targets = kept
	}
	if len(targets) == 0 {
		return nil, errSurveyNoTargets
	}
	if err := s.store.MarkNetworkSurveyRun(ctx, n.ID); err != nil {
		return nil, err
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	out := make([]netSurveyRunView, 0, len(targets))
	for _, id := range targets {
		a := byID[id]
		run := store.NetworkSurveyRun{ID: idgen.New("nsr-"), SurveyID: n.ID, AgentID: id, Status: "dispatched",
			RequestedBy: requestedBy, Subnets: n.Subnets, BudgetSeconds: n.BudgetSeconds, StartedAt: time.Now().UTC()}
		if err := s.store.CreateNetworkSurveyRun(ctx, run); err != nil {
			return nil, err
		}
		wg.Add(1)
		go func(a store.AgentRecord, run store.NetworkSurveyRun) {
			defer wg.Done()
			status, detail := s.sendNetSurvey(ctx, a, n, run, cred)
			terminal := status != "running"
			if err := s.store.SetNetworkSurveyRunStatus(context.WithoutCancel(ctx), run.ID, status, detail, terminal); err != nil {
				s.logger.Warn("network survey: could not record a run's status", "run", run.ID, "error", err)
			}
			run.Status, run.Detail = status, detail
			mu.Lock()
			out = append(out, netSurveyRunView{NetworkSurveyRun: run, Hostname: a.Hostname, SurveyName: n.Name})
			mu.Unlock()
		}(a, run)
	}
	wg.Wait()
	slices.SortFunc(out, func(a, b netSurveyRunView) int { return strings.Compare(a.Hostname, b.Hostname) })
	return out, nil
}

// sendNetSurvey hands one endpoint its run and says what became of it:
// running, or why not (no_response, unsupported, failed).
func (s *Server) sendNetSurvey(ctx context.Context, a store.AgentRecord, n store.NetworkSurvey, run store.NetworkSurveyRun, cred *proto.NetSurveyCred) (string, string) {
	if !a.Online {
		return "no_response", "the endpoint is offline; nothing was sent"
	}
	job := proto.NetSurveyJob{RunID: run.ID, SurveyID: n.ID, Name: n.Name, Subnets: n.Subnets, AllowOffLink: n.AllowOffLink,
		Protocols: n.Protocols, PacketsPerSecond: n.PacketsPerSecond, Concurrency: n.Concurrency,
		TimeoutMillis: n.TimeoutMillis, BudgetSeconds: n.BudgetSeconds, SNMP: cred}
	payload, err := json.Marshal(proto.AgentCommand{Cmd: "network_survey", NetSurvey: &job})
	if err != nil {
		return "failed", err.Error()
	}
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	msg, err := s.nc.RequestWithContext(cctx, bnats.Cmd(a.AgentID), payload)
	if err != nil {
		return "no_response", "the endpoint did not answer: " + err.Error()
	}
	var res proto.AgentCommandResult
	if err := json.Unmarshal(msg.Data, &res); err != nil {
		return "failed", "unreadable answer from the endpoint"
	}
	switch {
	case res.OK:
		return "running", ""
	case strings.HasPrefix(res.Error, "unknown command"):
		return "unsupported", "this endpoint's agent predates network surveys; update it"
	default:
		return "failed", safeTruncate(res.Error, 500)
	}
}

// recordNetSurveyReport stores a run's report. A report for a run this
// server did not send to that endpoint is dropped: the run ID is the
// endpoint's only claim, and it must match what was dispatched.
func (s *Server) recordNetSurveyReport(ctx context.Context, snap proto.SensorSnapshot) error {
	var rep proto.NetSurveyReport
	if err := json.Unmarshal(snap.Data, &rep); err != nil {
		return fmt.Errorf("malformed network survey report: %w", err)
	}
	run, err := s.store.GetNetworkSurveyRun(ctx, rep.RunID)
	if err != nil {
		return err
	}
	if run == nil || run.AgentID != snap.AgentID {
		s.logger.Warn("dropping a network survey report for a run this endpoint was not sent", "agent_id", snap.AgentID, "run", rep.RunID)
		return nil
	}
	if run.Status != "dispatched" && run.Status != "running" && run.Status != "timed_out" {
		return nil // a redelivery of a report already recorded
	}
	status, detail, keep, dropped := surveyReportOutcome(*run, rep)
	if dropped > 0 {
		s.logger.Warn("network survey report carried answers outside its subnets", "agent_id", snap.AgentID, "run", run.ID, "dropped", dropped)
	}
	summary, _ := json.Marshal(map[string]any{"refused": rep.Refused, "unsupported": rep.Unsupported, "errors": rep.Errors,
		"truncated": rep.Truncated, "error": rep.Error, "discarded": dropped})
	run.Status, run.Detail, run.HostsPlanned, run.Probes, run.DevicesFound, run.Summary = status, detail, rep.HostsPlanned, rep.Probes, len(keep), summary
	seen := snap.Timestamp
	if seen.IsZero() || seen.After(time.Now().Add(5*time.Minute)) {
		seen = time.Now().UTC()
	}
	devs := make([]store.NetworkSurveyDevice, 0, len(keep))
	for _, d := range keep {
		raw, err := json.Marshal(d)
		if err != nil {
			continue
		}
		devs = append(devs, store.NetworkSurveyDevice{Key: surveyDeviceKey(d), MAC: d.MAC, IP: d.IP, DeviceType: classifyDevice(d),
			Device: raw, AgentID: snap.AgentID, SurveyID: run.SurveyID})
	}
	if err := s.store.FinishNetworkSurveyRun(ctx, *run, devs, seen); err != nil {
		return err
	}
	s.logger.Info("network survey report", "agent_id", snap.AgentID, "run", run.ID, "status", status, "devices", len(devs), "probes", rep.Probes)
	return nil
}

// withSurveyDevices merges what surveys found into Discover's list.
func (s *Server) withSurveyDevices(ctx context.Context, hosts []discoveredHost) []discoveredHost {
	devs, err := s.store.ListNetworkSurveyDevices(ctx)
	if err != nil || len(devs) == 0 {
		return hosts
	}
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return hosts
	}
	byIP, hostnames := managedAddresses(agents)
	return mergeSurveyDevices(hosts, devs, hostnames, byIP)
}

// netSurveyLoop starts scheduled surveys and closes runs whose report is
// overdue. A survey runs again only once its previous run has finished.
func (s *Server) netSurveyLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if n, err := s.store.ExpireNetworkSurveyRuns(ctx, netSurveyGrace); err == nil && n > 0 {
			s.logger.Info("network survey runs timed out without a report", "runs", n)
		}
		surveys, err := s.store.ListNetworkSurveys(ctx)
		if err != nil {
			continue
		}
		for _, n := range surveys {
			next := nextSurveyRun(n)
			if next == nil || next.After(time.Now()) {
				continue
			}
			if _, err := s.dispatchNetSurvey(ctx, n, "schedule"); err != nil {
				if errors.Is(err, errSurveyBusy) || errors.Is(err, errSurveyNoTargets) || errors.Is(err, errSurveyNoBus) {
					continue // still running, or nothing to run on: try next tick
				}
				s.logger.Warn("scheduled network survey failed", "survey", n.Name, "error", err)
				// Do not retry every minute: wait out the interval.
				_ = s.store.MarkNetworkSurveyRun(ctx, n.ID)
			}
		}
	}
}
