package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// The MCP action tools. None of them acts. Each checks what the action
// itself would check up front (the permission, the endpoints' reach, the
// package's content set), so a request nobody could carry out is refused
// now rather than approved for nothing, and then files an approval request
// through the same mechanism approval policies use: the operation stored
// verbatim, attributed to whoever called the tool, decidable by somebody
// else with approvals.decide, replayed as the requester when approved and
// expiring after eight hours. Approval policies decide which console
// operations wait; a model's request always waits, whatever they say and
// even for an approval-exempt token.

// mcpRequestPolicy is the policy name an MCP-filed request carries, in
// place of the approval policy a console request would name.
const mcpRequestPolicyID = "ai"

type mcpViaKey struct{}

// withMCPVia names, for the approval request and its audit row, what
// filed a request: an AI client over MCP unless the caller says otherwise.
func withMCPVia(ctx context.Context, via string) context.Context {
	return context.WithValue(ctx, mcpViaKey{}, via)
}

func mcpVia(ctx context.Context) string {
	if v, ok := ctx.Value(mcpViaKey{}).(string); ok && v != "" {
		return v
	}
	return "an AI client (MCP)"
}

// mcpFiling is one operation to park for a decision.
type mcpFiling struct {
	Tool       string
	Module     string // access module: deploy, patches, playbooks
	Handler    string // a key of replayable()
	Path       string // the route the operation is, replayed on approval
	PathValues map[string]string
	Summary    string
	Reason     string
	AgentIDs   []string
	Body       any
}

// mcpFiled is what an action tool answers.
type mcpFiled struct {
	RequestID      string    `json:"request_id"`
	State          string    `json:"state"`
	AlreadyPending bool      `json:"already_pending,omitempty"`
	Summary        string    `json:"summary"`
	Endpoints      int       `json:"endpoints"`
	Hostnames      []string  `json:"hostnames,omitempty"`
	ExpiresAt      time.Time `json:"expires_at"`
	ApproveURL     string    `json:"approve_url"`
	Message        string    `json:"message"`
}

// mcpFileRequest files f as an approval request from the caller. A request
// identical to one the same caller already has pending is not filed twice:
// a model that retries gets the first one back.
func (s *Server) mcpFileRequest(ctx context.Context, f mcpFiling) (any, *mcpError) {
	if _, ok := s.replayable()[f.Handler]; !ok {
		// A request nobody could carry out once approved must not be filed.
		return nil, &mcpError{mcpInternalError, f.Tool + " cannot be filed for approval"}
	}
	u := auth.CurrentUser(ctx)
	if u == nil {
		return mcpToolError("no caller identity"), nil
	}
	raw, err := json.Marshal(f.Body)
	if err != nil {
		return nil, &mcpError{mcpInternalError, "could not encode the request"}
	}
	parked, _ := json.Marshal(parkedRequest{Handler: f.Handler, Body: raw, PathValues: f.PathValues})
	summary := f.Summary
	if r := strings.TrimSpace(f.Reason); r != "" {
		summary += " — " + clip(r, 300)
	}
	requesterID, tokenID := approvalRequester(ctx)
	hosts := s.mcpHostnames(ctx, f.AgentIDs)

	pending, err := s.store.ListApprovalRequests(ctx, "pending", 200)
	if err != nil {
		s.logger.Error("mcp: listing pending approvals failed", "error", err)
		return nil, &mcpError{mcpInternalError, "could not read pending approvals"}
	}
	for _, p := range pending {
		if p.RequestedBy == u.Username && p.TokenID == tokenID && p.Path == f.Path && bytes.Equal(p.Body, parked) &&
			(p.ExpiresAt == nil || time.Now().Before(*p.ExpiresAt)) {
			out := s.mcpFiledAnswer(ctx, p, hosts)
			out.AlreadyPending = true
			out.Message = "An identical request is already waiting for approval; nothing new was filed. " + out.Message
			return mcpToolResult(out)
		}
	}

	expires := time.Now().Add(approvalWindow)
	via := mcpVia(ctx)
	req := store.ApprovalRequest{
		ID: idgen.New("apr-"), PolicyID: mcpRequestPolicyID, PolicyName: "Asked for by " + via, Module: f.Module,
		Summary: summary, Method: http.MethodPost, Path: f.Path, Body: parked,
		AgentIDs: f.AgentIDs, DeviceCount: len(f.AgentIDs), RequestedBy: u.Username, ExpiresAt: &expires,
		RequesterID: requesterID, TokenID: tokenID, State: "pending",
	}
	// Written before the request exists, like every endpoint action's row:
	// a request that cannot be attributed is not filed.
	detail := map[string]any{"request_id": req.ID, "via": via, "tool": f.Tool, "devices": len(f.AgentIDs)}
	if tokenID != "" {
		detail["token"] = tokenID
	}
	if f.Reason != "" {
		detail["reason"] = clip(f.Reason, 300)
	}
	if err := s.auditStrict(ctx, auditEvent{Action: f.Module + ".approval_requested", Actor: u.Username, Target: summary,
		Severity: "notice", Detail: detail}); err != nil {
		s.logger.Error("mcp: audit write failed; request not filed", "error", err)
		return nil, &mcpError{mcpInternalError, "could not record the request in the audit log, so it was not filed"}
	}
	if err := s.store.CreateApprovalRequest(ctx, req); err != nil {
		s.logger.Error("mcp: filing approval request failed", "error", err)
		return nil, &mcpError{mcpInternalError, "could not file the request"}
	}
	s.notifyRequest(ctx, "notice", "Approvals", u.Username+" (through "+via+") is asking for approval: "+summary,
		fmt.Sprintf("%s · %d endpoint(s)", f.Module, len(f.AgentIDs)), "/access#approvals", "approval", req.ID, true)
	s.logger.Info("mcp action request filed", "request", req.ID, "tool", f.Tool, "requested_by", u.Username, "endpoints", len(f.AgentIDs))
	return mcpToolResult(s.mcpFiledAnswer(ctx, req, hosts))
}

func (s *Server) mcpFiledAnswer(ctx context.Context, req store.ApprovalRequest, hosts []string) mcpFiled {
	link := "/approve?kind=approval&id=" + url.QueryEscape(req.ID)
	if base, err := s.agentPublicURLOrEmpty(ctx); err == nil && base != "" {
		link = strings.TrimRight(base, "/") + link
	}
	out := mcpFiled{RequestID: req.ID, State: "pending", Summary: req.Summary, Endpoints: req.DeviceCount, Hostnames: hosts,
		ApproveURL: link,
		Message: "Nothing has run. This is waiting for somebody other than the requester, holding approvals.decide, to approve it in the mustra console (Access → Approvals, or the link). " +
			"Once approved it runs as the requester, with the targeting and checks of the moment it runs; it expires if nobody decides within eight hours."}
	if req.ExpiresAt != nil {
		out.ExpiresAt = *req.ExpiresAt
	}
	return out
}

// mcpHostnames names up to ten endpoints, for the answer.
func (s *Server) mcpHostnames(ctx context.Context, ids []string) []string {
	if len(ids) == 0 || s.store == nil {
		return nil
	}
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return nil
	}
	want := idSet(ids)
	var out []string
	for _, a := range agents {
		if want[a.AgentID] {
			out = append(out, a.Hostname)
		}
	}
	slices.Sort(out)
	if len(out) > 10 {
		out = append(out[:10], fmt.Sprintf("and %d more", len(out)-10))
	}
	return out
}

// mcpTargets resolves an action tool's endpoints: agent IDs, hostnames
// and a computer group, together. Every name must resolve: a hostname
// that matches nothing or several endpoints, or a group that does not
// exist, is refused rather than dropped, and a group never stands for the
// fleet. explicit reports whether anything was named at all.
func (s *Server) mcpTargets(ctx context.Context, tool string, agentIDs, hostnames []string, group string) (ids []string, explicit bool, res any, rpc *mcpError) {
	if len(agentIDs) == 0 && len(hostnames) == 0 && group == "" {
		return nil, false, nil, nil
	}
	agents, e := s.mcpAgents(ctx)
	if e != nil {
		res, rpc = s.mcpRouteFailure(tool, e)
		return nil, true, res, rpc
	}
	byID := map[string]bool{}
	byHost := map[string][]string{}
	for _, a := range agents {
		byID[a.AgentID] = true
		byHost[strings.ToLower(a.Hostname)] = append(byHost[strings.ToLower(a.Hostname)], a.AgentID)
	}
	seen := map[string]bool{}
	add := func(id string) {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	for _, id := range agentIDs {
		if !byID[id] {
			return nil, true, mcpToolError("no endpoint has the agent ID " + id), nil
		}
		add(id)
	}
	for _, h := range hostnames {
		switch m := byHost[strings.ToLower(h)]; len(m) {
		case 0:
			return nil, true, mcpToolError("no endpoint is called " + h), nil
		case 1:
			add(m[0])
		default:
			return nil, true, mcpToolError("several endpoints are called " + h + "; give agent_ids (" + strings.Join(m, ", ") + ")"), nil
		}
	}
	if group != "" {
		name, members, gres, grpc := s.mcpGroup(ctx, tool, group)
		if gres != nil || grpc != nil {
			return nil, true, gres, grpc
		}
		if len(members) == 0 {
			return nil, true, mcpToolError("the group " + name + " has no endpoints in it right now"), nil
		}
		var gids []string
		for id := range members {
			gids = append(gids, id)
		}
		slices.Sort(gids)
		for _, id := range gids {
			add(id)
		}
	}
	return ids, true, nil, nil
}

// mcpCheckReach refuses endpoints outside the caller's management rights
// or the module's action group, exactly as the action's route would, and
// records the refusal the same way.
func (s *Server) mcpCheckReach(ctx context.Context, module string, ids []string) any {
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, auth.MCPPath, nil)
	if err != nil {
		return mcpToolError("could not check access")
	}
	rec := &captureWriter{header: http.Header{}}
	if !s.checkTargets(rec, r, module, ids) {
		return mcpToolError(strings.TrimSpace(rec.body.String()))
	}
	return nil
}

var mcpTargetProps = map[string]any{
	"agent_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "endpoints, by agent ID"},
	"hostnames": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "endpoints, by hostname"},
	"group":     map[string]any{"type": "string", "description": "a computer group, by ID or name: its members right now"},
	"reason":    map[string]any{"type": "string", "description": "why, in a sentence, for whoever decides"},
}

const mcpActionNote = " This does not run anything: it files an approval request that somebody else decides in the mustra console, and answers with its ID and a link. Tell the user it is waiting for approval."

var mcpActionTools = []mcpTool{
	{
		Name:  "request_playbook_run",
		Title: "Ask to run a playbook",
		Description: "Files a request to run a playbook on the endpoints it targets, or on some of them: agent_ids, hostnames or group narrow the run to those of its targets, never wider. " +
			"A playbook whose computer group was deleted targets nothing and cannot be requested." + mcpActionNote,
		Properties: withProps(mcpTargetProps, map[string]any{
			"playbook": map[string]any{"type": "string", "description": "the playbook, by ID or exact name (list_playbooks)"},
		}),
		Required:   []string{"playbook"},
		Permission: auth.PermDeployManage,
		Action:     true,
		Call: func(ctx context.Context, s *Server, args json.RawMessage) (any, *mcpError) {
			return s.mcpRequestPlaybookRun(ctx, args)
		},
	},
	{
		Name:  "request_package_deployment",
		Title: "Ask to deploy a catalog package",
		Description: "Files a request to install, update or remove a software package, or run an action package, from the catalog on named endpoints. " +
			"Endpoints must be named (agent_ids, hostnames or group); this never targets the whole fleet. Endpoints the package does not apply to are skipped when it runs." + mcpActionNote,
		Properties: withProps(mcpTargetProps, map[string]any{
			"package":    map[string]any{"type": "string", "description": "the package, by ID or exact name (list_packages)"},
			"operation":  map[string]any{"type": "string", "enum": []string{"install", "update", "remove", "run"}, "description": "run is for action packages"},
			"parameters": map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "values for the package's parameters, by name"},
		}),
		Required:   []string{"package", "operation"},
		Permission: auth.PermDeployManage,
		Action:     true,
		Call: func(ctx context.Context, s *Server, args json.RawMessage) (any, *mcpError) {
			return s.mcpRequestPackageDeployment(ctx, args)
		},
	},
	{
		Name:  "request_patch_deployment",
		Title: "Ask to apply patches",
		Description: "Files a request to install pending OS and package updates on named endpoints, within what their patch lists allow; packages narrows it to those packages. " +
			"Endpoints must be named (agent_ids, hostnames or group); offline endpoints are skipped when it runs." + mcpActionNote,
		Properties: withProps(mcpTargetProps, map[string]any{
			"packages": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "only these packages' updates (names as list_pending_updates shows them)"},
		}),
		Permission: auth.PermPatchesManage,
		Action:     true,
		Call: func(ctx context.Context, s *Server, args json.RawMessage) (any, *mcpError) {
			return s.mcpRequestPatchDeployment(ctx, args)
		},
	},
}

type mcpTargetArgs struct {
	AgentIDs  []string `json:"agent_ids"`
	Hostnames []string `json:"hostnames"`
	Group     string   `json:"group"`
	Reason    string   `json:"reason"`
}

func (s *Server) mcpRequestPlaybookRun(ctx context.Context, raw json.RawMessage) (any, *mcpError) {
	var args struct {
		mcpTargetArgs
		Playbook string `json:"playbook"`
	}
	if !mcpDecode(raw, &args) || args.Playbook == "" {
		return mcpToolError("playbook is required; list_playbooks shows them"), nil
	}
	list, err := s.store.ListPlaybooks(ctx)
	if err != nil {
		s.logger.Error("mcp request_playbook_run failed", "error", err)
		return nil, &mcpError{mcpInternalError, "could not read playbooks"}
	}
	var pb *store.Playbook
	for i := range list {
		if list[i].ID == args.Playbook || strings.EqualFold(list[i].Name, args.Playbook) {
			pb = &list[i]
			break
		}
	}
	if pb == nil {
		return mcpToolError("no playbook called " + args.Playbook + "; list_playbooks shows them"), nil
	}
	if pb.GroupDeleted {
		return mcpToolError("the playbook " + pb.Name + " targeted a computer group that was deleted, so it targets nothing until somebody chooses again"), nil
	}
	only, explicit, res, rpc := s.mcpTargets(ctx, "request_playbook_run", args.AgentIDs, args.Hostnames, args.Group)
	if res != nil || rpc != nil {
		return res, rpc
	}
	planned, err := s.playbookTargets(ctx, *pb)
	if err != nil {
		s.logger.Error("mcp request_playbook_run failed", "error", err)
		return nil, &mcpError{mcpInternalError, "could not resolve the playbook's targets"}
	}
	keep := idSet(only)
	var ids []string
	for _, a := range planned {
		if explicit && !keep[a.AgentID] {
			continue
		}
		ids = append(ids, a.AgentID)
	}
	if len(ids) == 0 {
		if explicit {
			return mcpToolError("none of those endpoints is an online endpoint the playbook " + pb.Name + " targets (" + playbookTargetDesc(*pb) + ")"), nil
		}
		return mcpToolError("no online endpoint matches the playbook " + pb.Name + "'s targeting (" + playbookTargetDesc(*pb) + ")"), nil
	}
	if bad := s.mcpCheckReach(ctx, "playbooks", ids); bad != nil {
		return bad, nil
	}
	body := runPlaybookRequest{}
	if explicit {
		body.AgentIDs = ids
	}
	return s.mcpFileRequest(ctx, mcpFiling{
		Tool: "request_playbook_run", Module: "playbooks", Handler: "playbooks.run",
		Path: "/api/playbooks/" + pb.ID + "/run", PathValues: map[string]string{"id": pb.ID},
		Summary: fmt.Sprintf("run playbook %s on %d endpoint(s)", pb.Name, len(ids)), Reason: args.Reason,
		AgentIDs: ids, Body: body,
	})
}

func (s *Server) mcpRequestPackageDeployment(ctx context.Context, raw json.RawMessage) (any, *mcpError) {
	var args struct {
		mcpTargetArgs
		Package    string            `json:"package"`
		Operation  string            `json:"operation"`
		Parameters map[string]string `json:"parameters"`
	}
	if !mcpDecode(raw, &args) || args.Package == "" {
		return mcpToolError("package and operation are required; list_packages shows packages"), nil
	}
	if !slices.Contains([]string{"install", "update", "remove", "run"}, args.Operation) {
		return mcpToolError("operation must be install, update, remove or run"), nil
	}
	pkgs, err := s.store.ListSoftwarePackages(ctx)
	if err != nil {
		s.logger.Error("mcp request_package_deployment failed", "error", err)
		return nil, &mcpError{mcpInternalError, "could not read the catalog"}
	}
	var pkg *store.SoftwarePackage
	for i := range pkgs {
		if pkgs[i].ID == args.Package || strings.EqualFold(pkgs[i].Name, args.Package) {
			pkg = &pkgs[i]
			break
		}
	}
	if pkg == nil {
		return mcpToolError("no package called " + args.Package + "; list_packages shows them"), nil
	}
	if ok, err := s.contentAllowed(ctx, "packages", pkg.ID); err != nil {
		return nil, &mcpError{mcpInternalError, "could not check content sets"}
	} else if !ok {
		return mcpToolError(pkg.Name + " is not in a content set your roles grant"), nil
	}
	if args.Operation == "run" && pkg.DeployRevision == "" && pkg.Kind != store.KindAction {
		return mcpToolError(`"run" applies to action packages; use install, update or remove for software`), nil
	}
	if pkg.DeployRevision == "" && len(pkg.Commands) == 0 {
		return mcpToolError(pkg.Name + " has nothing published to run yet"), nil
	}
	if pkg.DeployRevision == "" && len(pkg.Parameters) > 0 {
		if _, perr := resolveParameters(pkg.Parameters, args.Parameters); perr != nil {
			return mcpToolError(perr.Error()), nil
		}
	}
	ids, explicit, res, rpc := s.mcpTargets(ctx, "request_package_deployment", args.AgentIDs, args.Hostnames, args.Group)
	if res != nil || rpc != nil {
		return res, rpc
	}
	// An empty list means every eligible endpoint to the deploy route, so
	// a request must name endpoints and the list it files is never empty.
	if !explicit || len(ids) == 0 {
		return mcpToolError("name the endpoints (agent_ids, hostnames or group); a request never targets the whole fleet"), nil
	}
	if bad := s.mcpCheckReach(ctx, "deploy", ids); bad != nil {
		return bad, nil
	}
	return s.mcpFileRequest(ctx, mcpFiling{
		Tool: "request_package_deployment", Module: "deploy", Handler: "software.deploy", Path: "/api/software/deploy",
		Summary: fmt.Sprintf("%s %s on %d endpoint(s)", args.Operation, pkg.Name, len(ids)), Reason: args.Reason,
		AgentIDs: ids,
		Body:     softwareDeployRequest{PackageID: pkg.ID, Operation: args.Operation, AgentIDs: ids, Parameters: args.Parameters},
	})
}

func (s *Server) mcpRequestPatchDeployment(ctx context.Context, raw json.RawMessage) (any, *mcpError) {
	var args struct {
		mcpTargetArgs
		Packages []string `json:"packages"`
	}
	if !mcpDecode(raw, &args) {
		return mcpSchemaError(), nil
	}
	ids, explicit, res, rpc := s.mcpTargets(ctx, "request_patch_deployment", args.AgentIDs, args.Hostnames, args.Group)
	if res != nil || rpc != nil {
		return res, rpc
	}
	if !explicit || len(ids) == 0 {
		return mcpToolError("name the endpoints (agent_ids, hostnames or group); a request never targets the whole fleet"), nil
	}
	if bad := s.mcpCheckReach(ctx, "patches", ids); bad != nil {
		return bad, nil
	}
	body := deployPatchesRequest{TargetAgents: ids}
	what := "all pending updates"
	if len(args.Packages) > 0 {
		body.OnlyPackages = map[string][]string{}
		for _, id := range ids {
			body.OnlyPackages[id] = args.Packages
		}
		what = strings.Join(args.Packages, ", ")
		if len(what) > 120 {
			what = fmt.Sprintf("%d packages", len(args.Packages))
		}
	}
	return s.mcpFileRequest(ctx, mcpFiling{
		Tool: "request_patch_deployment", Module: "patches", Handler: "patches.deploy", Path: "/api/patches/deploy",
		Summary: fmt.Sprintf("patch %d endpoint(s): %s", len(ids), what), Reason: args.Reason,
		AgentIDs: ids, Body: body,
	})
}
