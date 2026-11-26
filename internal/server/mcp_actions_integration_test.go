package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

type mcpFixture struct {
	t         *testing.T
	ctx       context.Context
	st        *store.Store
	s         *Server
	requester *store.User
	approver  *store.User
	agent     string
	host      string
}

func newMCPFixture(t *testing.T) *mcpFixture {
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	s := &Server{logger: slog.Default(), store: st, live: &liveConfig{staleAfter: time.Hour}, syslog: &syslogSink{}}
	s.auth = auth.New(ctx, st, nil, false, slog.Default())
	s.routes()
	f := &mcpFixture{t: t, ctx: ctx, st: st, s: s}
	f.requester = f.user(auth.PermFleetRead, auth.PermDeployManage, auth.PermPatchesManage)
	f.approver = f.user(auth.PermFleetRead, auth.PermApprovalsDecide)
	f.host = idgen.New("mcpa-")
	f.agent = "agt-" + f.host
	if err := st.UpsertOnRegister(ctx, f.agent, proto.AgentInfo{Hostname: f.host, OS: "linux"}); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordHeartbeat(ctx, f.agent, time.Now()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteAgent(context.Background(), f.agent) })
	return f
}

func (f *mcpFixture) user(perms ...string) *store.User {
	f.t.Helper()
	u, err := f.st.CreateLocalUser(f.ctx, idgen.New("usr-"), idgen.New("mcp-"), "", "mcp test")
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = f.st.DeleteUser(context.Background(), u.ID) })
	role, err := f.st.CreateRole(f.ctx, idgen.New("role-"), idgen.New("mcp-role-"), "", perms, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = f.st.DeleteRole(context.Background(), role.ID) })
	if err := f.st.AssignUserRole(f.ctx, u.ID, role.ID); err != nil {
		f.t.Fatal(err)
	}
	return u
}

// token stores an API token made by creator and returns its ID and secret.
func (f *mcpFixture) token(creator *store.User, mcpOnly bool, perms ...string) (string, string) {
	f.t.Helper()
	secret, prefix, err := auth.GenerateToken()
	if err != nil {
		f.t.Fatal(err)
	}
	hash, err := auth.HashToken(secret)
	if err != nil {
		f.t.Fatal(err)
	}
	id := idgen.New("tok-")
	if err := f.st.CreateAPIToken(f.ctx, store.APIToken{ID: id, Name: idgen.New("mcp-tok-"), Prefix: prefix, Permissions: perms,
		CreatedBy: creator.Username, CreatedByID: creator.ID, MCPOnly: mcpOnly}, hash); err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = f.st.DeleteAPIToken(context.Background(), id) })
	return id, secret
}

func (f *mcpFixture) call(ctx context.Context, tool, args string) map[string]any {
	f.t.Helper()
	res, rpcErr := mcpResult(f.t, mcpCallAs(f.t, f.s, ctx, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"`+tool+`","arguments":`+args+`}}`))
	if rpcErr != nil {
		f.t.Fatalf("%s: %v", tool, rpcErr)
	}
	return res
}

func toolText(res map[string]any) string {
	return res["content"].([]any)[0].(map[string]any)["text"].(string)
}

func (f *mcpFixture) pending() map[string]store.ApprovalRequest {
	f.t.Helper()
	list, err := f.st.ListApprovalRequests(f.ctx, "pending", 1000)
	if err != nil {
		f.t.Fatal(err)
	}
	out := map[string]store.ApprovalRequest{}
	for _, a := range list {
		out[a.ID] = a
	}
	return out
}

// The action tools file approval requests and never act: nothing is
// dispatched, nothing starts, and the request names who asked and through
// which token. The requester, by name, through the token or through
// another token of theirs, cannot approve it; somebody else can.
func TestMCPActionToolsFileApprovalsAndNeverRun(t *testing.T) {
	f := newMCPFixture(t)
	ctx := f.ctx
	pbID := idgen.New("pb-")
	if err := f.st.UpsertPlaybook(ctx, store.Playbook{ID: pbID, Name: idgen.New("mcp playbook "), OS: "linux", Enabled: true,
		Steps: json.RawMessage(`[{"type":"reboot","name":"Reboot"}]`), UpdatedBy: "test"}, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.st.DeletePlaybook(context.Background(), pbID) })
	runsBefore, _ := f.st.ListPatchJobRuns(ctx, 1000)

	tokID, _ := f.token(f.requester, true, auth.PermFleetRead, auth.PermDeployManage, auth.PermPatchesManage)
	tokCtx, err := f.s.auth.TokenContext(ctx, tokID)
	if err != nil {
		t.Fatal(err)
	}

	res := f.call(tokCtx, "request_playbook_run", `{"playbook":"`+pbID+`","hostnames":["`+strings.ToUpper(f.host)+`"],"reason":"kernel update"}`)
	if res["isError"] == true {
		t.Fatalf("request_playbook_run: %s", toolText(res))
	}
	var filed mcpFiled
	if err := json.Unmarshal([]byte(toolText(res)), &filed); err != nil {
		t.Fatal(err)
	}
	req, ok := f.pending()[filed.RequestID]
	if !ok {
		t.Fatalf("no pending approval %s", filed.RequestID)
	}
	if req.TokenID != tokID || req.RequesterID != f.requester.ID || req.PolicyID != mcpRequestPolicyID ||
		req.Module != "playbooks" || req.DeviceCount != 1 || req.Path != "/api/playbooks/"+pbID+"/run" ||
		!strings.Contains(req.Summary, "kernel update") || !strings.Contains(filed.ApproveURL, "/approve?kind=approval&id="+req.ID) {
		t.Errorf("filed request: %+v / %+v", req, filed)
	}
	var parked parkedRequest
	_ = json.Unmarshal(req.Body, &parked)
	var body runPlaybookRequest
	_ = json.Unmarshal(parked.Body, &body)
	if parked.Handler != "playbooks.run" || len(body.AgentIDs) != 1 || body.AgentIDs[0] != f.agent || parked.PathValues["id"] != pbID {
		t.Errorf("parked: %+v body %+v", parked, body)
	}

	// Asking again files nothing new.
	again := f.call(tokCtx, "request_playbook_run", `{"playbook":"`+pbID+`","hostnames":["`+f.host+`"],"reason":"kernel update"}`)
	var dup mcpFiled
	_ = json.Unmarshal([]byte(toolText(again)), &dup)
	if dup.RequestID != req.ID || !dup.AlreadyPending {
		t.Errorf("repeat filed a second request: %+v", dup)
	}

	// Patches and packages, to named endpoints only.
	patch := f.call(tokCtx, "request_patch_deployment", `{"agent_ids":["`+f.agent+`"],"packages":["openssl"]}`)
	if patch["isError"] == true {
		t.Fatalf("request_patch_deployment: %s", toolText(patch))
	}
	var pf mcpFiled
	_ = json.Unmarshal([]byte(toolText(patch)), &pf)
	_ = json.Unmarshal(f.pending()[pf.RequestID].Body, &parked)
	var pbody deployPatchesRequest
	_ = json.Unmarshal(parked.Body, &pbody)
	if parked.Handler != "patches.deploy" || len(pbody.TargetAgents) != 1 || pbody.OnlyPackages[f.agent][0] != "openssl" {
		t.Errorf("patch request: %+v %+v", parked, pbody)
	}
	if res := f.call(tokCtx, "request_patch_deployment", `{}`); res["isError"] != true || !strings.Contains(toolText(res), "whole fleet") {
		t.Errorf("a patch request without endpoints was accepted: %v", res)
	}
	if res := f.call(tokCtx, "request_package_deployment", `{"package":"no-such-package","operation":"install","agent_ids":["`+f.agent+`"]}`); res["isError"] != true {
		t.Errorf("unknown package accepted: %v", res)
	}

	// Nothing ran.
	runsAfter, _ := f.st.ListPatchJobRuns(ctx, 1000)
	if len(runsAfter) != len(runsBefore) {
		t.Errorf("filing a request started %d deployment(s)", len(runsAfter)-len(runsBefore))
	}
	if pbRuns, _ := f.st.ListPlaybookRuns(ctx, 1000); len(pbRuns) > 0 {
		for _, r := range pbRuns {
			if r.PlaybookID == pbID {
				t.Errorf("filing a request started playbook run %s", r.ID)
			}
		}
	}

	// Self-approval, three ways, then somebody else.
	decide := func(c context.Context) int {
		r := httptest.NewRequestWithContext(c, http.MethodPost, "/api/approvals/"+req.ID+"/decide", strings.NewReader(`{"decision":"deny"}`))
		r.SetPathValue("id", req.ID)
		rec := httptest.NewRecorder()
		f.s.handleDecideApproval(rec, r)
		return rec.Code
	}
	otherTok, _ := f.token(f.requester, false, auth.PermApprovalsDecide)
	otherCtx, err := f.s.auth.TokenContext(ctx, otherTok)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]context.Context{
		"the requester":           auth.WithUser(ctx, f.requester),
		"the token that asked":    tokCtx,
		"another of their tokens": otherCtx,
	} {
		if code := decide(c); code != http.StatusForbidden {
			t.Errorf("%s decided their own request: %d", name, code)
		}
	}
	if code := decide(auth.WithUser(ctx, f.approver)); code != http.StatusOK {
		t.Errorf("another person could not decide it: %d", code)
	}
}

// Approving a token's request replays it as that token, and not at all
// once the token is revoked.
func TestMCPApprovedRequestRunsAsTheToken(t *testing.T) {
	f := newMCPFixture(t)
	tokID, _ := f.token(f.requester, true, auth.PermFleetRead, auth.PermDeployManage)
	tokCtx, err := f.s.auth.TokenContext(f.ctx, tokID)
	if err != nil {
		t.Fatal(err)
	}
	pbID := idgen.New("pb-")
	if err := f.st.UpsertPlaybook(f.ctx, store.Playbook{ID: pbID, Name: idgen.New("mcp replay "), OS: "linux", Enabled: true,
		Steps: json.RawMessage(`[{"type":"reboot","name":"Reboot"}]`), UpdatedBy: "test"}, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.st.DeletePlaybook(context.Background(), pbID) })
	res := f.call(tokCtx, "request_playbook_run", `{"playbook":"`+pbID+`","agent_ids":["`+f.agent+`"]}`)
	var filed mcpFiled
	_ = json.Unmarshal([]byte(toolText(res)), &filed)
	req, err := f.st.GetApprovalRequest(f.ctx, filed.RequestID)
	if err != nil || req == nil {
		t.Fatalf("%v %v (%s)", req, err, toolText(res))
	}
	if err := f.st.RevokeAPIToken(f.ctx, tokID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.DecideApprovalRequest(f.ctx, req.ID, "approved", f.approver.Username, ""); err != nil {
		t.Fatal(err)
	}
	f.s.runApproved(f.ctx, *req)
	done, _ := f.st.GetApprovalRequest(f.ctx, req.ID)
	if done.State != "failed" || !strings.Contains(done.Outcome, "no longer live") {
		t.Errorf("a revoked token's request replayed: %s %s", done.State, done.Outcome)
	}
	if _, err := f.s.auth.TokenContext(f.ctx, tokID); err == nil {
		t.Error("TokenContext accepted a revoked token")
	}
}

// A deleted target group never widens to the fleet: a playbook that lost
// its group cannot be requested, and naming a group that does not exist
// files nothing.
func TestMCPDeletedGroupNeverWidens(t *testing.T) {
	f := newMCPFixture(t)
	ctx := auth.WithUser(f.ctx, f.requester)
	g, err := f.st.UpsertComputerGroup(f.ctx, store.ComputerGroup{ID: idgen.New("grp-"), Name: idgen.New("mcp group "), Kind: "static",
		MatchMode: "all", MemberIDs: []string{f.agent}, CreatedBy: "test"})
	if err != nil {
		t.Fatal(err)
	}
	pbID := idgen.New("pb-")
	if err := f.st.UpsertPlaybook(f.ctx, store.Playbook{ID: pbID, Name: idgen.New("mcp grouped "), GroupID: g.ID, Enabled: true,
		Steps: json.RawMessage(`[{"type":"reboot","name":"Reboot"}]`), UpdatedBy: "test"}, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.st.DeletePlaybook(context.Background(), pbID) })
	if _, _, err := f.st.DeleteComputerGroupAndOrphans(f.ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	f.s.invalidateAccess()
	before := len(f.pending())
	if res := f.call(ctx, "request_playbook_run", `{"playbook":"`+pbID+`"}`); res["isError"] != true || !strings.Contains(toolText(res), "deleted") {
		t.Errorf("a playbook whose group was deleted was requested: %v", res)
	}
	for _, tool := range []string{"request_playbook_run", "request_patch_deployment", "request_package_deployment"} {
		res := f.call(ctx, tool, `{"playbook":"`+pbID+`","package":"x","operation":"install","group":"`+g.ID+`"}`)
		if res["isError"] != true {
			t.Errorf("%s accepted a deleted group: %v", tool, res)
		}
	}
	if after := len(f.pending()); after != before {
		t.Errorf("%d request(s) filed for a deleted group", after-before)
	}
}

// An MCP-only token reaches /api/mcp and nothing else.
func TestMCPOnlyTokenIsConfined(t *testing.T) {
	f := newMCPFixture(t)
	_, secret := f.token(f.requester, true, auth.PermFleetRead, auth.PermDeployManage)
	_, plain := f.token(f.requester, false, auth.PermFleetRead)
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })
	h := f.s.auth.RequireAuth(ok)
	get := func(secret, path string) int {
		r := httptest.NewRequest(http.MethodPost, path, nil)
		r.Header.Set("Authorization", "Bearer "+secret)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}
	if code := get(secret, "/api/mcp"); code != http.StatusTeapot {
		t.Errorf("MCP-only token refused at /api/mcp: %d", code)
	}
	for _, p := range []string{"/api/agents", "/api/playbooks/x/run", "/api/mcp/../agents", "/"} {
		if code := get(secret, p); code != http.StatusForbidden {
			t.Errorf("MCP-only token reached %s: %d", p, code)
		}
	}
	if code := get(plain, "/api/agents"); code != http.StatusTeapot {
		t.Errorf("an ordinary token was refused: %d", code)
	}
}

// Read tools see what the route shows the caller: a read-only token gets
// endpoints and a sensor answer, with limits applied.
func TestMCPReadToolsAnswer(t *testing.T) {
	f := newMCPFixture(t)
	raw, _ := json.Marshal([]map[string]any{{"pid": 1, "name": "init"}, {"pid": 2, "name": "kthreadd"}, {"pid": 3, "name": "sshd"}})
	if err := f.st.UpsertSensorData(f.ctx, f.agent, string(proto.SensorProcesses), time.Now(), raw); err != nil {
		t.Fatal(err)
	}
	ctx := mcpTokenCtx(auth.PermFleetRead)
	list := f.call(ctx, "list_endpoints", `{"search":"`+f.host+`"}`)
	var eps mcpEndpointList
	if err := json.Unmarshal([]byte(toolText(list)), &eps); err != nil || eps.Total != 1 || eps.Endpoints[0].AgentID != f.agent || !eps.Endpoints[0].Online {
		t.Errorf("list_endpoints: %s", toolText(list))
	}
	sensor := f.call(ctx, "get_sensor", `{"hostname":"`+f.host+`","sensor":"processes","limit":2}`)
	var ans mcpSensorAnswer
	if err := json.Unmarshal([]byte(toolText(sensor)), &ans); err != nil || ans.Rows != 3 || !ans.Truncated {
		t.Errorf("get_sensor: %s", toolText(sensor))
	}
	for _, tool := range []string{"get_endpoint", "list_vulnerabilities", "get_hardening", "list_enforce_drift"} {
		if res := f.call(ctx, tool, `{"agent_id":"`+f.agent+`"}`); res["isError"] == true {
			t.Errorf("%s: %s", tool, toolText(res))
		}
	}
	for _, tool := range []string{"list_groups", "list_deployments", "get_needs_attention", "list_notifications", "list_playbooks", "list_packages"} {
		if res := f.call(ctx, tool, `{}`); res["isError"] == true {
			t.Errorf("%s: %s", tool, toolText(res))
		}
	}
	if res := f.call(ctx, "get_deployment", `{"id":"run-none"}`); res["isError"] != true {
		t.Errorf("get_deployment of nothing: %v", res)
	}
}
