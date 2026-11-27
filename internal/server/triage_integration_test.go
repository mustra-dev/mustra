package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// triageHarness is a server over the disposable database whose deploy and
// playbook routes are stubs registered the way httpapi.go registers the
// real ones (permission check, then the shared gate), recording the body
// each call reached the handler with.
type triageHarness struct {
	t     *testing.T
	ctx   context.Context
	st    *store.Store
	s     *Server
	mu    sync.Mutex
	calls []stubCall
	// outcome is the status the stubbed playbook run finishes with.
	outcome string
	tag     string
}

type stubCall struct {
	pattern  string
	agentIDs []string
}

func newTriageHarness(t *testing.T) *triageHarness {
	t.Helper()
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
	s := &Server{logger: slog.Default(), store: st, live: &liveConfig{staleAfter: 2 * time.Minute}, syslog: &syslogSink{}}
	s.auth = auth.New(ctx, st, nil, false, slog.Default())
	h := &triageHarness{t: t, ctx: ctx, st: st, s: s, outcome: "succeeded", tag: strings.TrimPrefix(idgen.New("x"), "x")[:8]}

	tbl := s.newRouteTable()
	wrap := func(next http.Handler) http.Handler { return s.auth.RequirePermission(auth.PermDeployManage)(next) }
	register := func(pattern string, fn http.HandlerFunc) {
		tbl.Handle(pattern, &permGuard{perms: []string{auth.PermDeployManage}, check: wrap(fn), next: fn, wrap: wrap})
	}
	register("POST /api/playbooks/{id}/run", func(w http.ResponseWriter, r *http.Request) {
		var body runPlaybookRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		h.record("POST /api/playbooks/{id}/run", body.AgentIDs)
		runID := idgen.New("pbr-")
		if err := st.StartPlaybookRun(r.Context(), store.PlaybookRun{ID: runID, PlaybookID: r.PathValue("id"), Name: "stub",
			Steps: json.RawMessage("[]"), AgentCount: len(body.AgentIDs), TriggeredBy: auth.CurrentUser(r.Context()).Username}); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		_ = st.FinishPlaybookRun(r.Context(), runID, h.outcome)
		writeJSONResponse(w, runPlaybookResponse{RunID: runID, Endpoints: len(body.AgentIDs), Playbook: "stub"})
	})
	register("POST /api/deploy/run", func(w http.ResponseWriter, r *http.Request) {
		var body deployRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		h.record("POST /api/deploy/run", body.AgentIDs)
		writeJSONResponse(w, deployRunResponse{RunID: idgen.New("run-"), Targets: len(body.AgentIDs), Skipped: []map[string]string{}})
	})
	return h
}

func (h *triageHarness) record(pattern string, ids []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, stubCall{pattern: pattern, agentIDs: append([]string(nil), ids...)})
}

func (h *triageHarness) takeCalls() []stubCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := h.calls
	h.calls = nil
	return out
}

func (h *triageHarness) user(perms ...string) *store.User {
	h.t.Helper()
	u, err := h.st.CreateLocalUser(h.ctx, idgen.New("usr-"), idgen.New("triage-"), "", "triage test")
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { _ = h.st.DeleteUser(context.Background(), u.ID) })
	role, err := h.st.CreateRole(h.ctx, idgen.New("role-"), idgen.New("triage-role-"), "", perms, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { _ = h.st.DeleteRole(context.Background(), role.ID) })
	if err := h.st.AssignUserRole(h.ctx, u.ID, role.ID); err != nil {
		h.t.Fatal(err)
	}
	return u
}

func (h *triageHarness) agent(hostname, serial string) string {
	h.t.Helper()
	id := idgen.New("agt-tri-")
	if err := h.st.UpsertOnRegister(h.ctx, id, proto.AgentInfo{Hostname: hostname, OS: "linux"}); err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { _ = h.st.DeleteAgent(context.Background(), id) })
	if serial != "" {
		hw, _ := json.Marshal([]proto.HardwareInfo{{Serial: serial, Manufacturer: "Example", Model: "Box"}})
		if err := h.st.UpsertSensorData(h.ctx, id, string(proto.SensorHardware), time.Now(), hw); err != nil {
			h.t.Fatal(err)
		}
	}
	return id
}

// call runs a handler as a user (or a token, when tok is set) and decodes
// a JSON answer into out.
func (h *triageHarness) call(fn http.HandlerFunc, u *store.User, method, path, body string, pv map[string]string, out any) int {
	h.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range pv {
		req.SetPathValue(k, v)
	}
	req = req.WithContext(auth.WithUser(h.ctx, u))
	rec := httptest.NewRecorder()
	fn(rec, req)
	if out != nil && rec.Code < 300 {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			h.t.Fatalf("%s %s: %v: %s", method, path, err, rec.Body.String())
		}
	}
	if rec.Code >= 300 {
		h.t.Logf("%s %s → %d %s", method, path, rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	return rec.Code
}

func (h *triageHarness) item(id string) store.TriageItem {
	h.t.Helper()
	it, err := h.st.GetTriageItem(h.ctx, id)
	if err != nil || it == nil {
		h.t.Fatalf("item %s: %v", id, err)
	}
	return *it
}

func sysID() string { return strings.TrimPrefix(idgen.New("x"), "x")[:32] }

// Filing, deduplication, endpoint matching and the status workflow.
func TestTriageItemsLifecycle(t *testing.T) {
	h := newTriageHarness(t)
	op := h.user(auth.PermAlertsTriage, auth.PermFleetRead)
	web := h.agent("tri-web-"+h.tag, "SN-TRI-"+h.tag)
	h.agent("tri-dup-"+h.tag, "")
	h.agent("TRI-DUP-"+h.tag, "")

	// A ServiceNow ticket naming the endpoint by serial only.
	ref := sysID()
	body := `{"source":"servicenow","external_ref":"` + ref + `","external_number":"INC9","title":"jq missing","serial":"sn-tri-` + h.tag + `"}`
	var first triageItemResponse
	if code := h.call(h.s.handleCreateTriage, op, "POST", "/api/triage/items", body, nil, &first); code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}
	if !first.Created || first.Item.AgentID != web || first.Item.Status != "new" {
		t.Fatalf("created item = %+v", first.Item)
	}
	// The same ticket again updates that item, and a note from the source
	// lands in its timeline.
	body2 := `{"source":"servicenow","external_ref":"` + ref + `","title":"jq missing on web","note":"user says it is urgent"}`
	var second triageItemResponse
	if code := h.call(h.s.handleCreateTriage, op, "POST", "/api/triage/items", body2, nil, &second); code != http.StatusOK {
		t.Fatalf("update: %d", code)
	}
	if second.Created || second.Item.ID != first.Item.ID || second.Item.Title != "jq missing on web" || second.Item.AgentID != web {
		t.Fatalf("deduplicated item = %+v (first %s)", second.Item, first.Item.ID)
	}
	notes, _ := h.st.ListTriageNotes(h.ctx, first.Item.ID)
	if len(notes) != 3 || notes[2].Body != "user says it is urgent" {
		t.Errorf("timeline = %+v", notes)
	}
	// The same reference from another source is another item.
	var other triageItemResponse
	h.call(h.s.handleCreateTriage, op, "POST", "/api/triage/items", `{"source":"api","external_ref":"`+ref+`","title":"x"}`, nil, &other)
	if other.Item.ID == first.Item.ID || !other.Created {
		t.Errorf("api item with a ServiceNow item's reference was merged into it")
	}
	// A ServiceNow item must carry a sys_id; alerts come only from the Guide.
	if code := h.call(h.s.handleCreateTriage, op, "POST", "/api/triage/items", `{"source":"servicenow","external_ref":"INC1","title":"x"}`, nil, nil); code != 400 {
		t.Errorf("servicenow item without a sys_id: %d", code)
	}
	if code := h.call(h.s.handleCreateTriage, op, "POST", "/api/triage/items", `{"source":"alert","title":"x"}`, nil, nil); code != 400 {
		t.Errorf("alert through the inbound API: %d", code)
	}

	// Two endpoints with the hostname: unattached, both offered.
	var amb triageItemResponse
	h.call(h.s.handleCreateTriage, op, "POST", "/api/triage/items", `{"title":"slow","hostname":"tri-dup-`+h.tag+`"}`, nil, &amb)
	if amb.Item.AgentID != "" || !strings.Contains(amb.Item.EndpointMatch, "matches 2 endpoints") {
		t.Fatalf("ambiguous hostname attached: %+v", amb.Item)
	}
	var detail triageDetailResponse
	h.call(h.s.handleGetTriage, op, "GET", "/api/triage/items/x", "", map[string]string{"id": amb.Item.ID}, &detail)
	if len(detail.Candidates) != 2 {
		t.Errorf("candidates = %+v", detail.Candidates)
	}
	// An operator chooses.
	pick := detail.Candidates[1].AgentID
	var picked triageItemResponse
	h.call(h.s.handleUpdateTriage, op, "PUT", "/x", `{"agent_id":"`+pick+`"}`, map[string]string{"id": amb.Item.ID}, &picked)
	if picked.Item.AgentID != pick || !strings.HasPrefix(picked.Item.EndpointMatch, "chosen by") {
		t.Errorf("chosen endpoint not attached: %+v", picked.Item)
	}
	// A hostname nobody has: unattached.
	var none triageItemResponse
	h.call(h.s.handleCreateTriage, op, "POST", "/api/triage/items", `{"title":"x","hostname":"nobody-`+h.tag+`"}`, nil, &none)
	if none.Item.AgentID != "" || !strings.Contains(none.Item.EndpointMatch, "no endpoint matched") {
		t.Errorf("unknown hostname: %+v", none.Item)
	}

	// Status workflow.
	id := map[string]string{"id": first.Item.ID}
	put := func(body string) int { return h.call(h.s.handleUpdateTriage, op, "PUT", "/x", body, id, nil) }
	if code := put(`{"status":"closed"}`); code != 400 {
		t.Errorf("unknown status: %d", code)
	}
	if code := put(`{"status":"waiting","assignee":"` + op.Username + `"}`); code != 200 {
		t.Fatalf("new → waiting: %d", code)
	}
	if code := put(`{"assignee":"no-such-user-` + h.tag + `"}`); code != 400 {
		t.Errorf("assigning an unknown user: %d", code)
	}
	if code := put(`{"status":"new"}`); code != http.StatusConflict {
		t.Errorf("waiting → new: %d", code)
	}
	if code := put(`{"status":"resolved"}`); code != 200 {
		t.Fatalf("waiting → resolved: %d", code)
	}
	it := h.item(first.Item.ID)
	if it.ResolvedAt == nil || it.ResolvedBy != op.Username || it.Assignee != op.Username {
		t.Errorf("resolved item = %+v", it)
	}
	if code := put(`{"status":"waiting"}`); code != http.StatusConflict {
		t.Errorf("resolved → waiting: %d", code)
	}
	if code := put(`{"status":"in_progress"}`); code != 200 {
		t.Errorf("reopen: %d", code)
	}
	if it := h.item(first.Item.ID); it.ResolvedAt != nil || it.Status != "in_progress" {
		t.Errorf("reopened item = %+v", it)
	}
	// Two people moving it at once: the second write loses.
	stale := h.item(first.Item.ID)
	stale.Status = "waiting"
	if ok, err := h.st.UpdateTriageItem(h.ctx, stale, "new"); err != nil || ok {
		t.Errorf("a stale transition was written (%v)", err)
	}

	// The list filters.
	var list listTriageResponse
	h.call(h.s.handleListTriage, op, "GET", "/api/triage/items?agent_id="+web, "", nil, &list)
	if len(list.Items) != 1 || list.Items[0].ID != first.Item.ID || list.Items[0].Hostname != "tri-web-"+h.tag {
		t.Errorf("filtered list = %+v", list.Items)
	}
}

// A Guide alert becomes an item about the endpoint it links to, once.
func TestTriageFromGuide(t *testing.T) {
	h := newTriageHarness(t)
	op := h.user(auth.PermAlertsTriage, auth.PermFleetRead)
	web := h.agent("tri-guide-"+h.tag, "")
	key := "endpoint:offline:" + web
	if err := h.st.UpsertGuide(h.ctx, store.GuideNotification{ID: idgen.New("gd-"), SubjectKey: key, Source: "endpoint", Kind: "observation",
		Severity: "low", Title: "offline for a day", Link: "/endpoint/" + web, Count: 1}); err != nil {
		t.Fatal(err)
	}
	list, _ := h.st.ListGuide(h.ctx, false)
	var gid string
	for _, n := range list {
		if n.SubjectKey == key {
			gid = n.ID
		}
	}
	var got triageItemResponse
	if code := h.call(h.s.handleGuideToTriage, op, "POST", "/x", "", map[string]string{"id": gid}, &got); code != http.StatusCreated {
		t.Fatalf("guide → triage: %d", code)
	}
	if got.Item.Source != "alert" || got.Item.AgentID != web || got.Item.ExternalRef != gid {
		t.Fatalf("item = %+v", got.Item)
	}
	var again triageItemResponse
	h.call(h.s.handleGuideToTriage, op, "POST", "/x", "", map[string]string{"id": gid}, &again)
	if again.Created || again.Item.ID != got.Item.ID {
		t.Errorf("sending the alert again made another item")
	}
	// The endpoint's open alerts are on the item's context.
	var cx triageContextResponse
	h.call(h.s.handleTriageContext, op, "GET", "/x", "", map[string]string{"id": got.Item.ID}, &cx)
	if cx.Endpoint == nil || cx.Endpoint.AgentID != web || len(cx.Alerts) != 1 || cx.Alerts[0].ID != gid {
		t.Errorf("context = %+v", cx)
	}
	if code := h.call(h.s.handleGuideToTriage, op, "POST", "/x", "", map[string]string{"id": "gd-none"}, nil); code != 404 {
		t.Errorf("unknown guide item: %d", code)
	}
}

// A fix runs on the item's endpoint and nowhere else, through the route's
// own permission check; the fleet step is an approval request naming the
// endpoints the requester saw, which the requester cannot approve and
// which a deleted group cannot widen.
func TestTriageFixThenSimilar(t *testing.T) {
	h := newTriageHarness(t)
	op := h.user(auth.PermAlertsTriage, auth.PermDeployManage, auth.PermFleetRead)
	triager := h.user(auth.PermAlertsTriage, auth.PermFleetRead)
	approver := h.user(auth.PermApprovalsDecide, auth.PermFleetRead)
	a := h.agent("tri-a-"+h.tag, "")
	b := h.agent("tri-b-"+h.tag, "")
	c := h.agent("tri-c-"+h.tag, "")
	h.agent("tri-outside-"+h.tag, "")

	pb := store.Playbook{ID: idgen.New("pb-"), Name: "restart nginx " + h.tag, Steps: json.RawMessage(`[{"kind":"wait","wait_seconds":1}]`), Enabled: true}
	if err := h.st.UpsertPlaybook(h.ctx, pb, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.st.DeletePlaybook(context.Background(), pb.ID) })
	g, err := h.st.UpsertComputerGroup(h.ctx, store.ComputerGroup{ID: idgen.New("cgrp-"), Name: "web " + h.tag, Kind: "static",
		MatchMode: "all", MemberIDs: []string{a, b, c}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _, _ = h.st.DeleteComputerGroupAndOrphans(context.Background(), g.ID) })

	var created triageItemResponse
	h.call(h.s.handleCreateTriage, op, "POST", "/api/triage/items", `{"title":"nginx down","agent_id":"`+a+`"}`, nil, &created)
	item := map[string]string{"id": created.Item.ID}

	// Without deploy.manage the route itself refuses, and nothing runs.
	fixBody := `{"kind":"playbook","playbook_id":"` + pb.ID + `","agent_ids":["` + b + `"],"group_ids":["` + g.ID + `"]}`
	if code := h.call(h.s.handleTriageFix, triager, "POST", "/x", fixBody, item, nil); code != http.StatusForbidden {
		t.Errorf("fix without deploy.manage: %d", code)
	}
	if calls := h.takeCalls(); len(calls) != 0 {
		t.Fatalf("a refused fix reached the route: %+v", calls)
	}
	// With it: exactly the item's endpoint, whatever else the body says.
	var fixed triageFixResponse
	if code := h.call(h.s.handleTriageFix, op, "POST", "/x", fixBody, item, &fixed); code != 200 {
		t.Fatalf("fix: %d", code)
	}
	calls := h.takeCalls()
	if len(calls) != 1 || !slices.Equal(calls[0].agentIDs, []string{a}) {
		t.Fatalf("fix reached the route with %+v, want exactly [%s]", calls, a)
	}
	if fixed.Fix.Outcome != "succeeded" || fixed.Fix.AgentID != a || fixed.Fix.RunID == "" {
		t.Errorf("fix = %+v", fixed.Fix)
	}
	if h.item(created.Item.ID).Status != "in_progress" {
		t.Errorf("running a fix did not start work on the item")
	}
	// A package fix goes through Deploy's route the same way.
	pkg, err := h.st.UpsertSoftwarePackage(h.ctx, store.SoftwarePackage{ID: idgen.New("sw-"), Name: "flush dns " + h.tag, Kind: "action"})
	if err != nil {
		t.Fatal(err)
	}
	var pkgFix triageFixResponse
	if code := h.call(h.s.handleTriageFix, op, "POST", "/x", `{"kind":"package","package_id":"`+pkg.ID+`","agent_ids":["`+c+`"]}`, item, &pkgFix); code != 200 {
		t.Fatalf("package fix: %d", code)
	}
	if calls := h.takeCalls(); len(calls) != 1 || calls[0].pattern != "POST /api/deploy/run" || !slices.Equal(calls[0].agentIDs, []string{a}) {
		t.Fatalf("package fix reached Deploy with %+v", calls)
	}
	var tmpl deployRequest
	if json.Unmarshal(pkgFix.Fix.Request, &tmpl) != nil || tmpl.Operation != "run" || len(tmpl.AgentIDs) != 0 {
		t.Errorf("package fix kept %s", pkgFix.Fix.Request)
	}

	similar := `{"fix_id":"` + fixed.Fix.ID + `","group_id":"` + g.ID + `"}`
	// The preview names the group's other members.
	var pv triageSimilarPreview
	if code := h.call(h.s.handleTriageSimilarPreview, op, "POST", "/x", similar, item, &pv); code != 200 {
		t.Fatalf("preview: %d", code)
	}
	var seen []string
	for _, e := range pv.Endpoints {
		seen = append(seen, e.AgentID)
	}
	want := []string{b, c}
	slices.Sort(want)
	slices.Sort(seen)
	if !slices.Equal(seen, want) || pv.TargetName != g.Name {
		t.Fatalf("preview = %+v, want %v", pv, want)
	}
	// A token cannot ask (nobody could approve it), nor can someone
	// without the route's permission.
	tokCtx := auth.WithToken(auth.WithUser(h.ctx, op), []string{auth.PermAlertsTriage, auth.PermDeployManage}, &auth.TokenInfo{ID: "tok-x"})
	req := httptest.NewRequest("POST", "/x", strings.NewReader(similar)).WithContext(tokCtx)
	req.SetPathValue("id", created.Item.ID)
	rec := httptest.NewRecorder()
	h.s.handleTriageSimilar(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("token asked for a rollout: %d", rec.Code)
	}
	if code := h.call(h.s.handleTriageSimilar, triager, "POST", "/x", similar, item, nil); code != http.StatusForbidden {
		t.Errorf("rollout without deploy.manage: %d", code)
	}
	// Asked for: an approval request naming b and c, nothing run yet.
	var asked triageSimilarResponse
	if code := h.call(h.s.handleTriageSimilar, op, "POST", "/x", similar, item, &asked); code != http.StatusAccepted {
		t.Fatalf("similar: %d", code)
	}
	if calls := h.takeCalls(); len(calls) != 0 {
		t.Fatalf("the rollout ran before approval: %+v", calls)
	}
	apr, err := h.st.GetApprovalRequest(h.ctx, asked.RequestID)
	if err != nil || apr == nil {
		t.Fatalf("approval request %s: %v", asked.RequestID, err)
	}
	got := append([]string(nil), apr.AgentIDs...)
	slices.Sort(got)
	if apr.State != "pending" || apr.Module != "playbooks" || apr.RequestedBy != op.Username || !slices.Equal(got, want) {
		t.Fatalf("approval request = %+v", apr)
	}
	// The requester cannot approve it.
	decide := `{"decision":"approve","note":"ok"}`
	if code := h.call(h.s.handleDecideApproval, op, "POST", "/x", decide, map[string]string{"id": apr.ID}, nil); code != http.StatusForbidden {
		t.Errorf("self-approval: %d", code)
	}
	// The group is deleted while the request waits: a new preview is
	// refused rather than read as "everyone"...
	if _, _, err := h.st.DeleteComputerGroupAndOrphans(h.ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	if code := h.call(h.s.handleTriageSimilarPreview, op, "POST", "/x", similar, item, nil); code != http.StatusConflict {
		t.Errorf("preview over a deleted group: %d", code)
	}
	// ...and approving the waiting request runs on exactly b and c.
	if code := h.call(h.s.handleDecideApproval, approver, "POST", "/x", decide, map[string]string{"id": apr.ID}, nil); code != 200 {
		t.Fatalf("approve: %d", code)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if done, _ := h.st.GetApprovalRequest(h.ctx, apr.ID); done != nil && done.Outcome != "" {
			if done.State != "approved" {
				t.Fatalf("approved request ended %s: %s", done.State, done.Outcome)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the approved request never ran")
		}
		time.Sleep(50 * time.Millisecond)
	}
	calls = h.takeCalls()
	if len(calls) != 1 || calls[0].pattern != "POST /api/playbooks/{id}/run" {
		t.Fatalf("approved rollout calls = %+v", calls)
	}
	ran := append([]string(nil), calls[0].agentIDs...)
	slices.Sort(ran)
	if !slices.Equal(ran, want) {
		t.Fatalf("approved rollout ran on %v, want exactly %v", ran, want)
	}
	var detail triageDetailResponse
	h.call(h.s.handleGetTriage, op, "GET", "/x", "", item, &detail)
	if len(detail.Rollouts) != 1 || detail.Rollouts[0].ApprovalState != "approved" || detail.Rollouts[0].DecidedBy != approver.Username {
		t.Errorf("rollouts = %+v", detail.Rollouts)
	}

	// A fix that did not succeed cannot be rolled out.
	h.outcome = "failed"
	var failed triageFixResponse
	h.call(h.s.handleTriageFix, op, "POST", "/x", `{"kind":"playbook","playbook_id":"`+pb.ID+`"}`, item, &failed)
	h.takeCalls()
	g2, err := h.st.UpsertComputerGroup(h.ctx, store.ComputerGroup{ID: idgen.New("cgrp-"), Name: "web2 " + h.tag, Kind: "static",
		MatchMode: "all", MemberIDs: []string{b}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _, _ = h.st.DeleteComputerGroupAndOrphans(context.Background(), g2.ID) })
	if code := h.call(h.s.handleTriageSimilarPreview, op, "POST", "/x", `{"fix_id":"`+failed.Fix.ID+`","group_id":"`+g2.ID+`"}`, item, nil); code != http.StatusConflict {
		t.Errorf("rollout of a failed fix: %d", code)
	}
	// An unattached item runs nothing.
	var loose triageItemResponse
	h.call(h.s.handleCreateTriage, op, "POST", "/api/triage/items", `{"title":"who knows"}`, nil, &loose)
	if code := h.call(h.s.handleTriageFix, op, "POST", "/x", `{"kind":"playbook","playbook_id":"`+pb.ID+`"}`, map[string]string{"id": loose.Item.ID}, nil); code != http.StatusConflict {
		t.Errorf("fix on an unattached item: %d", code)
	}
	if calls := h.takeCalls(); len(calls) != 0 {
		t.Errorf("an unattached item's fix reached the route: %+v", calls)
	}
}

// Resolving a ServiceNow item posts a work note to the ticket through the
// integration's URL and credentials, and records whether it arrived.
func TestTriageServiceNowRoundTrip(t *testing.T) {
	h := newTriageHarness(t)
	op := h.user(auth.PermAlertsTriage, auth.PermFleetRead)
	web := h.agent("tri-snow-"+h.tag, "")

	type got struct {
		method, path, auth string
		body               map[string]string
	}
	var mu sync.Mutex
	var reqs []got
	fail := false
	snow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]string
		_ = json.Unmarshal(raw, &body)
		user, pass, _ := r.BasicAuth()
		mu.Lock()
		reqs = append(reqs, got{r.Method, r.URL.Path, user + ":" + pass, body})
		f := fail
		mu.Unlock()
		if f {
			http.Error(w, `{"error":{"message":"Insufficient rights"}}`, http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":{}}`))
	}))
	defer snow.Close()

	in := store.Integration{ID: idgen.New("int-"), Kind: "servicenow", Name: "ServiceNow " + h.tag, Enabled: true,
		Config: map[string]string{"url": snow.URL}, Events: []string{"alert"}, MinSeverity: "warning"}
	sealed, err := h.s.sealSetting("integration/"+in.ID, "svc-mustra:s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.st.SaveIntegration(h.ctx, in, &sealed); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.st.DeleteIntegration(context.Background(), in.ID) })

	ref := sysID()
	var created triageItemResponse
	h.call(h.s.handleCreateTriage, op, "POST", "/api/triage/items", `{"source":"servicenow","external_ref":"`+ref+`","external_number":"INC0099",
		"integration_id":"`+in.ID+`","title":"jq missing","agent_id":"`+web+`"}`, nil, &created)
	id := map[string]string{"id": created.Item.ID}
	var resolved triageItemResponse
	if code := h.call(h.s.handleUpdateTriage, op, "PUT", "/x", `{"status":"resolved","note":"Installed jq; release job passes."}`, id, &resolved); code != 200 {
		t.Fatalf("resolve: %d", code)
	}
	if resolved.Item.SyncState != "sent" || resolved.Item.SyncError != "" || resolved.Item.SyncAt == nil {
		t.Fatalf("resolved item = %+v", resolved.Item)
	}
	mu.Lock()
	if len(reqs) != 1 {
		t.Fatalf("ServiceNow got %d requests", len(reqs))
	}
	r := reqs[0]
	mu.Unlock()
	if r.method != http.MethodPatch || r.path != "/api/now/table/incident/"+ref || r.auth != "svc-mustra:s3cret" {
		t.Errorf("ServiceNow request = %s %s as %s", r.method, r.path, r.auth)
	}
	if note := r.body["work_notes"]; !strings.Contains(note, "Resolved in Mustra by "+op.Username) ||
		!strings.Contains(note, "Installed jq; release job passes.") || !strings.Contains(note, "tri-snow-"+h.tag) {
		t.Errorf("work note = %q", note)
	}
	// A refusal is recorded, and sending again after the fix works.
	mu.Lock()
	fail = true
	mu.Unlock()
	if code := h.call(h.s.handleTriageSync, op, "POST", "/x", "", id, nil); code != 200 {
		t.Fatalf("sync: %d", code)
	}
	it := h.item(created.Item.ID)
	if it.SyncState != "failed" || !strings.Contains(it.SyncError, "403") {
		t.Errorf("failed sync recorded as %q %q", it.SyncState, it.SyncError)
	}
	mu.Lock()
	fail = false
	mu.Unlock()
	var synced triageSyncResponse
	h.call(h.s.handleTriageSync, op, "POST", "/x", "", id, &synced)
	if synced.Item.SyncState != "sent" {
		t.Errorf("resent sync = %q %q", synced.Item.SyncState, synced.Item.SyncError)
	}
	mu.Lock()
	if last := reqs[len(reqs)-1]; !strings.Contains(last.body["work_notes"], "Installed jq") {
		t.Errorf("resent note lost the resolution: %q", last.body["work_notes"])
	}
	mu.Unlock()
	notes, _ := h.st.ListTriageNotes(h.ctx, created.Item.ID)
	var syncs []string
	for _, n := range notes {
		if n.Kind == "sync" {
			syncs = append(syncs, n.Detail["state"].(string))
		}
	}
	if !slices.Equal(syncs, []string{"sent", "failed", "sent"}) {
		t.Errorf("timeline sync entries = %v", syncs)
	}
	// Items from elsewhere have no ticket to update.
	var manual triageItemResponse
	h.call(h.s.handleCreateTriage, op, "POST", "/api/triage/items", `{"title":"x"}`, nil, &manual)
	var res triageItemResponse
	h.call(h.s.handleUpdateTriage, op, "PUT", "/x", `{"status":"resolved"}`, map[string]string{"id": manual.Item.ID}, &res)
	if res.Item.SyncState != "" {
		t.Errorf("a manual item tried to sync: %q", res.Item.SyncState)
	}
	if code := h.call(h.s.handleTriageSync, op, "POST", "/x", "", map[string]string{"id": manual.Item.ID}, nil); code != http.StatusConflict {
		t.Errorf("sync of a manual item: %d", code)
	}
}

// The context is read-only aggregation over what mustra holds, and sensor
// data is left out for a caller whose content sets do not grant it.
func TestTriageContextReadsWhatExists(t *testing.T) {
	h := newTriageHarness(t)
	op := h.user(auth.PermAlertsTriage, auth.PermFleetRead)
	web := h.agent("tri-cx-"+h.tag, "SN-CX-"+h.tag)
	patches, _ := json.Marshal([]proto.PatchInfo{{Name: "openssl", Severity: "security"}, {Name: "curl"}})
	if err := h.st.UpsertSensorData(h.ctx, web, string(proto.SensorPatches), time.Now(), patches); err != nil {
		t.Fatal(err)
	}
	var created triageItemResponse
	h.call(h.s.handleCreateTriage, op, "POST", "/api/triage/items", `{"title":"x","serial":"SN-CX-`+h.tag+`"}`, nil, &created)
	if created.Item.AgentID != web {
		t.Fatalf("serial did not attach: %+v", created.Item)
	}
	var cx triageContextResponse
	if code := h.call(h.s.handleTriageContext, op, "GET", "/x", "", map[string]string{"id": created.Item.ID}, &cx); code != 200 {
		t.Fatalf("context: %d", code)
	}
	if cx.Endpoint == nil || cx.Endpoint.Serial != "SN-CX-"+h.tag || cx.Patches == nil || cx.Patches.Pending != 2 || cx.Patches.Security != 1 ||
		cx.Patches.Items[0].Name != "openssl" {
		t.Errorf("context = %+v / %+v", cx.Endpoint, cx.Patches)
	}
	// Unattached: no endpoint, nothing else.
	var loose triageItemResponse
	h.call(h.s.handleCreateTriage, op, "POST", "/api/triage/items", `{"title":"x"}`, nil, &loose)
	var empty triageContextResponse
	h.call(h.s.handleTriageContext, op, "GET", "/x", "", map[string]string{"id": loose.Item.ID}, &empty)
	if empty.Endpoint != nil || empty.Patches != nil {
		t.Errorf("unattached context = %+v", empty)
	}
}

// A playbook run on named endpoints reaches those endpoints only: an
// unknown one is an error, and one that cannot run it now is skipped and
// named rather than replaced by the playbook's own targets.
func TestNamedPlaybookTargets(t *testing.T) {
	h := newTriageHarness(t)
	on := h.agent("tri-on-"+h.tag, "")
	off := h.agent("tri-off-"+h.tag, "")
	if err := h.st.RecordHeartbeat(h.ctx, on, time.Now()); err != nil {
		t.Fatal(err)
	}
	pb := store.Playbook{ID: "pb-x", Name: "x", OS: "linux"}
	got, skipped, err := h.s.namedPlaybookTargets(h.ctx, pb, []string{on, off, on})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].AgentID != on || len(skipped) != 1 || !strings.Contains(skipped[0], "offline") {
		t.Errorf("targets %+v, skipped %v", got, skipped)
	}
	pb.OS = "windows"
	if got, skipped, _ := h.s.namedPlaybookTargets(h.ctx, pb, []string{on}); len(got) != 0 || !strings.Contains(skipped[0], "not windows") {
		t.Errorf("a Windows playbook targeted a Linux endpoint: %+v %v", got, skipped)
	}
	if _, _, err := h.s.namedPlaybookTargets(h.ctx, pb, []string{"agt-none"}); err == nil {
		t.Error("an unknown endpoint was accepted")
	}
}

// Naming endpoints narrows a playbook's own targeting and never widens it:
// an endpoint outside its group is skipped and named, a run naming only such
// endpoints is refused, and once the group is deleted nothing is reached.
func TestNamedPlaybookRunNeverWidens(t *testing.T) {
	h := newTriageHarness(t)
	in := h.agent("tri-in-"+h.tag, "")
	out := h.agent("tri-out-"+h.tag, "")
	for _, id := range []string{in, out} {
		if err := h.st.RecordHeartbeat(h.ctx, id, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	g, err := h.st.UpsertComputerGroup(h.ctx, store.ComputerGroup{ID: idgen.New("grp-"), Name: idgen.New("tri group "), Kind: "static",
		MatchMode: "all", MemberIDs: []string{in}, CreatedBy: "test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _, _ = h.st.DeleteComputerGroupAndOrphans(context.Background(), g.ID) })
	pb := store.Playbook{ID: idgen.New("pb-"), Name: idgen.New("tri narrow "), GroupID: g.ID, Enabled: true,
		Steps: json.RawMessage(`[{"kind":"wait","wait_seconds":1}]`)}
	if err := h.st.UpsertPlaybook(h.ctx, pb, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.st.DeletePlaybook(context.Background(), pb.ID) })

	got, skipped, err := h.s.namedPlaybookTargets(h.ctx, pb, []string{in, out})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].AgentID != in || len(skipped) != 1 || !strings.Contains(skipped[0], "not targeted") {
		t.Errorf("an endpoint outside the playbook's group was reached: targets %+v, skipped %v", got, skipped)
	}

	admin := h.user(auth.PermDeployManage, auth.PermFleetRead)
	pv := map[string]string{"id": pb.ID}
	if code := h.call(h.s.handleRunPlaybook, admin, "POST", "/api/playbooks/"+pb.ID+"/run", `{"agent_ids":["`+out+`"]}`, pv, nil); code != http.StatusBadRequest {
		t.Errorf("a run naming only an untargeted endpoint answered %d, want 400", code)
	}

	if _, _, err := h.st.DeleteComputerGroupAndOrphans(h.ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	stored, err := h.st.GetPlaybook(h.ctx, pb.ID)
	if err != nil || stored == nil || !stored.GroupDeleted {
		t.Fatalf("playbook after its group was deleted: %+v %v", stored, err)
	}
	if got, _, _ := h.s.namedPlaybookTargets(h.ctx, *stored, []string{in, out}); len(got) != 0 {
		t.Errorf("a playbook whose group was deleted reached %+v", got)
	}
	if code := h.call(h.s.handleRunPlaybook, admin, "POST", "/api/playbooks/"+pb.ID+"/run", `{"agent_ids":["`+in+`"]}`, pv, nil); code != http.StatusBadRequest {
		t.Errorf("a run on a playbook whose group was deleted answered %d, want 400", code)
	}
	runs, err := h.st.ListPlaybookRuns(h.ctx, 200)
	if err != nil {
		t.Fatal(err)
	}
	for _, run := range runs {
		if run.PlaybookID == pb.ID {
			t.Errorf("run %s started", run.ID)
		}
	}
}
