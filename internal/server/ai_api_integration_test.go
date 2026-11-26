package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/server/vault"
	"github.com/mustra-dev/mustra/internal/store"
)

// syncBuffer collects the server's log so a test can search it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// The assistant end to end against an OpenAI-compatible stand-in: off
// until turned on, the key sealed and never returned, the model's tool
// calls run as the user (and refused where the user lacks the
// permission), each audited, and the key in no response and no log line.
func TestAIAssistantEndToEnd(t *testing.T) {
	f := newMCPFixture(t)
	logs := &syncBuffer{}
	f.s.logger = slog.New(slog.NewTextHandler(logs, nil))
	key, _ := vault.GenerateKey()
	v, err := vault.New(f.st, key)
	if err != nil {
		t.Fatal(err)
	}
	f.s.vault = v
	t.Setenv("MUSTRA_WEBHOOK_ALLOWED_HOSTS", "127.0.0.1")
	// Start from a clean slate: other tests share the database.
	for _, c := range mustList(t, f.st) {
		_, _ = f.st.DeleteAIConnection(f.ctx, c.ID)
	}

	var mu sync.Mutex
	var requests []string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		requests = append(requests, string(raw))
		n := len(requests)
		mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+aiTestKey {
			t.Errorf("provider got Authorization %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(string(raw), "Reply with the single word OK"):
			io.WriteString(w, `{"choices":[{"message":{"content":"OK"}}]}`)
		case n == 1 || !strings.Contains(string(raw), `"role":"tool"`):
			io.WriteString(w, `{"choices":[{"message":{"content":"","tool_calls":[`+
				`{"id":"a","type":"function","function":{"name":"list_endpoints","arguments":"{\"search\":\"`+f.host+`\"}"}},`+
				`{"id":"b","type":"function","function":{"name":"request_patch_deployment","arguments":"{\"hostnames\":[\"`+f.host+`\"]}"}}]}}]}`)
		default:
			io.WriteString(w, `{"choices":[{"message":{"content":"**`+f.host+`** is online. <script>alert(1)</script>"}}]}`)
		}
	}))
	defer provider.Close()

	admin := auth.WithUser(f.ctx, &store.User{ID: "usr-ai-admin", Username: "ai-admin", IsAdmin: true, Active: true})
	user := auth.WithUser(f.ctx, f.user(auth.PermFleetRead, auth.PermAIUse)) // no patches.manage
	do := func(ctx context.Context, method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequestWithContext(ctx, method, path, strings.NewReader(body))
		rec := httptest.NewRecorder()
		f.s.routeLog.ServeMux.ServeHTTP(rec, r)
		if strings.Contains(rec.Body.String(), aiTestKey) {
			t.Fatalf("%s %s returned the API key: %s", method, path, rec.Body)
		}
		return rec
	}

	// Off: no connection, not enabled.
	if rec := do(user, "POST", "/api/ai/chat", `{"messages":[{"role":"user","content":"hi"}]}`); rec.Code != http.StatusConflict {
		t.Fatalf("chat while off: %d %s", rec.Code, rec.Body)
	}
	// A user without ai.use cannot reach it at all.
	if rec := do(auth.WithUser(f.ctx, f.user(auth.PermFleetRead)), "POST", "/api/ai/chat", `{"messages":[{"role":"user","content":"hi"}]}`); rec.Code != http.StatusForbidden {
		t.Errorf("chat without ai.use: %d", rec.Code)
	}
	// Nor configure it without settings.manage.
	if rec := do(user, "GET", "/api/ai/settings", ""); rec.Code != http.StatusForbidden {
		t.Errorf("settings without settings.manage: %d", rec.Code)
	}

	rec := do(admin, "POST", "/api/ai/connections", `{"name":"Local","provider":"openai_compatible","base_url":"`+provider.URL+`/v1","model":"llama","api_key":"`+aiTestKey+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body)
	}
	var conn aiConnectionView
	_ = json.Unmarshal(rec.Body.Bytes(), &conn)
	if !conn.KeySet || conn.ID == "" {
		t.Fatalf("saved: %+v", conn)
	}
	stored, _ := f.st.GetAIConnection(f.ctx, conn.ID)
	if !strings.HasPrefix(stored.APIKey, "vault:") || strings.Contains(stored.APIKey, aiTestKey) {
		t.Errorf("key stored unsealed: %q", stored.APIKey)
	}
	// Pointing the key somewhere else needs it again.
	if rec := do(admin, "PUT", "/api/ai/connections/"+conn.ID, `{"name":"Local","provider":"openai_compatible","base_url":"https://elsewhere.example/v1","model":"llama"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("moving the key without retyping it: %d", rec.Code)
	}
	if rec := do(admin, "POST", "/api/ai/connections/"+conn.ID+"/test", ""); !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Errorf("test connection: %s", rec.Body)
	}
	// Still off until an administrator turns it on.
	if rec := do(user, "GET", "/api/ai/status", ""); !strings.Contains(rec.Body.String(), `"available":false`) {
		t.Errorf("status before enabling: %s", rec.Body)
	}
	if rec := do(admin, "PUT", "/api/ai/settings", `{"enabled":true,"self_hosted_only":true}`); rec.Code != http.StatusOK {
		t.Fatalf("enable: %d %s", rec.Code, rec.Body)
	}
	if rec := do(admin, "GET", "/api/ai/settings", ""); !strings.Contains(rec.Body.String(), `"key_set":true`) {
		t.Errorf("settings: %s", rec.Body)
	}

	rec = do(user, "POST", "/api/ai/chat", `{"messages":[{"role":"user","content":"Is my endpoint online? Patch it."}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("chat: %d %s", rec.Code, rec.Body)
	}
	var out aiChatResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out.ToolCalls) != 2 || !out.ToolCalls[0].OK || out.ToolCalls[1].OK || !out.ToolCalls[1].Action ||
		!strings.Contains(out.ToolCalls[1].Error, "patches.manage") || !strings.Contains(out.Reply, f.host) {
		t.Errorf("chat answer: %+v", out)
	}
	// The endpoint data the tool read went to the provider; the
	// permission refusal did too, so the model can explain it.
	mu.Lock()
	last := requests[len(requests)-1]
	mu.Unlock()
	if !strings.Contains(last, f.agent) || !strings.Contains(last, "patches.manage") {
		t.Errorf("tool results not sent back to the model: %s", clip(last, 500))
	}
	events, err := f.st.ListAuditEvents(f.ctx, "ai.tool_call", "", "", 50)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range events {
		if strings.HasPrefix(e.Actor, "mcp-") {
			seen[e.Target] = true
		}
	}
	if !seen["list_endpoints"] || !seen["request_patch_deployment"] {
		t.Errorf("tool calls not audited with the user: %+v", events)
	}
	if strings.Contains(logs.String(), aiTestKey) {
		t.Error("the API key appears in the server log")
	}

	// Restricted to self-hosted: a cloud connection is not offered.
	rec = do(admin, "POST", "/api/ai/connections", `{"name":"Cloud","provider":"anthropic","model":"claude","api_key":"`+aiTestKey+`"}`)
	var cloud aiConnectionView
	_ = json.Unmarshal(rec.Body.Bytes(), &cloud)
	if rec := do(user, "POST", "/api/ai/chat", `{"connection_id":"`+cloud.ID+`","messages":[{"role":"user","content":"hi"}]}`); rec.Code != http.StatusConflict {
		t.Errorf("a cloud connection was used while restricted to self-hosted: %d", rec.Code)
	}
	for _, id := range []string{conn.ID, cloud.ID} {
		if rec := do(admin, "DELETE", "/api/ai/connections/"+id, ""); rec.Code != http.StatusNoContent {
			t.Errorf("delete: %d", rec.Code)
		}
	}
	_ = f.st.SetSetting(f.ctx, settingAIEnabled, "false", "test")
	_ = f.st.SetSetting(f.ctx, settingAISelfHostedOnly, "false", "test")
}

func mustList(t *testing.T, st *store.Store) []store.AIConnection {
	t.Helper()
	l, err := st.ListAIConnections(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return l
}
