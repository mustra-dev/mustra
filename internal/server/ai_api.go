package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// The console assistant: a chat that sends the conversation to a model
// provider an administrator connected (Settings → AI) with the MCP tool
// registry offered as tools, and runs the tools the model calls as the
// signed-in user. It is off until a connection exists and an
// administrator turns it on; using it needs ai.use, and each tool still
// needs its own permission, so the assistant can read nothing its user
// could not read in the console. Action tools only file approval requests,
// as they do over MCP. Every tool call is audited before it runs.
//
// What the tools return is endpoint data, and it goes to the provider.
// Settings says so, and can restrict the assistant to self-hosted
// (OpenAI-compatible) connections.

const (
	settingAIEnabled         = "ai.enabled"
	settingAISelfHostedOnly  = "ai.self_hosted_only"
	aiMaxSteps               = 8
	aiChatTimeout            = 3 * time.Minute
	aiMaxHistory             = 40
	aiMaxMessageBytes        = 32 << 10
	aiMaxToolResultBytes     = 24 << 10
	aiAuditArgumentsMaxBytes = 1000
)

func aiKeyAAD(id string) string { return "ai_connection/api_key/" + id }

// aiConnectionView is a connection as the API shows it: never the key,
// only whether one is stored.
type aiConnectionView struct {
	store.AIConnection
	KeySet     bool `json:"key_set"`
	SelfHosted bool `json:"self_hosted"`
}

func viewAIConnection(c store.AIConnection) aiConnectionView {
	return aiConnectionView{AIConnection: c, KeySet: c.APIKey != "", SelfHosted: c.Provider == aiOpenAICompatible}
}

// aiSettingsResponse is what GET /api/ai/settings answers.
type aiSettingsResponse struct {
	// Enabled is the administrator's switch; the assistant also needs a
	// connection.
	Enabled bool `json:"enabled"`
	// SelfHostedOnly restricts the assistant to OpenAI-compatible
	// connections, which an operator runs themselves.
	SelfHostedOnly bool               `json:"self_hosted_only"`
	Connections    []aiConnectionView `json:"connections"`
	// Providers names each provider type.
	Providers map[string]string `json:"providers"`
	// VaultConfigured says whether API keys can be stored: they are
	// sealed with the credential encryption key.
	VaultConfigured bool `json:"vault_configured"`
}

func (s *Server) aiSettings(ctx context.Context) (enabled, selfHostedOnly bool) {
	if s.store == nil {
		return false, false
	}
	e, _ := s.store.GetSetting(ctx, settingAIEnabled)
	h, _ := s.store.GetSetting(ctx, settingAISelfHostedOnly)
	return e == "true", h == "true"
}

func (s *Server) handleGetAISettings(w http.ResponseWriter, r *http.Request) {
	conns, err := s.store.ListAIConnections(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	enabled, selfHosted := s.aiSettings(r.Context())
	out := aiSettingsResponse{Enabled: enabled, SelfHostedOnly: selfHosted, Connections: []aiConnectionView{},
		Providers: aiProviders, VaultConfigured: s.vault != nil}
	for _, c := range conns {
		out.Connections = append(out.Connections, viewAIConnection(c))
	}
	writeJSONResponse(w, out)
}

// putAISettingsRequest is the body of PUT /api/ai/settings.
type putAISettingsRequest struct {
	Enabled        bool `json:"enabled"`
	SelfHostedOnly bool `json:"self_hosted_only"`
}

func (s *Server) handlePutAISettings(w http.ResponseWriter, r *http.Request) {
	var req putAISettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	u := auth.CurrentUser(r.Context())
	if err := s.auditStrict(r.Context(), auditEvent{Action: "settings.ai", Actor: u.Username, Target: "AI assistant",
		Severity: "notice", Detail: map[string]any{"enabled": req.Enabled, "self_hosted_only": req.SelfHostedOnly}}); err != nil {
		http.Error(w, "the change could not be recorded in the audit log, so it was not made", http.StatusServiceUnavailable)
		return
	}
	for k, v := range map[string]bool{settingAIEnabled: req.Enabled, settingAISelfHostedOnly: req.SelfHostedOnly} {
		if err := s.store.SetSetting(r.Context(), k, fmt.Sprint(v), u.Username); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	s.handleGetAISettings(w, r)
}

// saveAIConnectionRequest is the body of POST /api/ai/connections and
// PUT /api/ai/connections/{id}.
type saveAIConnectionRequest struct {
	Name     string `json:"name" api:"required"`
	Provider string `json:"provider" api:"required"`
	// BaseURL is required for Azure OpenAI (the resource endpoint) and
	// OpenAI-compatible servers; optional for the others.
	BaseURL string `json:"base_url"`
	// Model is the model ID, or for Azure OpenAI the deployment name.
	Model string `json:"model" api:"required"`
	// APIKey replaces the stored key when set. Leave it empty to keep the
	// current one; it is never returned.
	APIKey string `json:"api_key" api:"writeonly"`
	// ClearKey removes the stored key (a local server that needs none).
	ClearKey  bool `json:"clear_key"`
	MaxTokens int  `json:"max_tokens"`
}

// aiCheckURL accepts https anywhere and plain http only to a host on the
// internal destinations allowlist. Where the address may lead is checked
// again when connecting.
func aiCheckURL(raw string, allowed map[string]bool) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil {
		return errors.New("the base URL is not a valid absolute URL")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if allowed[host] {
			return nil
		}
		return fmt.Errorf("the base URL must use https unless %s is on the internal destinations allowlist (Administration → Network Allowlists)", host)
	}
	return errors.New("the base URL must be an https URL")
}

func (s *Server) handleSaveAIConnection(w http.ResponseWriter, r *http.Request) {
	var req saveAIConnectionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	req.Name, req.Model, req.BaseURL = strings.TrimSpace(req.Name), strings.TrimSpace(req.Model), strings.TrimSpace(req.BaseURL)
	if _, ok := aiProviders[req.Provider]; !ok {
		http.Error(w, "provider must be anthropic, openai, azure_openai, gemini or openai_compatible", http.StatusBadRequest)
		return
	}
	if req.Name == "" || req.Model == "" {
		http.Error(w, "name and model are required", http.StatusBadRequest)
		return
	}
	if req.MaxTokens < 0 || req.MaxTokens > 200000 {
		http.Error(w, "max_tokens must be between 0 (the default) and 200000", http.StatusBadRequest)
		return
	}
	if req.BaseURL == "" && (req.Provider == aiAzureOpenAI || req.Provider == aiOpenAICompatible) {
		http.Error(w, "this provider needs a base URL", http.StatusBadRequest)
		return
	}
	if req.BaseURL != "" {
		if err := aiCheckURL(req.BaseURL, s.webhookAllowedHosts(r.Context())); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	c := store.AIConnection{ID: r.PathValue("id"), Name: req.Name, Provider: req.Provider, BaseURL: req.BaseURL,
		Model: req.Model, MaxTokens: req.MaxTokens, CreatedBy: auth.CurrentUser(r.Context()).Username}
	if c.ID == "" {
		c.ID = idgen.New("aic-")
	} else {
		cur, err := s.store.GetAIConnection(r.Context(), c.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if cur == nil {
			http.Error(w, "no such connection", http.StatusNotFound)
			return
		}
		c.CreatedBy, c.APIKey = cur.CreatedBy, cur.APIKey
		// The key follows its provider: sending the stored key somewhere
		// else needs it typed again.
		if cur.APIKey != "" && req.APIKey == "" && !req.ClearKey && (cur.Provider != req.Provider || cur.BaseURL != req.BaseURL) {
			http.Error(w, "the provider or base URL changed: enter the API key again", http.StatusBadRequest)
			return
		}
	}
	switch {
	case req.ClearKey:
		c.APIKey = ""
	case req.APIKey != "":
		if s.vault == nil {
			http.Error(w, "API keys are stored encrypted, and no credential encryption key is configured (MUSTRA_CREDENTIAL_ENCRYPTION_KEY)", http.StatusServiceUnavailable)
			return
		}
		sealed, err := sealWith(s.vault, aiKeyAAD(c.ID), strings.TrimSpace(req.APIKey))
		if err != nil {
			http.Error(w, "could not encrypt the API key", http.StatusInternalServerError)
			return
		}
		c.APIKey = sealed
	}
	if c.APIKey == "" && c.Provider != aiOpenAICompatible {
		http.Error(w, "this provider needs an API key", http.StatusBadRequest)
		return
	}
	if err := s.auditStrict(r.Context(), auditEvent{Action: "settings.ai_connection", Actor: auth.CurrentUser(r.Context()).Username,
		Target: c.Name, Severity: "notice", Detail: map[string]any{"id": c.ID, "provider": c.Provider, "base_url": c.BaseURL,
			"model": c.Model, "key_changed": req.APIKey != "" || req.ClearKey}}); err != nil {
		http.Error(w, "the change could not be recorded in the audit log, so it was not made", http.StatusServiceUnavailable)
		return
	}
	if err := s.store.UpsertAIConnection(r.Context(), c); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	saved, err := s.store.GetAIConnection(r.Context(), c.ID)
	if err != nil || saved == nil {
		http.Error(w, "saved, but could not read it back", http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, viewAIConnection(*saved))
}

func (s *Server) handleDeleteAIConnection(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.auditStrict(r.Context(), auditEvent{Action: "settings.ai_connection_delete", Actor: auth.CurrentUser(r.Context()).Username,
		Target: id, Severity: "notice"}); err != nil {
		http.Error(w, "the change could not be recorded in the audit log, so it was not made", http.StatusServiceUnavailable)
		return
	}
	ok, err := s.store.DeleteAIConnection(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "no such connection", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// aiClientFor opens a connection's key and builds its client.
func (s *Server) aiClientFor(ctx context.Context, c store.AIConnection) (*aiClient, error) {
	key, err := openWith(s.vault, aiKeyAAD(c.ID), c.APIKey)
	if err != nil {
		return nil, errors.New("the stored API key cannot be decrypted; enter it again")
	}
	return &aiClient{provider: c.Provider, baseURL: c.BaseURL, model: c.Model, apiKey: key, maxTokens: c.MaxTokens,
		http: guardedHTTPClient(s.webhookAllowedHosts(ctx), aiTimeout)}, nil
}

// aiTestResponse is what POST /api/ai/connections/{id}/test answers.
type aiTestResponse struct {
	OK    bool   `json:"ok"`
	Reply string `json:"reply,omitempty"`
	Error string `json:"error,omitempty"`
}

func (s *Server) handleTestAIConnection(w http.ResponseWriter, r *http.Request) {
	c, err := s.store.GetAIConnection(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if c == nil {
		http.Error(w, "no such connection", http.StatusNotFound)
		return
	}
	client, err := s.aiClientFor(r.Context(), *c)
	if err != nil {
		writeJSONResponse(w, aiTestResponse{Error: err.Error()})
		return
	}
	client.maxTokens = 32
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	reply, err := client.complete(ctx, "You are checking that a connection works.",
		[]aiMessage{{Role: "user", Text: "Reply with the single word OK."}}, nil)
	if err != nil {
		writeJSONResponse(w, aiTestResponse{Error: err.Error()})
		return
	}
	writeJSONResponse(w, aiTestResponse{OK: true, Reply: clip(strings.TrimSpace(reply.Text), 200)})
}

// aiStatusResponse is what GET /api/ai/status answers: whether the
// assistant can be used, and with which connections.
type aiStatusResponse struct {
	Available bool `json:"available"`
	// Reason says why not, when it cannot.
	Reason      string             `json:"reason,omitempty"`
	Connections []aiConnectionPick `json:"connections"`
	// Provider data notice, for the page to show.
	Notice string `json:"notice"`
}

type aiConnectionPick struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Provider   string `json:"provider"`
	Model      string `json:"model"`
	SelfHosted bool   `json:"self_hosted"`
}

const aiNotice = "Your questions, and what the assistant's tools read about your endpoints to answer them, are sent to the model provider of the connection you choose."

// aiUsable lists the connections the assistant may use now, or why none.
func (s *Server) aiUsable(ctx context.Context) ([]store.AIConnection, string, error) {
	enabled, selfHosted := s.aiSettings(ctx)
	if !enabled {
		return nil, "The assistant is turned off. An administrator can turn it on under Administration → AI.", nil
	}
	conns, err := s.store.ListAIConnections(ctx)
	if err != nil {
		return nil, "", err
	}
	var out []store.AIConnection
	for _, c := range conns {
		if selfHosted && c.Provider != aiOpenAICompatible {
			continue
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		if selfHosted && len(conns) > 0 {
			return nil, "The assistant is limited to self-hosted connections, and none is set up.", nil
		}
		return nil, "No model connection is set up yet. An administrator can add one under Administration → AI.", nil
	}
	return out, "", nil
}

func (s *Server) handleAIStatus(w http.ResponseWriter, r *http.Request) {
	conns, reason, err := s.aiUsable(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := aiStatusResponse{Available: len(conns) > 0, Reason: reason, Connections: []aiConnectionPick{}, Notice: aiNotice}
	for _, c := range conns {
		out.Connections = append(out.Connections, aiConnectionPick{ID: c.ID, Name: c.Name, Provider: aiProviders[c.Provider],
			Model: c.Model, SelfHosted: c.Provider == aiOpenAICompatible})
	}
	writeJSONResponse(w, out)
}

// aiChatRequest is the body of POST /api/ai/chat: the conversation so
// far, as the page keeps it, oldest first, ending with the user's turn.
type aiChatRequest struct {
	// ConnectionID picks the connection; empty means the first usable one.
	ConnectionID string          `json:"connection_id"`
	Messages     []aiChatMessage `json:"messages" api:"required"`
}

type aiChatMessage struct {
	Role    string `json:"role" api:"required"` // user | assistant
	Content string `json:"content" api:"required"`
}

// aiChatResponse is what POST /api/ai/chat answers.
type aiChatResponse struct {
	// Reply is the model's answer, in Markdown. The page renders it with
	// every character escaped and no HTML passed through.
	Reply      string           `json:"reply"`
	ToolCalls  []aiToolCallView `json:"tool_calls"`
	Connection string           `json:"connection"`
	// Stopped says why the answer is incomplete, when it is: the step
	// limit or the time limit.
	Stopped string `json:"stopped,omitempty"`
}

// aiToolCallView is one tool the model called, as the page lists it.
type aiToolCallView struct {
	Tool      string          `json:"tool"`
	Arguments json.RawMessage `json:"arguments"`
	OK        bool            `json:"ok"`
	Error     string          `json:"error,omitempty"`
	// Action marks a request_* tool: it filed an approval request.
	Action bool `json:"action,omitempty"`
}

func (s *Server) handleAIChat(w http.ResponseWriter, r *http.Request) {
	var req aiChatRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if len(req.Messages) == 0 || req.Messages[len(req.Messages)-1].Role != "user" {
		http.Error(w, "messages must end with the user's turn", http.StatusBadRequest)
		return
	}
	if len(req.Messages) > aiMaxHistory {
		req.Messages = req.Messages[len(req.Messages)-aiMaxHistory:]
	}
	var msgs []aiMessage
	for _, m := range req.Messages {
		if m.Role != "user" && m.Role != "assistant" {
			http.Error(w, "a message's role must be user or assistant", http.StatusBadRequest)
			return
		}
		if len(m.Content) > aiMaxMessageBytes {
			http.Error(w, fmt.Sprintf("a message is longer than %d bytes", aiMaxMessageBytes), http.StatusBadRequest)
			return
		}
		msgs = append(msgs, aiMessage{Role: m.Role, Text: m.Content})
	}
	// A conversation the page trimmed may now start with the assistant;
	// providers want the user first.
	for len(msgs) > 0 && msgs[0].Role != "user" {
		msgs = msgs[1:]
	}
	conns, reason, err := s.aiUsable(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(conns) == 0 {
		http.Error(w, reason, http.StatusConflict)
		return
	}
	conn := conns[0]
	if req.ConnectionID != "" {
		found := false
		for _, c := range conns {
			if c.ID == req.ConnectionID {
				conn, found = c, true
			}
		}
		if !found {
			http.Error(w, "that connection is not available to the assistant", http.StatusConflict)
			return
		}
	}
	client, err := s.aiClientFor(r.Context(), conn)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), aiChatTimeout)
	defer cancel()
	u := auth.CurrentUser(ctx)
	tools := s.mcpToolsFor(ctx)
	run := func(ctx context.Context, call aiToolCall) (string, bool) {
		return s.aiRunTool(ctx, conn, call)
	}
	out, err := aiConverse(ctx, client, aiSystemPrompt(u.DisplayName, u.Username), msgs, aiToolSpecs(tools), run)
	out.Connection = conn.Name
	if err != nil {
		s.logger.Warn("assistant: provider call failed", "connection", conn.Name, "provider", conn.Provider, "error", err)
		var pe *aiProviderError
		if errors.As(err, &pe) && pe.Status == http.StatusTooManyRequests {
			if pe.RetryAfter != "" {
				w.Header().Set("Retry-After", pe.RetryAfter)
			}
			http.Error(w, err.Error(), http.StatusTooManyRequests)
			return
		}
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSONResponse(w, out)
}

func aiSystemPrompt(display, username string) string {
	who := firstNonEmpty(display, username)
	return "You are the assistant in the mustra console, a fleet-management and endpoint-operations platform, helping " + who + ". " +
		mcpInstructions + " " +
		"Your tools run with " + who + "'s own permissions; a tool refused for want of a permission means they lack it, so say so. " +
		"Answer in concise Markdown. Name endpoints by hostname. Say when a list was truncated, and when data is old or a check could not be evaluated. " +
		"Do not claim to have run, deployed, patched or changed anything: a request_* tool only files an approval request, so give its ID and link and say it waits for somebody else to approve it."
}

func aiToolSpecs(tools []mcpTool) []aiToolSpec {
	out := make([]aiToolSpec, 0, len(tools))
	for _, t := range tools {
		d := t.descriptor()
		out = append(out, aiToolSpec{Name: t.Name, Description: t.Description, Schema: d["inputSchema"].(map[string]any)})
	}
	return out
}

// aiConverse runs the model and its tool calls until it answers without
// calling one, it has taken aiMaxSteps turns, or ctx ends.
func aiConverse(ctx context.Context, client *aiClient, system string, msgs []aiMessage, tools []aiToolSpec,
	run func(context.Context, aiToolCall) (string, bool)) (aiChatResponse, error) {
	out := aiChatResponse{ToolCalls: []aiToolCallView{}}
	for step := 0; ; step++ {
		offer := tools
		if step == aiMaxSteps-1 {
			// The last turn gets no tools, so it has to answer with what it has.
			offer = nil
		}
		reply, err := client.complete(ctx, system, msgs, offer)
		if err != nil {
			if ctx.Err() != nil && len(out.ToolCalls) > 0 {
				out.Stopped = "the time limit was reached before the assistant finished"
				out.Reply = "I ran out of time before finishing. The tools I called are listed below."
				return out, nil
			}
			return out, err
		}
		if len(reply.ToolCalls) == 0 {
			out.Reply = reply.Text
			return out, nil
		}
		if step >= aiMaxSteps-1 {
			out.Reply = reply.Text
			out.Stopped = fmt.Sprintf("the assistant reached its limit of %d steps", aiMaxSteps)
			return out, nil
		}
		msgs = append(msgs, aiMessage{Role: "assistant", Text: reply.Text, ToolCalls: reply.ToolCalls})
		results := aiMessage{Role: "tool"}
		for _, call := range reply.ToolCalls {
			text, ok := run(ctx, call)
			view := aiToolCallView{Tool: call.Name, Arguments: call.Args, OK: ok, Action: strings.HasPrefix(call.Name, "request_")}
			if !ok {
				view.Error = clip(text, 300)
			}
			out.ToolCalls = append(out.ToolCalls, view)
			results.Results = append(results.Results, aiToolResult{CallID: call.ID, Name: call.Name, Content: text, IsError: !ok})
		}
		msgs = append(msgs, results)
	}
}

// aiRunTool audits one tool call and runs it as the signed-in user. The
// audit row comes first: a call that cannot be recorded does not run.
func (s *Server) aiRunTool(ctx context.Context, conn store.AIConnection, call aiToolCall) (string, bool) {
	u := auth.CurrentUser(ctx)
	if err := s.auditStrict(ctx, auditEvent{Action: "ai.tool_call", Actor: u.Username, Target: call.Name, Severity: "info",
		Detail: map[string]any{"connection": conn.Name, "provider": conn.Provider, "model": conn.Model,
			"arguments": clip(string(call.Args), aiAuditArgumentsMaxBytes)}}); err != nil {
		return "not run: the call could not be recorded in the audit log", false
	}
	res, rpcErr := s.mcpRunTool(withMCPVia(ctx, "the console assistant"), call.Name, call.Args)
	if rpcErr != nil {
		return rpcErr.Message, false
	}
	m, _ := res.(map[string]any)
	text := ""
	if content, ok := m["content"].([]any); ok && len(content) > 0 {
		if first, ok := content[0].(map[string]any); ok {
			text, _ = first["text"].(string)
		}
	}
	if len(text) > aiMaxToolResultBytes {
		text = clip(text, aiMaxToolResultBytes) + " (cut short: ask for fewer rows with limit or a filter)"
	}
	return text, m["isError"] != true
}
