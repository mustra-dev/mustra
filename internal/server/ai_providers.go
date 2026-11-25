package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// The assistant's model providers, called over their own HTTP APIs with
// net/http: Anthropic's Messages API, OpenAI's Chat Completions (also
// Azure OpenAI and any OpenAI-compatible server such as Ollama, LM Studio,
// vLLM or OpenRouter), and Google's Gemini generateContent. Each turns the
// same conversation and tool list into its own wire format and back.
//
// The API key goes only into the request header its provider expects. It
// is never logged, and an error a provider sends back is scrubbed of it
// before anyone sees it, since some providers echo what they were sent.

const (
	aiAnthropic        = "anthropic"
	aiOpenAI           = "openai"
	aiAzureOpenAI      = "azure_openai"
	aiGemini           = "gemini"
	aiOpenAICompatible = "openai_compatible"

	aiDefaultMaxTokens = 4096
	aiAzureAPIVersion  = "2024-10-21"
	aiMaxResponseBytes = 4 << 20
)

// aiProviders names each provider type for the console.
var aiProviders = map[string]string{
	aiAnthropic:        "Anthropic",
	aiOpenAI:           "OpenAI",
	aiAzureOpenAI:      "Azure OpenAI",
	aiGemini:           "Google Gemini",
	aiOpenAICompatible: "OpenAI-compatible (Ollama, LM Studio, vLLM, OpenRouter…)",
}

// aiMessage is one turn of a conversation, in no provider's format.
type aiMessage struct {
	Role string // user | assistant | tool
	Text string
	// ToolCalls are what an assistant turn asked to run.
	ToolCalls []aiToolCall
	// Results answer the previous assistant turn's ToolCalls, in a tool
	// turn.
	Results []aiToolResult
}

type aiToolCall struct {
	ID   string
	Name string
	Args json.RawMessage
}

type aiToolResult struct {
	CallID  string
	Name    string
	Content string
	IsError bool
}

// aiToolSpec is a tool as a model is told about it.
type aiToolSpec struct {
	Name        string
	Description string
	Schema      map[string]any
}

type aiReply struct {
	Text      string
	ToolCalls []aiToolCall
}

// aiProviderError is a provider's refusal, with whether trying again
// later could help.
type aiProviderError struct {
	Status     int
	Message    string
	RetryAfter string
}

func (e *aiProviderError) Error() string {
	switch {
	case e.Status == http.StatusTooManyRequests:
		msg := "the provider is rate limiting this key (HTTP 429)"
		if e.RetryAfter != "" {
			msg += "; retry after " + e.RetryAfter + "s"
		}
		if e.Message != "" {
			msg += ": " + e.Message
		}
		return msg
	case e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden:
		return fmt.Sprintf("the provider refused the API key (HTTP %d): %s", e.Status, e.Message)
	}
	return fmt.Sprintf("the provider answered HTTP %d: %s", e.Status, e.Message)
}

// aiClient is one connection, ready to call.
type aiClient struct {
	provider  string
	baseURL   string
	model     string
	apiKey    string
	maxTokens int
	http      *http.Client
}

func (c *aiClient) scrub(s string) string {
	if c.apiKey != "" {
		s = strings.ReplaceAll(s, c.apiKey, "[key]")
	}
	return s
}

// post sends body as JSON to url and decodes the answer into out.
func (c *aiClient) post(ctx context.Context, target string, headers map[string]string, body, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("the connection's URL is not valid")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return errors.New(c.scrub("could not reach the provider: " + err.Error()))
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, aiMaxResponseBytes))
	if err != nil {
		return fmt.Errorf("reading the provider's answer: %w", err)
	}
	if resp.StatusCode >= 300 {
		return &aiProviderError{Status: resp.StatusCode, Message: c.scrub(providerErrorText(data)), RetryAfter: resp.Header.Get("Retry-After")}
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("the provider's answer is not the JSON expected: %s", c.scrub(clip(string(data), 200)))
	}
	return nil
}

// providerErrorText pulls the message out of the error bodies providers
// send ({"error":{"message":…}} in some form), or a short excerpt.
func providerErrorText(data []byte) string {
	var e struct {
		Error   json.RawMessage `json:"error"`
		Message string          `json:"message"`
	}
	if json.Unmarshal(data, &e) == nil {
		var inner struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(e.Error, &inner) == nil && inner.Message != "" {
			return clip(inner.Message, 300)
		}
		var s string
		if json.Unmarshal(e.Error, &s) == nil && s != "" {
			return clip(s, 300)
		}
		if e.Message != "" {
			return clip(e.Message, 300)
		}
	}
	return clip(strings.TrimSpace(string(data)), 300)
}

func (c *aiClient) tokens() int {
	if c.maxTokens > 0 {
		return c.maxTokens
	}
	return aiDefaultMaxTokens
}

// complete sends the conversation and answers the model's next turn.
func (c *aiClient) complete(ctx context.Context, system string, msgs []aiMessage, tools []aiToolSpec) (aiReply, error) {
	switch c.provider {
	case aiAnthropic:
		return c.anthropic(ctx, system, msgs, tools)
	case aiOpenAI, aiAzureOpenAI, aiOpenAICompatible:
		return c.openai(ctx, system, msgs, tools)
	case aiGemini:
		return c.gemini(ctx, system, msgs, tools)
	}
	return aiReply{}, fmt.Errorf("unknown provider %q", c.provider)
}

func argsObject(raw json.RawMessage) json.RawMessage {
	if len(bytes.TrimSpace(raw)) == 0 || string(raw) == "null" {
		return json.RawMessage("{}")
	}
	return raw
}

// --- Anthropic Messages API ----------------------------------------------

func (c *aiClient) anthropic(ctx context.Context, system string, msgs []aiMessage, tools []aiToolSpec) (aiReply, error) {
	type block map[string]any
	var wire []map[string]any
	for _, m := range msgs {
		switch m.Role {
		case "user":
			wire = append(wire, map[string]any{"role": "user", "content": m.Text})
		case "assistant":
			var content []block
			if m.Text != "" {
				content = append(content, block{"type": "text", "text": m.Text})
			}
			for _, tc := range m.ToolCalls {
				content = append(content, block{"type": "tool_use", "id": tc.ID, "name": tc.Name, "input": argsObject(tc.Args)})
			}
			wire = append(wire, map[string]any{"role": "assistant", "content": content})
		case "tool":
			var content []block
			for _, r := range m.Results {
				content = append(content, block{"type": "tool_result", "tool_use_id": r.CallID, "content": r.Content, "is_error": r.IsError})
			}
			wire = append(wire, map[string]any{"role": "user", "content": content})
		}
	}
	body := map[string]any{"model": c.model, "max_tokens": c.tokens(), "system": system, "messages": wire}
	if len(tools) > 0 {
		var ts []map[string]any
		for _, t := range tools {
			ts = append(ts, map[string]any{"name": t.Name, "description": t.Description, "input_schema": t.Schema})
		}
		body["tools"] = ts
	}
	base := strings.TrimRight(firstNonEmpty(c.baseURL, "https://api.anthropic.com"), "/")
	var out struct {
		Content []struct {
			Type  string          `json:"type"`
			Text  string          `json:"text"`
			ID    string          `json:"id"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		} `json:"content"`
	}
	if err := c.post(ctx, base+"/v1/messages", map[string]string{"x-api-key": c.apiKey, "anthropic-version": "2023-06-01"}, body, &out); err != nil {
		return aiReply{}, err
	}
	var r aiReply
	var text []string
	for _, b := range out.Content {
		switch b.Type {
		case "text":
			text = append(text, b.Text)
		case "tool_use":
			r.ToolCalls = append(r.ToolCalls, aiToolCall{ID: b.ID, Name: b.Name, Args: argsObject(b.Input)})
		}
	}
	r.Text = strings.Join(text, "\n")
	return r, nil
}

// --- OpenAI Chat Completions (and Azure, and compatible servers) ----------

func (c *aiClient) openaiTarget() (string, map[string]string, error) {
	switch c.provider {
	case aiAzureOpenAI:
		if c.baseURL == "" {
			return "", nil, errors.New("Azure OpenAI needs the resource's endpoint as the base URL")
		}
		u := strings.TrimRight(c.baseURL, "/") + "/openai/deployments/" + url.PathEscape(c.model) +
			"/chat/completions?api-version=" + aiAzureAPIVersion
		return u, map[string]string{"api-key": c.apiKey}, nil
	case aiOpenAICompatible:
		if c.baseURL == "" {
			return "", nil, errors.New("an OpenAI-compatible connection needs a base URL, such as http://ollama.internal:11434/v1")
		}
	}
	h := map[string]string{}
	if c.apiKey != "" {
		h["Authorization"] = "Bearer " + c.apiKey
	}
	return strings.TrimRight(firstNonEmpty(c.baseURL, "https://api.openai.com/v1"), "/") + "/chat/completions", h, nil
}

func (c *aiClient) openai(ctx context.Context, system string, msgs []aiMessage, tools []aiToolSpec) (aiReply, error) {
	target, headers, err := c.openaiTarget()
	if err != nil {
		return aiReply{}, err
	}
	wire := []map[string]any{{"role": "system", "content": system}}
	for _, m := range msgs {
		switch m.Role {
		case "user":
			wire = append(wire, map[string]any{"role": "user", "content": m.Text})
		case "assistant":
			msg := map[string]any{"role": "assistant", "content": m.Text}
			if len(m.ToolCalls) > 0 {
				var calls []map[string]any
				for _, tc := range m.ToolCalls {
					calls = append(calls, map[string]any{"id": tc.ID, "type": "function",
						"function": map[string]any{"name": tc.Name, "arguments": string(argsObject(tc.Args))}})
				}
				msg["tool_calls"] = calls
			}
			wire = append(wire, msg)
		case "tool":
			for _, r := range m.Results {
				wire = append(wire, map[string]any{"role": "tool", "tool_call_id": r.CallID, "content": r.Content})
			}
		}
	}
	body := map[string]any{"model": c.model, "messages": wire}
	// OpenAI's current models take max_completion_tokens; compatible
	// servers mostly still read max_tokens.
	if c.provider == aiOpenAICompatible {
		body["max_tokens"] = c.tokens()
	} else {
		body["max_completion_tokens"] = c.tokens()
	}
	if len(tools) > 0 {
		var ts []map[string]any
		for _, t := range tools {
			ts = append(ts, map[string]any{"type": "function", "function": map[string]any{
				"name": t.Name, "description": t.Description, "parameters": t.Schema}})
		}
		body["tools"] = ts
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content   *string `json:"content"`
				ToolCalls []struct {
					ID       string `json:"id"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := c.post(ctx, target, headers, body, &out); err != nil {
		return aiReply{}, err
	}
	if len(out.Choices) == 0 {
		return aiReply{}, errors.New("the provider answered with no choices")
	}
	m := out.Choices[0].Message
	var r aiReply
	if m.Content != nil {
		r.Text = *m.Content
	}
	for i, tc := range m.ToolCalls {
		args := json.RawMessage(tc.Function.Arguments)
		if !json.Valid(args) {
			args = json.RawMessage("{}")
		}
		id := tc.ID
		if id == "" {
			id = "call_" + strconv.Itoa(i)
		}
		r.ToolCalls = append(r.ToolCalls, aiToolCall{ID: id, Name: tc.Function.Name, Args: argsObject(args)})
	}
	return r, nil
}

// --- Google Gemini generateContent ------------------------------------------

// geminiSchema is a tool schema as Gemini accepts it: its OpenAPI subset
// has no additionalProperties.
func geminiSchema(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, val := range t {
			if k == "additionalProperties" {
				continue
			}
			out[k] = geminiSchema(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = geminiSchema(val)
		}
		return out
	}
	return v
}

func (c *aiClient) gemini(ctx context.Context, system string, msgs []aiMessage, tools []aiToolSpec) (aiReply, error) {
	type part map[string]any
	var contents []map[string]any
	for _, m := range msgs {
		switch m.Role {
		case "user":
			contents = append(contents, map[string]any{"role": "user", "parts": []part{{"text": m.Text}}})
		case "assistant":
			var parts []part
			if m.Text != "" {
				parts = append(parts, part{"text": m.Text})
			}
			for _, tc := range m.ToolCalls {
				parts = append(parts, part{"functionCall": map[string]any{"name": tc.Name, "args": argsObject(tc.Args)}})
			}
			contents = append(contents, map[string]any{"role": "model", "parts": parts})
		case "tool":
			var parts []part
			for _, r := range m.Results {
				// The response must be an object.
				resp := map[string]any{"result": json.RawMessage(mustJSONString(r.Content))}
				var obj map[string]any
				if json.Unmarshal([]byte(r.Content), &obj) == nil {
					resp = map[string]any{"result": obj}
				}
				if r.IsError {
					resp = map[string]any{"error": r.Content}
				}
				parts = append(parts, part{"functionResponse": map[string]any{"name": r.Name, "response": resp}})
			}
			contents = append(contents, map[string]any{"role": "user", "parts": parts})
		}
	}
	body := map[string]any{
		"systemInstruction": map[string]any{"parts": []part{{"text": system}}},
		"contents":          contents,
		"generationConfig":  map[string]any{"maxOutputTokens": c.tokens()},
	}
	if len(tools) > 0 {
		var decls []map[string]any
		for _, t := range tools {
			decls = append(decls, map[string]any{"name": t.Name, "description": t.Description, "parameters": geminiSchema(t.Schema)})
		}
		body["tools"] = []map[string]any{{"functionDeclarations": decls}}
	}
	base := strings.TrimRight(firstNonEmpty(c.baseURL, "https://generativelanguage.googleapis.com"), "/")
	target := base + "/v1beta/models/" + url.PathEscape(c.model) + ":generateContent"
	var out struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text         string `json:"text"`
					FunctionCall *struct {
						ID   string          `json:"id"`
						Name string          `json:"name"`
						Args json.RawMessage `json:"args"`
					} `json:"functionCall"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := c.post(ctx, target, map[string]string{"x-goog-api-key": c.apiKey}, body, &out); err != nil {
		return aiReply{}, err
	}
	if len(out.Candidates) == 0 {
		return aiReply{}, errors.New("the provider answered with no candidates (the prompt may have been blocked)")
	}
	var r aiReply
	var text []string
	for i, p := range out.Candidates[0].Content.Parts {
		if p.FunctionCall != nil {
			id := firstNonEmpty(p.FunctionCall.ID, "call_"+strconv.Itoa(i))
			r.ToolCalls = append(r.ToolCalls, aiToolCall{ID: id, Name: p.FunctionCall.Name, Args: argsObject(p.FunctionCall.Args)})
		} else if p.Text != "" {
			text = append(text, p.Text)
		}
	}
	r.Text = strings.Join(text, "")
	return r, nil
}

func mustJSONString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// aiTimeout bounds one provider call.
const aiTimeout = 90 * time.Second
