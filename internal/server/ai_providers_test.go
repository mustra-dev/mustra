package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const aiTestKey = "sk-test-0123456789abcdef"

// standIn is a provider's API played by an httptest server: the first
// request is answered with a tool call, the second (which must carry the
// tool's result) with text. It records each request body and checks the
// key arrives in the header the provider expects.
type standIn struct {
	t        *testing.T
	mu       sync.Mutex
	bodies   []map[string]any
	paths    []string
	header   string // where the key must be
	prefix   string // e.g. "Bearer "
	first    string
	second   string
	sawError bool
}

func (si *standIn) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		si.t.Errorf("request body is not JSON: %s", raw)
	}
	si.mu.Lock()
	si.bodies = append(si.bodies, body)
	si.paths = append(si.paths, r.URL.RequestURI())
	n := len(si.bodies)
	si.mu.Unlock()
	if si.header != "" && r.Header.Get(si.header) != si.prefix+aiTestKey {
		si.t.Errorf("key not in %s: %q", si.header, r.Header.Get(si.header))
	}
	if strings.Contains(r.URL.RawQuery, aiTestKey) {
		si.t.Error("the key travelled in the URL")
	}
	w.Header().Set("Content-Type", "application/json")
	if n == 1 {
		io.WriteString(w, si.first)
		return
	}
	io.WriteString(w, si.second)
}

func (si *standIn) client(provider, baseURL string) *aiClient {
	return &aiClient{provider: provider, baseURL: baseURL, model: "test-model", apiKey: aiTestKey, http: http.DefaultClient}
}

var aiTestTools = []aiToolSpec{{Name: "list_endpoints", Description: "List endpoints",
	Schema: map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{"os": map[string]any{"type": "string"}}}}}

// roundTrip runs a conversation through c in which the model calls
// list_endpoints once, and checks what came back.
func roundTrip(t *testing.T, c *aiClient) (aiChatResponse, []aiToolCall) {
	t.Helper()
	var calls []aiToolCall
	run := func(_ context.Context, call aiToolCall) (string, bool) {
		calls = append(calls, call)
		return `{"endpoints":[{"hostname":"web-01"}],"total":1}`, true
	}
	out, err := aiConverse(context.Background(), c, "system prompt", []aiMessage{{Role: "user", Text: "Which Linux endpoints are there?"}}, aiTestTools, run)
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0].Name != "list_endpoints" || !strings.Contains(string(calls[0].Args), `"linux"`) {
		t.Fatalf("tool calls: %+v", calls)
	}
	if out.Reply != "web-01 runs Linux." || len(out.ToolCalls) != 1 || !out.ToolCalls[0].OK {
		t.Fatalf("answer: %+v", out)
	}
	return out, calls
}

func TestAIAnthropicToolRoundTrip(t *testing.T) {
	si := &standIn{t: t, header: "x-api-key",
		first:  `{"content":[{"type":"text","text":"Looking."},{"type":"tool_use","id":"toolu_1","name":"list_endpoints","input":{"os":"linux"}}],"stop_reason":"tool_use"}`,
		second: `{"content":[{"type":"text","text":"web-01 runs Linux."}],"stop_reason":"end_turn"}`}
	srv := httptest.NewServer(si)
	defer srv.Close()
	roundTrip(t, si.client(aiAnthropic, srv.URL))
	if si.paths[0] != "/v1/messages" {
		t.Errorf("path %s", si.paths[0])
	}
	first := si.bodies[0]
	if first["system"] != "system prompt" || first["model"] != "test-model" || first["max_tokens"].(float64) != aiDefaultMaxTokens {
		t.Errorf("first request: %v", first)
	}
	tool := first["tools"].([]any)[0].(map[string]any)
	if tool["name"] != "list_endpoints" || tool["input_schema"] == nil {
		t.Errorf("tools: %v", tool)
	}
	// The second request carries the assistant's tool_use and the result.
	msgs := si.bodies[1]["messages"].([]any)
	asst := msgs[1].(map[string]any)["content"].([]any)
	if asst[1].(map[string]any)["type"] != "tool_use" || asst[1].(map[string]any)["id"] != "toolu_1" {
		t.Errorf("assistant turn: %v", asst)
	}
	res := msgs[2].(map[string]any)
	block := res["content"].([]any)[0].(map[string]any)
	if res["role"] != "user" || block["type"] != "tool_result" || block["tool_use_id"] != "toolu_1" || !strings.Contains(block["content"].(string), "web-01") {
		t.Errorf("tool result turn: %v", res)
	}
}

func TestAIOpenAIToolRoundTrip(t *testing.T) {
	first := `{"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"list_endpoints","arguments":"{\"os\":\"linux\"}"}}]}}]}`
	second := `{"choices":[{"message":{"role":"assistant","content":"web-01 runs Linux."}}]}`
	for _, c := range []struct {
		provider, header, prefix, path string
		tokens                         string
	}{
		{aiOpenAI, "Authorization", "Bearer ", "/v1/chat/completions", "max_completion_tokens"},
		{aiOpenAICompatible, "Authorization", "Bearer ", "/v1/chat/completions", "max_tokens"},
		{aiAzureOpenAI, "api-key", "", "/openai/deployments/test-model/chat/completions?api-version=" + aiAzureAPIVersion, "max_completion_tokens"},
	} {
		t.Run(c.provider, func(t *testing.T) {
			si := &standIn{t: t, header: c.header, prefix: c.prefix, first: first, second: second}
			srv := httptest.NewServer(si)
			defer srv.Close()
			base := srv.URL
			if c.provider != aiAzureOpenAI {
				base += "/v1"
			}
			roundTrip(t, si.client(c.provider, base))
			if si.paths[0] != c.path {
				t.Errorf("path %s, want %s", si.paths[0], c.path)
			}
			if _, ok := si.bodies[0][c.tokens]; !ok {
				t.Errorf("no %s in %v", c.tokens, si.bodies[0])
			}
			msgs := si.bodies[1]["messages"].([]any)
			if msgs[0].(map[string]any)["role"] != "system" {
				t.Errorf("first message: %v", msgs[0])
			}
			calls := msgs[2].(map[string]any)["tool_calls"].([]any)
			fn := calls[0].(map[string]any)["function"].(map[string]any)
			if fn["name"] != "list_endpoints" || fn["arguments"] != `{"os":"linux"}` {
				t.Errorf("assistant tool call: %v", calls)
			}
			tool := msgs[3].(map[string]any)
			if tool["role"] != "tool" || tool["tool_call_id"] != "call_1" {
				t.Errorf("tool message: %v", tool)
			}
		})
	}
}

func TestAIGeminiToolRoundTrip(t *testing.T) {
	si := &standIn{t: t, header: "x-goog-api-key",
		first:  `{"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"list_endpoints","args":{"os":"linux"}}}]}}]}`,
		second: `{"candidates":[{"content":{"role":"model","parts":[{"text":"web-01 runs Linux."}]}}]}`}
	srv := httptest.NewServer(si)
	defer srv.Close()
	roundTrip(t, si.client(aiGemini, srv.URL))
	if si.paths[0] != "/v1beta/models/test-model:generateContent" {
		t.Errorf("path %s", si.paths[0])
	}
	decl := si.bodies[0]["tools"].([]any)[0].(map[string]any)["functionDeclarations"].([]any)[0].(map[string]any)
	if _, has := decl["parameters"].(map[string]any)["additionalProperties"]; has {
		t.Error("Gemini was sent additionalProperties, which it rejects")
	}
	contents := si.bodies[1]["contents"].([]any)
	if contents[1].(map[string]any)["role"] != "model" {
		t.Errorf("model turn: %v", contents[1])
	}
	fr := contents[2].(map[string]any)["parts"].([]any)[0].(map[string]any)["functionResponse"].(map[string]any)
	if fr["name"] != "list_endpoints" || fr["response"].(map[string]any)["result"] == nil {
		t.Errorf("function response: %v", fr)
	}
}

// A 429 says it is rate limiting and when to retry; an error body that
// echoes the key comes back without it.
func TestAIProviderErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages":
			w.Header().Set("Retry-After", "17")
			w.WriteHeader(http.StatusTooManyRequests)
			io.WriteString(w, `{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}`)
		default:
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"error":{"message":"Incorrect API key provided: `+aiTestKey+`"}}`)
		}
	}))
	defer srv.Close()
	c := &aiClient{provider: aiAnthropic, baseURL: srv.URL, model: "m", apiKey: aiTestKey, http: http.DefaultClient}
	_, err := c.complete(context.Background(), "s", []aiMessage{{Role: "user", Text: "hi"}}, nil)
	var pe *aiProviderError
	if !errors.As(err, &pe) || pe.Status != 429 || pe.RetryAfter != "17" || !strings.Contains(err.Error(), "rate limiting") || !strings.Contains(err.Error(), "slow down") {
		t.Errorf("429: %v", err)
	}
	c.provider, c.baseURL = aiOpenAI, srv.URL+"/v1"
	_, err = c.complete(context.Background(), "s", []aiMessage{{Role: "user", Text: "hi"}}, nil)
	if err == nil || strings.Contains(err.Error(), aiTestKey) || !strings.Contains(err.Error(), "[key]") {
		t.Errorf("401 error leaks or loses the message: %v", err)
	}
}

// The loop stops: a model that keeps calling tools gets aiMaxSteps turns,
// the last without tools, and the answer says it was stopped.
func TestAIConverseIsBounded(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["tools"] == nil {
			io.WriteString(w, `{"choices":[{"message":{"content":"Here is what I found."}}]}`)
			return
		}
		io.WriteString(w, `{"choices":[{"message":{"content":"","tool_calls":[{"id":"c","type":"function","function":{"name":"list_endpoints","arguments":"{}"}}]}}]}`)
	}))
	defer srv.Close()
	c := &aiClient{provider: aiOpenAI, baseURL: srv.URL, model: "m", apiKey: aiTestKey, http: http.DefaultClient}
	ran := 0
	out, err := aiConverse(context.Background(), c, "s", []aiMessage{{Role: "user", Text: "go"}}, aiTestTools,
		func(context.Context, aiToolCall) (string, bool) { ran++; return "{}", true })
	if err != nil {
		t.Fatal(err)
	}
	if requests != aiMaxSteps || ran != aiMaxSteps-1 || out.Reply != "Here is what I found." {
		t.Errorf("requests %d, tools run %d, reply %q", requests, ran, out.Reply)
	}
}

// A base URL is https, or http only to an allowlisted host.
func TestAICheckURL(t *testing.T) {
	allowed := map[string]bool{"ollama.lan": true}
	for raw, ok := range map[string]bool{
		"https://api.example.com/v1":  true,
		"http://ollama.lan:11434/v1":  true,
		"http://other.lan:11434/v1":   false,
		"ftp://x":                     false,
		"https://user:pw@example.com": false,
		"not a url":                   false,
	} {
		if err := aiCheckURL(raw, allowed); (err == nil) != ok {
			t.Errorf("%s: %v", raw, err)
		}
	}
}
