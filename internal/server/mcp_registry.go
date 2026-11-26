package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mustra-dev/mustra/internal/server/auth"
)

// The tool registry: every tool the MCP endpoint offers, described once,
// so that anything else offering mustra's tools to a model offers the same
// ones with the same checks. A tool is a name, what it does, the JSON
// schema of its arguments, the permission a caller needs to see or call
// it, and the function that answers it as the caller.
//
// Two kinds. A read tool answers from what mustra already holds, through
// the same route (and so the same permission checks and content filters)
// the console uses. An action tool never acts: it files an approval
// request, attributed to whoever called it, and a person decides it in the
// console. A model reads text that endpoints and third parties wrote, so
// nothing it decides runs without somebody else agreeing.

// mcpTool is one tool in the registry.
type mcpTool struct {
	Name        string
	Title       string
	Description string
	// Properties are the argument schema's properties; Required names
	// those that must be present. The schema is always a closed object.
	Properties map[string]any
	Required   []string
	// Permission is what a caller must hold to be offered the tool and
	// to call it. Read tools need fleet.read; an action tool needs the
	// permission the action itself needs.
	Permission string
	// Action marks a tool that files an approval request instead of
	// reading. It is annotated destructive, since approving it changes
	// endpoints.
	Action bool
	// OpenWorld marks a tool that reaches outside mustra (GitHub release
	// notes).
	OpenWorld bool
	Call      func(ctx context.Context, s *Server, args json.RawMessage) (any, *mcpError)
}

// descriptor is the tool as tools/list describes it.
func (t mcpTool) descriptor() map[string]any {
	schema := map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties":           t.Properties,
	}
	if schema["properties"] == nil {
		schema["properties"] = map[string]any{}
	}
	if len(t.Required) > 0 {
		schema["required"] = t.Required
	}
	ann := map[string]any{"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": t.OpenWorld}
	if t.Action {
		ann = map[string]any{"readOnlyHint": false, "destructiveHint": true, "idempotentHint": false, "openWorldHint": false}
	}
	return map[string]any{
		"name":        t.Name,
		"title":       t.Title,
		"description": t.Description,
		"annotations": ann,
		"inputSchema": schema,
	}
}

// mcpRegistry lists every tool in the order tools/list offers them, from
// the files that define them.
func mcpRegistry() []mcpTool {
	out := []mcpTool{mcpListContainersTool, mcpChangesTool, mcpPendingUpdatesTool}
	out = append(out, mcpFleetTools...)
	return append(out, mcpActionTools...)
}

// mcpFindTool returns the registered tool called name.
func mcpFindTool(name string) (mcpTool, bool) {
	for _, t := range mcpRegistry() {
		if t.Name == name {
			return t, true
		}
	}
	return mcpTool{}, false
}

// mcpMayUse reports whether the caller may see and call t.
func (s *Server) mcpMayUse(ctx context.Context, t mcpTool) bool {
	if t.Permission == "" {
		return true
	}
	if s.auth == nil {
		return false
	}
	ok, err := s.auth.HasPermission(ctx, auth.CurrentUser(ctx), t.Permission)
	return err == nil && ok
}

// mcpToolsFor is the registry as the caller may use it.
func (s *Server) mcpToolsFor(ctx context.Context) []mcpTool {
	var out []mcpTool
	for _, t := range mcpRegistry() {
		if s.mcpMayUse(ctx, t) {
			out = append(out, t)
		}
	}
	return out
}

// mcpRunTool calls one tool as the caller. An unknown name is a protocol
// error; a tool the caller may not use is a tool error the model can read,
// naming the permission, so it can tell its user what to ask for.
func (s *Server) mcpRunTool(ctx context.Context, name string, args json.RawMessage) (any, *mcpError) {
	t, ok := mcpFindTool(name)
	if !ok {
		return nil, &mcpError{mcpInvalidParams, "unknown tool"}
	}
	if !s.mcpMayUse(ctx, t) {
		return mcpToolError(fmt.Sprintf("%s needs the %q permission, which this caller does not hold", t.Name, t.Permission)), nil
	}
	return t.Call(ctx, s, args)
}

// mcpDecode reads a tool's arguments into v, refusing fields the schema
// does not have. No arguments at all leaves v's defaults.
func mcpDecode(raw json.RawMessage, v any) bool {
	if len(raw) == 0 || string(raw) == "null" {
		return true
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	return dec.Decode(v) == nil
}

// mcpSchemaError is the answer to arguments that do not match a schema.
func mcpSchemaError() map[string]any {
	return mcpToolError("arguments do not match the tool's schema")
}

// mcpLimitProp is the schema of a tool's row limit.
func mcpLimitProp(what string) map[string]any {
	return map[string]any{"type": "integer", "minimum": 1, "maximum": mcpMaxRows,
		"description": fmt.Sprintf("most %s to return (default %d)", what, mcpDefaultRows)}
}

// mcpCheckLimit says why a limit argument is out of range. Tools set the
// default before decoding, so an explicit 0 is a mistake to report.
func mcpCheckLimit(limit *int) (any, bool) {
	if *limit < 1 || *limit > mcpMaxRows {
		return mcpToolError(fmt.Sprintf("limit must be between 1 and %d", mcpMaxRows)), false
	}
	return nil, true
}
