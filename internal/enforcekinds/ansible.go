package enforcekinds

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/mustra-dev/mustra/internal/proto"
)

// The Ansible kind differs from the others in one way that matters: it does
// not compile into rules and a remediation command. A playbook already says
// what must be true and how to make it so, and ansible-playbook --check
// already answers "would anything change" -- re-expressing it as shell would
// lose exactly the idempotence that makes a playbook worth holding. So the
// setting carries the playbook itself (proto.AnsiblePlaybook) and the agent
// runs it; report mode, dry run, the give-up counter and the audit trail
// are still the engine's, unchanged.

// Limits on what is shipped in every run_enforce command. A playbook bigger
// than this belongs in a role on the endpoint or a package, not in a
// message the server sends every half hour.
const (
	maxPlaybookBytes = 256 << 10
	maxVarsBytes     = 64 << 10
)

// ansibleRule is the setting's rule. An agent that knows the Ansible field
// never evaluates it; an older one does not understand it either, and so
// reports the setting as unknown rather than passing or fixing it.
const ansibleRule = "ansible:playbook"

// AnsibleConfig is the Ansible policy's form.
type AnsibleConfig struct {
	// Playbook is the playbook's YAML: a list of plays, each for hosts all
	// or localhost.
	Playbook string `json:"playbook"`
	// Vars is an optional YAML (or JSON) mapping of extra variables.
	Vars string `json:"vars"`
	// Diff records what each changed task would change in the results.
	Diff bool `json:"diff"`
	// Severity is the setting's severity: low, medium, high or critical.
	Severity string `json:"severity"`
}

// DefaultAnsible is a small, harmless example to start from.
func DefaultAnsible() AnsibleConfig {
	return AnsibleConfig{
		Severity: "medium",
		Playbook: `- name: Message of the day
  hosts: localhost
  gather_facts: false
  tasks:
    - name: /etc/motd says this machine is managed
      ansible.builtin.copy:
        dest: /etc/motd
        content: "This machine is managed by mustra.\n"
        owner: root
        group: root
        mode: "0644"
`,
	}
}

// localHosts are the host patterns that match the inventory the agent runs
// with ("localhost,"). Anything else matches nothing there, and a playbook
// that runs nothing would read as compliant.
var localHosts = map[string]bool{"all": true, "localhost": true, "127.0.0.1": true}

func compileAnsible(c AnsibleConfig) ([]proto.EnforceSetting, error) {
	playbook := strings.TrimSpace(strings.ReplaceAll(c.Playbook, "\r\n", "\n"))
	if playbook == "" {
		return nil, fmt.Errorf("the policy needs a playbook")
	}
	if len(playbook) > maxPlaybookBytes {
		return nil, fmt.Errorf("the playbook is %d KiB; the limit is %d KiB", len(playbook)>>10, maxPlaybookBytes>>10)
	}
	name, err := checkPlaybook(playbook)
	if err != nil {
		return nil, err
	}
	vars, err := compileVars(c.Vars)
	if err != nil {
		return nil, err
	}
	severity := strings.ToLower(strings.TrimSpace(c.Severity))
	switch severity {
	case "":
		severity = "medium"
	case "low", "medium", "high", "critical":
	default:
		return nil, fmt.Errorf("severity must be low, medium, high or critical")
	}
	return []proto.EnforceSetting{{
		ID:       stableID(KindAnsible, "playbook"),
		Name:     name,
		Severity: severity,
		Rules:    []string{ansibleRule},
		Ansible:  &proto.AnsiblePlaybook{Playbook: playbook + "\n", Vars: vars, Diff: c.Diff},
	}}, nil
}

// checkPlaybook parses the playbook the way ansible-playbook will read it
// and refuses what would fail or mislead on the endpoint. It returns the
// setting's name.
func checkPlaybook(src string) (string, error) {
	dec := yaml.NewDecoder(strings.NewReader(src))
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return "", fmt.Errorf("the playbook is not valid YAML: %v", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return "", fmt.Errorf("the playbook is not valid YAML: %v", err)
		}
		return "", fmt.Errorf("the playbook has more than one YAML document; ansible-playbook reads only one")
	}
	plays, ok := doc.([]any)
	if !ok || len(plays) == 0 {
		return "", fmt.Errorf("a playbook is a YAML list of plays (each starting with \"- name:\" or \"- hosts:\")")
	}
	first := ""
	for i, p := range plays {
		play, ok := p.(map[string]any)
		if !ok {
			return "", fmt.Errorf("play %d is not a mapping of keys such as hosts and tasks", i+1)
		}
		label := fmt.Sprintf("play %d", i+1)
		if n, ok := play["name"].(string); ok && strings.TrimSpace(n) != "" {
			label = fmt.Sprintf("play %q", strings.TrimSpace(n))
			if first == "" {
				first = strings.TrimSpace(n)
			}
		}
		for _, k := range []string{"import_playbook", "ansible.builtin.import_playbook", "include"} {
			if _, ok := play[k]; ok {
				return "", fmt.Errorf("%s uses %s: only the playbook itself is sent to the endpoint, so files it imports are not there", label, k)
			}
		}
		if err := checkHosts(play["hosts"]); err != nil {
			return "", fmt.Errorf("%s: %w", label, err)
		}
		if conn, ok := play["connection"]; ok && conn != "local" {
			return "", fmt.Errorf("%s: connection must be local (or left out); the endpoint runs the playbook against itself", label)
		}
	}
	if first == "" {
		return "Ansible playbook", nil
	}
	name := "Ansible: " + first
	if len(name) > 200 {
		name = name[:200]
	}
	return name, nil
}

func checkHosts(v any) error {
	var patterns []string
	switch h := v.(type) {
	case nil:
		return fmt.Errorf("hosts is required; use hosts: localhost")
	case string:
		for _, p := range strings.Split(h, ",") {
			patterns = append(patterns, strings.TrimSpace(p))
		}
	case []any:
		for _, p := range h {
			s, ok := p.(string)
			if !ok {
				return fmt.Errorf("hosts must be localhost or all")
			}
			patterns = append(patterns, strings.TrimSpace(s))
		}
	default:
		return fmt.Errorf("hosts must be localhost or all")
	}
	for _, p := range patterns {
		if !localHosts[p] {
			return fmt.Errorf("hosts is %q, which matches nothing when the endpoint runs the playbook against itself; use hosts: localhost (or all)", p)
		}
	}
	return nil
}

// compileVars turns the vars form into the JSON object the agent passes
// with -e @file. Re-encoding through Go gives sorted keys, so an unchanged
// form compiles to identical bytes and saving it keeps the policy's history.
func compileVars(src string) (string, error) {
	if strings.TrimSpace(src) == "" {
		return "", nil
	}
	if len(src) > maxVarsBytes {
		return "", fmt.Errorf("the variables are %d KiB; the limit is %d KiB", len(src)>>10, maxVarsBytes>>10)
	}
	var v any
	if err := yaml.Unmarshal([]byte(src), &v); err != nil {
		return "", fmt.Errorf("the variables are not valid YAML: %v", err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return "", fmt.Errorf("the variables must be a mapping, such as \"motd: hello\"")
	}
	if len(m) == 0 {
		return "", nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return "", fmt.Errorf("the variables cannot be passed to ansible: %v", err)
	}
	return strings.TrimSpace(buf.String()), nil
}
