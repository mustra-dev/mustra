package enforcekinds

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
)

func compileAnsibleJSON(t *testing.T, c AnsibleConfig) ([]proto.EnforceSetting, error) {
	t.Helper()
	return Compile(KindAnsible, mustJSON(t, c))
}

func TestAnsibleCompilesToOnePlaybookSetting(t *testing.T) {
	c := AnsibleConfig{
		Playbook: "- name: Baseline\n  hosts: localhost\n  tasks:\n    - name: motd\n      ansible.builtin.copy: {dest: /etc/motd, content: \"{{ motd }}\"}\n",
		Vars:     "motd: hello\nports: [22, 443]\nnested: {a: 1}\n",
		Diff:     true,
		Severity: "high",
	}
	got, err := compileAnsibleJSON(t, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d settings, want 1", len(got))
	}
	s := got[0]
	if s.Ansible == nil || s.RemediateLinux+s.RemediateWindows+s.RemediateDarwin != "" {
		t.Fatalf("setting should carry the playbook and no shell remediation: %+v", s)
	}
	if s.Name != "Ansible: Baseline" || s.Severity != "high" || !s.Ansible.Diff {
		t.Errorf("name/severity/diff = %q/%q/%v", s.Name, s.Severity, s.Ansible.Diff)
	}
	// An agent that predates the Ansible field reads this rule as one it
	// does not understand, which is unknown: never a pass, never a fix.
	if len(s.Rules) != 1 || s.Rules[0] != "ansible:playbook" {
		t.Errorf("rules = %q", s.Rules)
	}
	if !strings.Contains(s.Ansible.Playbook, "hosts: localhost") {
		t.Errorf("playbook not carried: %q", s.Ansible.Playbook)
	}
	var vars map[string]any
	if err := json.Unmarshal([]byte(s.Ansible.Vars), &vars); err != nil {
		t.Fatalf("vars are not a JSON object: %q: %v", s.Ansible.Vars, err)
	}
	if vars["motd"] != "hello" || len(vars["ports"].([]any)) != 2 {
		t.Errorf("vars = %v", vars)
	}
	if s.Ansible.Vars != `{"motd":"hello","nested":{"a":1},"ports":[22,443]}` {
		t.Errorf("vars are not canonical JSON: %s", s.Ansible.Vars)
	}

	// Recompiling the same form gives the same setting, id included, so a
	// re-save does not clear the policy's history.
	again, _ := compileAnsibleJSON(t, c)
	if again[0].ID != s.ID || again[0].Ansible.Vars != s.Ansible.Vars || again[0].Ansible.Playbook != s.Ansible.Playbook {
		t.Error("compiling the same form twice differs")
	}
}

func TestAnsibleRefusesWhatWouldFailOrMislead(t *testing.T) {
	cases := map[string]struct {
		playbook, vars, severity, want string
	}{
		"empty":          {playbook: "  ", want: "needs a playbook"},
		"not yaml":       {playbook: "- hosts: localhost\n  tasks: [\n", want: "not valid YAML"},
		"not a list":     {playbook: "hosts: localhost\ntasks: []\n", want: "list of plays"},
		"play not a map": {playbook: "- just a string\n", want: "not a mapping"},
		"two documents":  {playbook: "- hosts: localhost\n---\n- hosts: localhost\n", want: "more than one YAML document"},
		"no hosts":       {playbook: "- name: x\n  tasks: []\n", want: "hosts is required"},
		// A group name matches nothing in the inventory "localhost,", and a
		// playbook that runs nothing would otherwise look compliant.
		"other hosts":     {playbook: "- hosts: webservers\n  tasks: []\n", want: `"webservers"`},
		"host list":       {playbook: "- hosts: [localhost, db1]\n  tasks: []\n", want: `"db1"`},
		"import":          {playbook: "- import_playbook: other.yml\n", want: "import_playbook"},
		"ssh connection":  {playbook: "- hosts: all\n  connection: ssh\n  tasks: []\n", want: "connection must be local"},
		"vars not a map":  {playbook: "- hosts: all\n  tasks: []\n", vars: "- a\n- b\n", want: "must be a mapping"},
		"vars not yaml":   {playbook: "- hosts: all\n  tasks: []\n", vars: "a: [\n", want: "variables are not valid YAML"},
		"bad severity":    {playbook: "- hosts: all\n  tasks: []\n", severity: "urgent", want: "severity"},
		"too big":         {playbook: "- hosts: all\n  tasks: []\n#" + strings.Repeat("x", maxPlaybookBytes), want: "limit"},
		"non-string keys": {playbook: "- hosts: all\n  tasks: []\n", vars: "1: one\n", want: "variables"},
	}
	for name, c := range cases {
		_, err := compileAnsibleJSON(t, AnsibleConfig{Playbook: c.playbook, Vars: c.vars, Severity: c.severity})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want it to mention %q", name, err, c.want)
		}
	}
}

func TestAnsibleAcceptsLocalHostPatterns(t *testing.T) {
	for _, hosts := range []string{"localhost", "all", "127.0.0.1", "[localhost]", "\"localhost,all\""} {
		pb := "- hosts: " + hosts + "\n  connection: local\n  tasks: []\n"
		got, err := compileAnsibleJSON(t, AnsibleConfig{Playbook: pb})
		if err != nil {
			t.Errorf("hosts %s: %v", hosts, err)
			continue
		}
		if got[0].Name != "Ansible playbook" || got[0].Severity != "medium" || got[0].Ansible.Vars != "" {
			t.Errorf("hosts %s: unnamed play / default severity / no vars: %+v", hosts, got[0])
		}
	}
}

func TestAnsibleKindIsLinux(t *testing.T) {
	for _, k := range Kinds() {
		if k.Kind == KindAnsible && k.OS != "linux" {
			t.Fatalf("the Ansible kind targets %q, want linux", k.OS)
		}
	}
	if !Valid(KindAnsible) {
		t.Fatal("ansible is not a valid kind")
	}
}
