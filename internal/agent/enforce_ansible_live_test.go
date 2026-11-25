package agent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
)

// TestLiveAnsible runs real ansible-playbook through the Enforce path:
// drift, fix, compliant, and the unknowns. Opt-in, because it needs
// ansible-core and changes files (only under a temporary directory):
//
//	MUSTRA_LIVE_ANSIBLE=1 go test ./internal/agent/ -run LiveAnsible -v
func TestLiveAnsible(t *testing.T) {
	if os.Getenv("MUSTRA_LIVE_ANSIBLE") == "" {
		t.Skip("set MUSTRA_LIVE_ANSIBLE=1 to run against a real ansible-playbook")
	}
	if ansibleGOOS != "linux" {
		t.Skip("Ansible policies are Linux-only")
	}
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Fatal("ansible-playbook is not installed")
	}
	target := filepath.Join(t.TempDir(), "managed.conf")
	playbook := `- name: Live check
  hosts: localhost
  gather_facts: false
  tasks:
    - name: managed.conf holds the greeting
      ansible.builtin.copy:
        dest: ` + target + `
        content: "{{ greeting }}\n"
        mode: "0600"
    - name: nothing to do here
      ansible.builtin.debug:
        msg: hello
`
	setting := func(pb string, enforce, diff bool) proto.EnforceSetting {
		return proto.EnforceSetting{ID: "set-live", Name: "Ansible: Live check", Rules: []string{"ansible:playbook"}, Enforce: enforce,
			Ansible: &proto.AnsiblePlaybook{Playbook: pb, Vars: `{"greeting":"hello from mustra"}`, Diff: diff}}
	}
	ctx := context.Background()

	r := enforceSetting(ctx, setting(playbook, false, true))
	t.Logf("report: %s %q\n%s", r.State, r.Detail, r.Output)
	if r.State != "drifted" || !strings.Contains(r.Detail, "1 task would change: managed.conf holds the greeting") || !strings.Contains(r.Output, "hello from mustra") {
		t.Fatalf("missing file should be drift with its diff: %+v", r)
	}
	if _, err := os.Stat(target); err == nil {
		t.Fatal("report mode changed the endpoint")
	}

	r = enforceSetting(ctx, setting(playbook, true, false))
	t.Logf("enforce: %s %q\n%s", r.State, r.Detail, r.Output)
	if r.State != "remediated" {
		t.Fatalf("enforce: %+v", r)
	}
	if data, _ := os.ReadFile(target); string(data) != "hello from mustra\n" {
		t.Fatalf("file after the fix: %q", data)
	}

	r = enforceSetting(ctx, setting(playbook, false, false))
	if r.State != "compliant" {
		t.Fatalf("after the fix: %+v", r)
	}

	for name, c := range map[string]struct{ playbook, want string }{
		"does not parse":  {"- hosts: localhost\n  tasks: [\n", "--check failed"},
		"fails in check":  {"- hosts: localhost\n  gather_facts: false\n  tasks:\n    - name: boom\n      ansible.builtin.fail:\n        msg: nope\n", "boom: nope"},
		"matches nothing": {"- hosts: webservers\n  gather_facts: false\n  tasks:\n    - ansible.builtin.debug: {msg: hi}\n", "ran nothing"},
		"missing module":  {"- hosts: localhost\n  gather_facts: false\n  tasks:\n    - no.such.module: {}\n", "--check failed"},
	} {
		r := enforceSetting(ctx, setting(c.playbook, true, false))
		t.Logf("%s: %s %q", name, r.State, r.Detail)
		if r.State != "unknown" || !strings.Contains(r.Detail, c.want) {
			t.Errorf("%s: %+v, want unknown mentioning %q", name, r, c.want)
		}
	}
}
