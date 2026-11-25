//go:build e2e

package e2e

import (
	"net/http"
	"strings"
	"testing"
)

// stepEnforceAnsible holds a file in place with an Ansible playbook policy
// on the enrolled endpoints (the endpoint image carries ansible-core):
// report mode finds the drift and lists the task without touching the
// file, enforce mode applies the playbook and re-checks, and the next pass
// is compliant.
func stepEnforceAnsible(t *testing.T, r *run) {
	const path = "/etc/mustra-e2e-ansible.conf"
	r.ep1.sh("rm -f " + path)
	playbook := "- name: e2e baseline\n  hosts: localhost\n  gather_facts: false\n  tasks:\n" +
		"    - name: e2e file holds the greeting\n      ansible.builtin.copy:\n        dest: " + path + "\n" +
		"        content: \"{{ greeting }}\\n\"\n        mode: \"0644\"\n"
	policy := map[string]any{
		"name": "e2e ansible", "os": "linux", "mode": "report", "kind": "ansible",
		"config": map[string]any{"playbook": playbook, "vars": "greeting: hello from e2e", "diff": true},
	}
	var saved struct {
		Policy struct {
			ID string `json:"id"`
		} `json:"policy"`
	}
	r.c.call(http.MethodPost, "/api/enforce/policies", policy, http.StatusOK, &saved)
	id := saved.Policy.ID
	defer r.c.do(http.MethodDelete, "/api/enforce/policies/"+id, nil)

	type result struct {
		AgentID string `json:"agent_id"`
		State   string `json:"state"`
		Detail  string `json:"detail"`
		Output  string `json:"output"`
	}
	runPolicy := func() result {
		t.Helper()
		var summary struct {
			Endpoints int `json:"endpoints"`
			Unreached int `json:"unreached"`
		}
		r.c.call(http.MethodPost, "/api/enforce/policies/"+id+"/run", map[string]bool{"dry_run": false}, http.StatusOK, &summary)
		if summary.Endpoints == 0 || summary.Unreached != 0 {
			t.Fatalf("run reached %d endpoints, %d unreached", summary.Endpoints, summary.Unreached)
		}
		var out struct {
			Results []result `json:"results"`
		}
		r.c.call(http.MethodGet, "/api/enforce/results?policy="+id, nil, http.StatusOK, &out)
		for _, res := range out.Results {
			if res.AgentID == r.agent1.AgentID {
				return res
			}
		}
		t.Fatalf("no result for %s: %+v", r.agent1.Hostname, out.Results)
		return result{}
	}

	res := runPolicy()
	if res.State != "drifted" || !strings.Contains(res.Detail, "e2e file holds the greeting") || !strings.Contains(res.Output, "+hello from e2e") {
		t.Fatalf("report mode: %+v, want drifted naming the task with its diff", res)
	}
	if out, err := r.ep1.sh("test -e " + path); err == nil {
		t.Fatalf("report mode created %s: %s", path, out)
	}

	policy["id"], policy["mode"] = id, "enforce"
	r.c.call(http.MethodPut, "/api/enforce/policies/"+id, policy, http.StatusOK, nil)
	if res = runPolicy(); res.State != "remediated" {
		t.Fatalf("enforce mode: %+v, want remediated", res)
	}
	if got := strings.TrimSpace(r.ep1.must("cat " + path)); got != "hello from e2e" {
		t.Fatalf("%s holds %q after the fix", path, got)
	}
	if res = runPolicy(); res.State != "compliant" {
		t.Fatalf("after the fix: %+v, want compliant", res)
	}
}
