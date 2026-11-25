# The mustra agent's stdout callback for ansible-playbook.
#
# The agent writes this file into a private temporary directory for one run
# and removes it afterwards. It prints a single JSON document, in the shape
# of the ansible.posix json callback (plays, tasks, hosts, stats), so the
# agent reads results rather than scraping text and needs nothing beyond
# ansible-core on the endpoint. Messages and diffs are cut short here: the
# agent bounds them again, but a task printing megabytes should not have to
# cross the pipe first.
from __future__ import annotations

import json

from ansible.plugins.callback import CallbackBase

DOCUMENTATION = """
name: mustra_json
type: stdout
short_description: one JSON document for the mustra agent
description:
  - Prints every task result and the recap as a single JSON document.
"""

MAX_MSG = 500
MAX_DIFF = 4000


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "stdout"
    CALLBACK_NAME = "mustra_json"

    def __init__(self, *args, **kwargs):
        super(CallbackModule, self).__init__(*args, **kwargs)
        self.plays = []
        self.tasks = {}

    def _play(self):
        if not self.plays:
            self.plays.append({"play": {"name": ""}, "tasks": []})
        return self.plays[-1]

    def v2_playbook_on_play_start(self, play):
        self.plays.append({"play": {"name": play.get_name()}, "tasks": []})

    def _task(self, task):
        entry = self.tasks.get(task._uuid)
        if entry is None:
            entry = {"task": {"name": task.get_name(), "id": task._uuid}, "hosts": {}}
            self.tasks[task._uuid] = entry
            self._play()["tasks"].append(entry)
        return entry

    def v2_playbook_on_task_start(self, task, is_conditional):
        self._task(task)

    def v2_playbook_on_handler_task_start(self, task):
        self._task(task)

    def _diff(self, r):
        diffs = []
        if r.get("diff"):
            diffs.append(r["diff"])
        for item in r.get("results") or []:
            if isinstance(item, dict) and item.get("changed") and item.get("diff"):
                diffs.append(item["diff"])
        text = ""
        for d in diffs:
            try:
                text += self._get_diff(d)
            except Exception:
                pass
        return text[:MAX_DIFF]

    def _record(self, result, **flags):
        r = result._result
        out = {"action": result._task.action, "changed": bool(r.get("changed", False))}
        out.update(flags)
        msg = r.get("msg") or r.get("stderr") or ""
        if msg:
            out["msg"] = str(msg)[:MAX_MSG]
        if r.get("censored"):
            out["censored"] = True
        diff = self._diff(r)
        if diff:
            out["mustra_diff"] = diff
        self._task(result._task)["hosts"][result._host.get_name()] = out

    def v2_runner_on_ok(self, result, **kwargs):
        self._record(result)

    def v2_runner_on_failed(self, result, ignore_errors=False, **kwargs):
        self._record(result, failed=True, mustra_ignored=bool(ignore_errors))

    def v2_runner_on_unreachable(self, result, **kwargs):
        self._record(result, unreachable=True)

    def v2_runner_on_skipped(self, result, **kwargs):
        self._record(result, skipped=True)

    def v2_playbook_on_stats(self, stats):
        summary = {}
        for host in sorted(stats.processed.keys()):
            summary[host] = stats.summarize(host)
        doc = {"plays": self.plays, "stats": summary}
        self._display.display(json.dumps(doc, sort_keys=True, default=str))
