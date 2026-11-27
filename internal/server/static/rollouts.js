// Ring rollouts (ring_rollouts.go): a patch run or an Enforce promotion
// going out ring by ring through a deployment plan. This draws each
// rollout's progress per ring with Resume and Abort, and edits the plans.
// Shared by Patch and Enforce; needs app.js (escapeHtml, sx, fmtTime,
// fmtAgo, showToast) and rollouts.css.
const Rollouts = (() => {
  let groupsCache = null;
  let namesCache = null;
  let plansCache = null;

  async function getJSON(url) {
    const r = await fetch(url);
    if (r.status === 401) { window.location.href = "/login"; return {}; }
    if (!r.ok) throw new Error((await r.text()).trim() || r.statusText);
    return r.json();
  }

  async function send(url, method, body) {
    const r = await fetch(url, {
      method, headers: body === undefined ? {} : { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!r.ok) throw new Error((await r.text()).trim() || r.statusText);
    return r.status === 204 ? null : r.json();
  }

  async function groups(force) {
    if (!groupsCache || force) groupsCache = (await getJSON("/api/groups")).groups || [];
    return groupsCache;
  }

  async function hostnames() {
    if (!namesCache) {
      const d = await getJSON("/api/agents").catch(() => ({}));
      const list = Array.isArray(d) ? d : (d.agents || []);
      namesCache = Object.fromEntries(list.map(a => [a.agent_id, a.hostname || a.agent_id]));
    }
    return namesCache;
  }

  async function plans(force) {
    if (!plansCache || force) plansCache = (await getJSON("/api/deployment-plans")).plans || [];
    return plansCache;
  }

  // planOptions is the <option> list for a "Rollout plan" select: the
  // first entry keeps today's behaviour, everything at once.
  function planOptions(list, allAtOnceLabel) {
    return `<option value="">${escapeHtml(allAtOnceLabel || "None — all at once")}</option>` +
      list.map(p => `<option value="${escapeHtml(p.id)}">${escapeHtml(p.name)} (${escapeHtml(p.rings.length)} ring${p.rings.length === 1 ? "" : "s"})</option>`).join("");
  }

  function soakLabel(min) {
    if (!min) return "no soak";
    if (min % 1440 === 0) return `soak ${min / 1440} d`;
    if (min % 60 === 0) return `soak ${min / 60} h`;
    return `soak ${min} min`;
  }

  function thresholdLabel(ring) {
    const parts = [];
    if (ring.success_rate) parts.push(`${ring.success_rate}% must succeed`);
    if (ring.min_success) parts.push(`at least ${ring.min_success} must succeed`);
    return parts.length ? parts.join(", ") : "no threshold";
  }

  function selectorLabel(ring, gmap) {
    if (ring.group_id) {
      const g = gmap[ring.group_id];
      return g ? `group ${g.name}` : "a deleted group";
    }
    return `${ring.percent}% of the target`;
  }

  const STATE_LABEL = { pending: "waiting", running: "running", soaking: "soaking", passed: "passed", failed: "failed", skipped: "skipped" };

  // The bar's segments in a fixed order, each with its own colour, so a
  // failure never reads as a timeout and a no-response never as success.
  const SEGMENTS = [
    ["succeeded", "succeeded", "var(--viz-good)"],
    ["failed", "failed", "var(--viz-critical)"],
    ["timed_out", "timed out", "var(--viz-warning)"],
    ["no_response", "no response", "var(--viz-none)"],
    ["unknown", "unknown", "color-mix(in srgb, var(--viz-none) 55%, transparent)"],
    ["open", "working", "var(--viz-progress)"],
  ];

  function outcomeBlock(o) {
    const total = o.total || 0;
    if (!total) return `<div class="rollout-counts">no endpoints yet</div>`;
    const bar = SEGMENTS.filter(([k]) => o[k] > 0)
      .map(([k, label, color]) => `<span ${sx(`flex:${escapeHtml(o[k])};background:${color}`)} title="${escapeHtml(`${label}: ${escapeHtml(o[k])}`)}"></span>`).join("");
    const counts = SEGMENTS.filter(([k]) => o[k] > 0).map(([k, label]) => `<b>${escapeHtml(o[k])}</b> ${escapeHtml(label)}`).join(" · ");
    return `<div class="rollout-bar" role="img" aria-label="${escapeHtml(`${o.succeeded || 0} of ${escapeHtml(total)} succeeded`)}">${bar}</div>
      <div class="rollout-counts">${counts} <span>of ${escapeHtml(total)}</span></div>`;
  }

  function ringRow(r, ring, i, gmap, names) {
    const current = (r.status === "running" || r.status === "halted") && i === r.current_ring;
    const st = ring.state || "pending";
    const when = [];
    if (st === "soaking" && ring.soak_until) when.push(`soaking until ${fmtTime(ring.soak_until)}`);
    else if (ring.started_at) when.push(`started ${fmtTime(ring.started_at)}`);
    const run = r.kind === "patch" && ring.run_id
      ? `<a href="/patches?run=${encodeURIComponent(ring.run_id)}#deployments">deployment</a>` : "";
    const members = (ring.agent_ids || []);
    const memberList = members.length
      ? `<details class="rollout-members"><summary>${escapeHtml(members.length)} endpoint${members.length === 1 ? "" : "s"}</summary><ul>${
          members.map(id => `<li>${escapeHtml(names[id] || id)}</li>`).join("")}</ul></details>` : "";
    const note = ring.note
      ? `<div class="rollout-ring-note${st === "failed" ? " is-bad" : ""}">${escapeHtml(ring.note)}</div>` : "";
    return `<li class="rollout-ring${current ? " is-current" : ""}">
      <span class="rollout-ring-no" aria-hidden="true">${escapeHtml(i + 1)}</span>
      <div>
        <div class="rollout-ring-name">${escapeHtml(ring.name || `Ring ${escapeHtml(i + 1)}`)}</div>
        <div class="rollout-ring-sub">${escapeHtml(selectorLabel(ring, gmap))} · ${escapeHtml(thresholdLabel(ring))} · ${escapeHtml(soakLabel(ring.wait_minutes))}</div>
      </div>
      <div>${st === "pending" || st === "skipped" ? `<div class="rollout-counts">${st === "skipped" ? "skipped" : "not started"}</div>` : outcomeBlock(ring.outcome || {})}</div>
      <div class="rollout-ring-end">
        <span class="rollout-status st-${escapeHtml(st)}">${escapeHtml(STATE_LABEL[st] || st)}</span>
        ${when.length ? `<span class="rollout-counts">${escapeHtml(when.join(" · "))}</span>` : ""}
        ${run}
      </div>
      ${note}${memberList}
    </li>`;
  }

  function card(r, opts, gmap, names) {
    const open = r.status === "running" || r.status === "halted";
    const title = r.source_name || (r.kind === "patch" ? "Patch deployment" : "Enforce promotion");
    const what = r.kind === "enforce" ? "Promotion to enforce" : (r.source_id ? "Scheduled patching" : "Deploy now");
    const meta = [`${what} through ${r.plan_name || "a plan"}`, `started ${fmtTime(r.created_at)} by ${r.created_by || "—"}`];
    if (r.finished_at) meta.push(`ended ${fmtTime(r.finished_at)}`);
    if (r.status === "completed" && r.untouched > 0) {
      meta.push(r.kind === "enforce"
        ? `${r.untouched} endpoint(s) in no ring switched to enforce with the policy`
        : `${r.untouched} endpoint(s) in no ring were not patched`);
    }
    const actions = opts.canAct && open ? `<div class="rollout-actions">
        ${r.status === "halted" ? `<button class="tiny" type="button" data-rollout-act="resume" data-id="${escapeHtml(r.id)}">Resume</button>` : ""}
        <button class="tiny danger" type="button" data-rollout-act="abort" data-id="${escapeHtml(r.id)}">Abort</button>
      </div>` : "";
    const halt = r.status === "halted" && r.halt_reason
      ? `<div class="rollout-halt"><b>Halted.</b> ${escapeHtml(r.halt_reason)}</div>`
      : (r.status === "aborted" && r.halt_reason ? `<div class="rollout-meta">Ended: ${escapeHtml(r.halt_reason)}</div>` : "");
    return `<article class="rollout-card${r.status === "halted" ? " is-halted" : ""}" id="rollout-${escapeHtml(r.id)}">
      <div class="rollout-head">
        <div>
          <div class="rollout-title">${escapeHtml(title)} <span class="rollout-status st-${escapeHtml(r.status)}">${escapeHtml(r.status)}</span></div>
          <div class="rollout-meta">${escapeHtml(meta.join(" · "))}</div>
        </div>
        ${actions}
      </div>
      ${halt}
      <ol class="rollout-rings">${(r.rings || []).map((ring, i) => ringRow(r, ring, i, gmap, names)).join("")}</ol>
    </article>`;
  }

  // mountRollouts draws the rollouts of one kind (and optionally one
  // schedule or policy) into el, refreshing while any is open.
  // opts: { kind, sourceId, canAct, empty, limit, onChange }
  function mountRollouts(el, opts) {
    let timer = null;
    async function render() {
      clearTimeout(timer);
      let list = [];
      try {
        const q = new URLSearchParams({ kind: opts.kind });
        if (opts.sourceId) q.set("source_id", opts.sourceId);
        if (opts.limit) q.set("limit", String(opts.limit));
        const [d, gs, names] = await Promise.all([getJSON("/api/rollouts?" + q), groups().catch(() => []), hostnames()]);
        list = d.rollouts || [];
        const gmap = Object.fromEntries(gs.map(g => [g.id, g]));
        el.innerHTML = list.length
          ? `<div class="rollout-list">${list.map(r => card(r, opts, gmap, names)).join("")}</div>`
          : `<div class="rollout-empty">${escapeHtml(opts.empty || "No rollouts yet.")}</div>`;
      } catch (e) {
        el.innerHTML = `<div class="rollout-empty">Could not load rollouts: ${escapeHtml(e.message)}</div>`;
      }
      if (opts.onChange) opts.onChange(list);
      // A rollout moves once a minute at most; refresh while one is open.
      if (list.some(r => r.status === "running" || r.status === "halted")) timer = setTimeout(render, 20000);
    }
    el.addEventListener("click", async e => {
      const btn = e.target.closest("[data-rollout-act]");
      if (!btn) return;
      const act = btn.dataset.rolloutAct;
      const base = opts.kind === "enforce" ? "/api/enforce/rollouts/" : "/api/patches/rollouts/";
      const question = act === "resume"
        ? "Resume this rollout? The ring it halted on is accepted as it stands and the next ring starts within a minute."
        : (opts.kind === "enforce"
          ? "Abort this rollout? No further ring is promoted, and every endpoint goes back to report mode."
          : "Abort this rollout? No further ring starts, and endpoints of the current ring still waiting for their maintenance window are cancelled.");
      if (!window.confirm(question)) return;
      btn.disabled = true;
      try {
        await send(base + encodeURIComponent(btn.dataset.id) + "/" + act, "POST");
        showToast(act === "resume" ? "Rollout resumed" : "Rollout aborted", "ok");
      } catch (err) {
        showToast(err.message, "error");
      }
      render();
    });
    render();
    return { reload: render };
  }

  // mountPlans lists the deployment plans and, for an account that may
  // change them (deploy.manage), edits them. opts: { canEdit, onChange }
  function mountPlans(el, opts) {
    let editing = null;
    let draft = [];

    function ringEditor(ring, i, gs) {
      const isGroup = !!ring.group_id || ring._type === "group";
      const soak = ring.wait_minutes || 0;
      const unit = soak && soak % 1440 === 0 ? 1440 : (soak && soak % 60 === 0 ? 60 : 1);
      return `<div class="plan-ring" data-ring="${escapeHtml(i)}">
        <span class="rollout-ring-no" aria-hidden="true">${escapeHtml(i + 1)}</span>
        <div><label for="pr-name-${escapeHtml(i)}">Name</label><input id="pr-name-${escapeHtml(i)}" data-f="name" value="${escapeHtml(ring.name || "")}" placeholder="Ring ${escapeHtml(i + 1)}"></div>
        <div><label for="pr-type-${escapeHtml(i)}">Endpoints</label><select id="pr-type-${escapeHtml(i)}" data-f="type">
          <option value="percent"${isGroup ? "" : " selected"}>A share of the target</option>
          <option value="group"${isGroup ? " selected" : ""}>A computer group</option></select></div>
        ${isGroup
          ? `<div><label for="pr-group-${escapeHtml(i)}">Group</label><select id="pr-group-${escapeHtml(i)}" data-f="group_id"><option value="">choose…</option>${
              gs.map(g => `<option value="${escapeHtml(g.id)}"${g.id === ring.group_id ? " selected" : ""}>${escapeHtml(g.name)}</option>`).join("")}</select></div>`
          : `<div><label for="pr-pct-${escapeHtml(i)}">Percent of the target</label><input id="pr-pct-${escapeHtml(i)}" data-f="percent" type="number" min="1" max="100" value="${escapeHtml(ring.percent || "")}"></div>`}
        <div><label for="pr-rate-${escapeHtml(i)}">Must succeed (%)</label><input id="pr-rate-${escapeHtml(i)}" data-f="success_rate" type="number" min="0" max="100" value="${escapeHtml(ring.success_rate || "")}" placeholder="none"></div>
        <div><label for="pr-soak-${escapeHtml(i)}">Soak</label><input id="pr-soak-${escapeHtml(i)}" data-f="soak" type="number" min="0" value="${soak ? soak / unit : ""}" placeholder="0"></div>
        <div><label for="pr-unit-${escapeHtml(i)}">Unit</label><select id="pr-unit-${escapeHtml(i)}" data-f="unit">
          <option value="1"${unit === 1 ? " selected" : ""}>minutes</option><option value="60"${unit === 60 ? " selected" : ""}>hours</option><option value="1440"${unit === 1440 ? " selected" : ""}>days</option></select></div>
        <div class="plan-ring-tools">
          <button class="tiny" type="button" data-ring-move="-1" aria-label="Move ring ${escapeHtml(i + 1)} up"${i === 0 ? " disabled" : ""}>↑</button>
          <button class="tiny" type="button" data-ring-move="1" aria-label="Move ring ${escapeHtml(i + 1)} down"${i === draft.length - 1 ? " disabled" : ""}>↓</button>
          <button class="tiny danger" type="button" data-ring-del aria-label="Remove ring ${escapeHtml(i + 1)}">✕</button>
        </div>
      </div>`;
    }

    function readDraft() {
      el.querySelectorAll(".plan-ring").forEach(row => {
        const i = Number(row.dataset.ring), ring = draft[i];
        const v = f => row.querySelector(`[data-f="${f}"]`);
        ring.name = v("name").value.trim();
        ring._type = v("type").value;
        if (ring._type === "group") { ring.group_id = v("group_id") ? v("group_id").value : ring.group_id || ""; ring.percent = 0; }
        else { ring.percent = v("percent") ? Number(v("percent").value) || 0 : ring.percent || 0; ring.group_id = ""; }
        ring.success_rate = Number(v("success_rate").value) || 0;
        ring.wait_minutes = Math.round((Number(v("soak").value) || 0) * Number(v("unit").value));
      });
    }

    async function render() {
      let list = [], gs = [];
      try { [list, gs] = await Promise.all([plans(true), groups(true)]); }
      catch (e) { el.innerHTML = `<div class="rollout-empty">Could not load plans: ${escapeHtml(e.message)}</div>`; return; }
      const gmap = Object.fromEntries(gs.map(g => [g.id, g]));
      const rows = list.length ? list.map(p => `<tr>
          <td>${escapeHtml(p.name)}</td>
          <td>${p.rings.map((r, i) => `${escapeHtml(i + 1)}. ${escapeHtml(r.name || "Ring " + (i + 1))} — ${escapeHtml(selectorLabel(r, gmap))}, ${escapeHtml(thresholdLabel(r))}, ${escapeHtml(soakLabel(r.wait_minutes))}`).join("<br>")}</td>
          <td>${escapeHtml(p.created_by || "—")}</td>
          <td>${opts.canEdit ? `<button class="tiny" type="button" data-plan-edit="${escapeHtml(p.id)}">Edit</button>
            <button class="tiny danger" type="button" data-plan-del="${escapeHtml(p.id)}">Delete</button>` : ""}</td></tr>`).join("")
        : `<tr><td class="empty" colspan="4">No plans yet.${opts.canEdit ? " Create one below." : ""}</td></tr>`;
      el.innerHTML = `<div class="table-scroll"><table>
          <thead><tr><th>Plan</th><th>Rings, in order</th><th>Created by</th><th>Action</th></tr></thead>
          <tbody>${rows}</tbody></table></div>
        ${opts.canEdit ? `<h3 class="u-fs-12 u-c-text-muted u-tt-upper u-ls-006em u-m-18-0-10">${editing ? "Edit plan" : "New plan"}</h3>
        <div class="form-grid"><div class="field"><label for="plan-name">Name</label><input id="plan-name" placeholder="Canary 5%, then 30%, then everyone" value="${escapeHtml(editing ? editing.name : "")}"></div></div>
        <div class="plan-rings">${draft.map((r, i) => ringEditor(r, i, gs)).join("")}</div>
        <p class="plan-hint">Each ring takes endpoints only from the deployment's own target: a group ring is the group's members in it,
          a share is that percentage of the whole target from what earlier rings left (the same endpoints each time the plan runs).
          A ring must reach its threshold, counting endpoints that never answered as not succeeded, before the soak starts; the next ring
          starts when the soak ends and the threshold still holds. Endpoints in no ring are left alone, so end with 100% to cover everyone.</p>
        <div class="panel-actions">
          <button class="tiny" type="button" id="plan-add-ring">Add ring</button>
          <button class="primary" type="button" id="plan-save">${editing ? "Save plan" : "Create plan"}</button>
          ${editing ? `<button type="button" id="plan-cancel">Cancel</button>` : ""}
        </div>` : `<p class="plan-hint">Creating and changing plans needs the deploy.manage permission.</p>`}`;
    }

    function startDraft(p) {
      editing = p || null;
      draft = p ? p.rings.map(r => ({ ...r, _type: r.group_id ? "group" : "percent" }))
        : [{ name: "Canary", _type: "percent", percent: 5, success_rate: 100, wait_minutes: 1440 },
          { name: "Everyone else", _type: "percent", percent: 100, success_rate: 95, wait_minutes: 0 }];
    }

    el.addEventListener("change", e => {
      if (e.target.matches('[data-f="type"]')) { readDraft(); render(); }
    });
    el.addEventListener("click", async e => {
      const t = e.target;
      if (t.id === "plan-add-ring") { readDraft(); draft.push({ name: "", _type: "percent", percent: 100 }); render(); return; }
      if (t.id === "plan-cancel") { startDraft(null); render(); return; }
      if (t.matches("[data-ring-del]")) { readDraft(); draft.splice(Number(t.closest(".plan-ring").dataset.ring), 1); render(); return; }
      if (t.matches("[data-ring-move]")) {
        readDraft();
        const i = Number(t.closest(".plan-ring").dataset.ring), j = i + Number(t.dataset.ringMove);
        [draft[i], draft[j]] = [draft[j], draft[i]];
        render();
        return;
      }
      if (t.matches("[data-plan-edit]")) { startDraft((plansCache || []).find(p => p.id === t.dataset.planEdit)); render(); return; }
      if (t.matches("[data-plan-del]")) {
        const p = (plansCache || []).find(x => x.id === t.dataset.planDel);
        if (!p || !window.confirm(`Delete the plan "${p.name}"? Rollouts already running keep their own copy of it.`)) return;
        try { await send("/api/deployment-plans/" + encodeURIComponent(p.id), "DELETE"); showToast("Plan deleted", "ok"); }
        catch (err) { showToast(err.message, "error"); }
        await render();
        if (opts.onChange) opts.onChange(plansCache || []);
        return;
      }
      if (t.id === "plan-save") {
        readDraft();
        const name = el.querySelector("#plan-name").value.trim();
        const rings = draft.map(({ _type, ...r }) => r);
        const body = { name, kind: rings.every(r => !r.group_id) ? "dynamic" : "custom", rings };
        t.disabled = true;
        try {
          await send(editing ? "/api/deployment-plans/" + encodeURIComponent(editing.id) : "/api/deployment-plans", editing ? "PUT" : "POST", body);
          showToast(editing ? "Plan saved" : "Plan created", "ok");
          startDraft(null);
        } catch (err) {
          showToast(err.message, "error");
          t.disabled = false;
          return;
        }
        await render();
        if (opts.onChange) opts.onChange(plansCache || []);
      }
    });
    startDraft(null);
    render();
    return { reload: render };
  }

  return { mountRollouts, mountPlans, plans, planOptions, send };
})();
