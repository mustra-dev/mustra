# To do

Open work, kept here so it can be picked up. Add to it when deferring something, and remove an item when it ships: [CHANGELOG.md](CHANGELOG.md) records what did.

## Security hardening

- [ ] Ship the Python runtime and the Windows tray through the signed Go update path; today only the agent binary updates that way and the others need the installer re-run.
- [ ] Replace bash-language-server's vulnerable braces/micromatch/fast-glob chain in tools/script-service once a non-breaking release exists.
- [ ] Review the open CodeQL alerts in code scanning, fix what is real and dismiss the rest with a reason.
- [ ] Run inventory-and-patching mode on a real Home Assistant host. The add-on has been tested with a stand-in Supervisor only.

## Containers

- [ ] Check private registries using registry logins the operator provides; checks are anonymous today.
- [ ] Turn registry checks off from a client profile; today it is an agent flag per host.
- [ ] Read Docker on Windows through its named pipe, and rootless engines' per-user sockets.
- [ ] Show an endpoint's containers on its endpoint page.

## AI clients (MCP)

- [ ] OAuth 2.1 sign-in for the MCP endpoint, so ChatGPT's connectors and Claude's custom connectors (which do not send a bearer token) can connect without a bridge.
- [ ] A tool that asks endpoints a live question (Interact) within a time and row budget; today only cached sensor answers are offered.
- [ ] A request to retry the failed devices of a deployment, filed for approval like the other request tools.
- [ ] Per-token rate limits on tool calls.
- [ ] Stream the assistant's answer as it is written, rather than waiting for the whole turn.
- [ ] Keep assistant conversations across page loads, per user, with a retention limit.
- [ ] Per-user limits on assistant requests, and a cost or token count per answer.
- [ ] Amazon Bedrock and Vertex AI connections, which sign requests rather than sending a key.

## Custom sensors

- [ ] Managed, version-pinned third-party Python dependencies.
- [ ] Python/WQL/Batch autocomplete where useful and reliable.
- [ ] Explicit transformations for multiple nested JSON arrays; avoid implicit Cartesian products that change the meaning of records and targeting.
- [ ] Evaluate remote WMI and event subscriptions separately from finite local inventory queries; they need distinct authorization and lifecycle semantics.

## Reveal

- [ ] An on-endpoint index. Every scan walks the files again; an Index hashes and indexes once and lets a rescan, a hash search and File Evidence all read the same table. It is also what would let a quick search answer in seconds on a large home directory.
- [ ] Pattern groups: two patterns within N characters of each other (a name next to an SSN) as one rule condition, which is how a false positive rate is actually driven down.
- [ ] Labels on matched files and an action from a finding (quarantine, delete, notify the owner), so a result is something to do rather than something to read.
- [ ] PDF text. Everything else people keep numbers in is read.

## Deploy

- [ ] Check the Self Service category column on a real Windows and macOS desktop (`endpoint-ui-testing`): it was tested in the console's preview frame only, at desktop and narrow widths, in both themes.
- [ ] Let the Appearance preview show the server's own Self Service categories. It shows sample categories today, because the sample packages would have to be filed under real ones to mean anything.
- [ ] Decide whether catalog package names should be unique. Nothing prevents two packages with the same name, which is how four entries called ShareX happened; the causes of that are fixed, but the shape is still possible. Uniqueness is not obviously right — the same application from two vendors is a real case — so this is a decision, not a fix.

## Device replacement

- [ ] Match products to packages across operating systems by vendor and name when replacing a Windows laptop with a Mac (or back): today a package matches only through a variant for the old endpoint's OS.
- [ ] Copy what is not software as well: the old endpoint's computer-group memberships, attributes (owner, location) and Self Service grants.
- [ ] Retire the old endpoint, or set its lifecycle state, when the job finishes.
- [ ] Prune finished jobs after a retention period; they are kept indefinitely today.

## Sensor examples

- [ ] Expand standalone examples to typed schemas and closer built-in parity where useful. Current examples use text records and explicitly document omitted fields, agent state, and integrations; they are not exact collector copies.

## macOS

- [ ] Show which Macs are missing Full Disk Access in one place. The agent measures it now and each endpoint's Privileges tab reports it, which closed the worst of the gap — a lapsed grant used to be invisible until a sensor covering a protected path quietly returned nothing. What is still missing is the fleet-wide view: answering "which Macs need this" means opening each Mac in turn.
- [ ] Sign the agent and the Self Service app with a Developer ID certificate and notarize them. The binary is ad-hoc signed today.

## Endpoint notifications

- [ ] A macOS equivalent. The gap there is smaller — the agent already reaches the console user's session through `osascript`, so notifications are native — but there is no menu-bar item. A real `NSStatusItem` needs Cocoa, so cgo, so a darwin-only build path separate from the `CGO_ENABLED=0` matrix the other five targets are cross-compiled from.
- [ ] Let the toast carry a deadline countdown that updates in place. Windows supports it, and a restart prompt that silently goes stale is the kind of thing people learn to ignore.

## Scale

- [ ] Ingest sensor snapshots in parallel by agent (ordered per agent). The consumer is one goroutine, latency-bound at ~330 snapshots/s: a fleet starting together drains its first snapshots in 71 s at 2,000 endpoints and 148 s at 5,000. Steady state (15-minute interval) needs ~80/s at 5,000 and ~160/s at 10,000. Watch patch-observation upserts for lock ordering when it is parallel.
- [ ] Stream live-query deltas to the console instead of whole snapshots: an installed-apps query over 5,000 endpoints sends ~1.4 GB of cumulative snapshots to each viewer.
- [ ] Cache or precompute the Patches summary and dashboard sources; both decode every endpoint's cached snapshot per view (5,000 endpoints, four viewers: Patches p50 719 ms, Security posture dashboard 597 ms).
- [ ] Upsert software_presence by difference: every installed-apps snapshot rewrites ~800 rows (20 ms of Postgres each), which a fleet starting together pays 5,000 times at once.
- [ ] Batch heartbeat writes (one UPDATE per second for every agent heard from) before ~10,000 endpoints: one statement and commit per heartbeat is 1,000/s there, on a single consumer.

## Fleet integrations

- [ ] Entra ID / Intune: verified against a simulated Microsoft Graph only; check against a real tenant (paging sizes, throttling 429 + Retry-After, Intune devices without an Entra device ID).
- [ ] Warranty lookup from vendor APIs (Dell TechDirect, Lenovo, HP) instead of a hand-entered warranty end; needs per-vendor API keys.
- [ ] Interactive Slack/Teams buttons that decide in the chat itself (needs a registered app and a signed callback endpoint); today's buttons open /approve.
- [ ] Verify the Rubrik Security Cloud provider against a live account (it follows Rubrik's documentation and passes against a stand-in server).
- [ ] ServiceNow CMDB sync (configuration items from endpoints); today ServiceNow receives incidents only.
- [ ] Request/response schemas in the OpenAPI document; today bodies are described as JSON objects.

## Hardening

- [ ] Wazuh's CIS content has rules that can never pass as written (Debian "shadowed passwords" inverted, `ucredit … compare < 0` with a `(\d+)` capture, `ENCRYPT_METHOD` SHA512 *and* YESCRYPT). Consider reporting upstream, or a per-policy rule override in Mustra so a bad rule can be corrected rather than excepted.
- [ ] Exceptions by check title cover every benchmark sharing the title; add optional per-benchmark scoping if two benchmarks ever share a title with different meaning.
- [ ] Run the Linux Firewall Enforce policy on real firewalld, ufw and nftables hosts (Debian, Ubuntu, a RHEL family release): its checks and fixes are tested against stubs that answer like the real tools, not against the tools themselves.
- [ ] Linux Firewall holds firewalld's default zone only; interfaces bound to another zone, and rules the policy does not list, are left alone. Consider an option to cover every active zone and to remove unlisted allowances.
- [ ] Ansible Enforce policies send one playbook: roles, collections, templates and files it uses must already be on the endpoint, and Ansible Vault is not supported. Shipping a role bundle (as package payloads are) and a vault password from the credential store would remove both limits.
- [ ] Ansible Enforce results list the tasks that would change as text in the result's output. Storing them as structured rows would let the console filter endpoints by task and count drift per task across the fleet.
- [ ] Windows account policy (password length, lockout) and advanced audit subcategories can only come from Group Policy; a typed Enforce kind for `auditpol`/`secedit` would let Mustra hold them on workgroup machines.

## Remote desktop

- [ ] Shadowing from the browser. Guacamole's RDP cannot shadow; a built-in viewer would need the agent to capture and relay the screen, with the consent prompt in the Self Service window and the tray. The command-line route shipped first because Windows already has the consent prompt.
- [ ] Run the Windows and macOS halves of temporary accounts on real machines: they are cross-compiled and reviewed, but only the Linux half (`MUSTRA_LIVE_JIT=1`) and the Guacamole SSH path have run for real.
- [ ] Play a recording in the console instead of only downloading the `.guac` file (guacamole-common-js's SessionRecording player).
- [ ] Track Guacamole's HTTP tunnel as well as its WebSocket one. Only the WebSocket refreshes `last_seen_at`, so a browser that falls back to the HTTP tunnel is ended three minutes in.
- [ ] Domain controllers: a temporary member of a scoped AD group, since a DC has no local accounts to create.
- [ ] Attended screen sharing in the agent (the signed-in user approves, input lock, clipboard, file transfer), so a session does not have to be an RDP login that signs the user out.
- [ ] macOS through Fleet: push the PPPC profile (Accessibility) and send `EnableRemoteDesktop` from Mustra's Fleet integration, so Screen Sharing needs no hands on the Mac. Apple doesn't let MDM grant Screen Recording to a third-party app silently.

## API reference

- [ ] Type the rows still built as maps inside typed responses: fields such as the jobs of `GET /api/deploy/jobs`, the plans of `POST /api/deploy/preview` and the rows of a dashboard panel are `[]map[string]any` or `map[string]any`.
- [ ] Check the spec against the official OAS 3.2 JSON Schema in CI. validated it by hand (Python `jsonschema` with `schema-base/2026-08-30` and the 3.2 dialect); `TestOpenAPIIsStructurallyValid` covers only the rules it spells out. CI would need the schemas vendored and a draft 2020-12 validator.
- [ ] Tag descriptions. The 81 tags come from path segments and have no `description` (Redocly's `tag-description` warning); 3.2's tag `summary` and `parent` could also nest the admin tags.
- [ ] A patch run can still be recorded with no actions when dispatch refuses every endpoint after the run is written. Two one-off applies to the same endpoint at once both pass the handler's open-job check; the second records its run, then `deployPatchesToAgents` refuses it as already patching and the handler answers 502, not 409. A bulk **Deploy now** whose every target is already patching does the same. The handler also ignores an error from `OpenPatchJobs`. Record the run only once an action row exists, or remove it when none was written.
- [ ] A Connect history row that starts at exactly the cursor's instant, but commits after the run that set the cursor, is never exported: the cursor skips rows at or before it. Closing that needs a tie-breaker (start plus row ID) in the cursor, not just the time.
- [ ] Integrity labels' "during maintenance" rule asks the window gate about kind `software`, which no window applies to, so the check always passes and the rule reduces to `hasWindow`: an endpoint any enabled window covers, open or not, in effect or not, matches at every hour, and an expected label on it hides all its changes. `hasWindow` also ignores a window's platform. Both should share `windowCheck`'s covering rule and ask whether a covering window is open.
- [ ] Playbook saves read a database error on a step's enforce policy, message or group as "no such …" and answer 400 (`validatePlaybookSteps`, `handleSavePlaybook`), as the Enforce handlers did before.
- [ ] Revoke an approved Self Service request. Since a decision is final, so the only way to withdraw an entitlement granted by mistake is to delete the package; deciding again used to overwrite it. Revocation needs its own action, audited, and a state other than `denied` so the history shows it was granted first.

## Windows

- [ ] Sign the Windows agent. Unsigned, its updater can be blocked by Defender attack surface reduction rules.

## Deployment rings

- [ ] Edit a patch schedule's rollout plan in place. Schedules can only be created and deleted today, so changing the plan means recreating the schedule.
- [ ] Restart choice and override-windows on scheduled patch rollouts. Scheduled firings, like scheduled runs without rings, patch without a restart.
- [ ] Software deployments still run their plans in one goroutine, drawing percentages at random and sleeping between rings, so a restart loses the rollout. Move them onto the persistent ring rollouts (resume, abort, halts) used by patching and Enforce.

## Windows drivers, feature updates and Hotpatch

- [ ] Run the driver, feature-update and hotpatch paths on real Windows machines: a driver offered by Windows Update, a feature update (24H2 → 25H2) through to its restart and verification, and a hotpatch-enrolled Windows 11 Enterprise device. The first slice was built and tested only with recorded Windows Update output.
- [ ] Set the Windows-side policies too (`TargetReleaseVersion`, `ExcludeWUDriversInQualityUpdate`) so Windows' own automatic updates follow the same hold and driver choices; today only mustra's runs do.
- [ ] Choose drivers per device or hardware ID, and roll a driver back (`pnputil`), rather than only by name pattern.
- [ ] Report a feature update's compatibility holds (safeguard holds) and setup's own result codes when it fails.
- [ ] Read hotpatch enrolment from a documented source if Microsoft publishes one; the agent reads the PolicyManager registry location of `Update/AllowRebootlessUpdates`, which is not documented as an interface.
- [ ] Show drivers and feature updates in the deploy preview (how many each run would install), and on the endpoint page.

## Patch health checks

- [ ] Check services after patching on Windows (automatic services that were running) and macOS (launchd daemons). Only Linux with systemd compares services today; other endpoints get the server's restart watch alone.
- [ ] Let an operator release a run held back after a failed health check, rather than starting a new deployment for the endpoints it cancelled.
- [ ] Hold scheduled patch runs too, not only the waiting actions of the run that failed: the schedule firing again still rolls the same kernel to more endpoints.
- [ ] Optional application probes (an HTTP URL or TCP port per endpoint or group) for apps whose systemd unit stays active while the app is broken.

## Remediation gallery

- [ ] Run each fix on real Windows, Linux (Debian/Ubuntu, RHEL-family, with systemd-networkd and NetworkManager) and macOS endpoints and record the result. The scripts were parse-checked (PowerShell) and linted (shellcheck) while writing them; the tests check their conventions, not their behaviour on those platforms.
- [ ] Offer a fix from where the problem shows: a "Run a remediation" action on the endpoint page (pre-selecting the endpoint in the deploy window through `?agents=`) and from Guide items such as low disk space.
- [ ] Say on the gallery when the imported package or playbook was edited after import, so **Update** can warn that it publishes over a locally changed version rather than beside it.
- [ ] A gallery update that adds a required input leaves an imported playbook without a value for it; its next run is refused at the step. Ask for the new input when updating.

## Triage queue

- [ ] Self Service help requests: a "Get help" form in the Self Service window that files a
  triage item (source `self_service`, already accepted by the queue) for the endpoint it runs
  on. Needs an agent change, a durable message type and broker ACL; deferred from #89.
- [ ] ServiceNow state changes into mustra: a ticket closed or cancelled in ServiceNow does
  not move its item yet; the inbound API only refreshes the text and adds notes.
- [ ] Apply to similar endpoints for patches and Enforce runs directly; today they go
  through a playbook step.

## Anomalies

- [ ] Crash and service-restart counts as metrics. Agents report no crash events (Windows Error Reporting, systemd-coredump, macOS diagnostic reports) and only the services' state now, not how often they restarted; both need agent collection and a sensor catalog entry.
- [ ] Time-of-day baselines, so a workstation idle at night and busy by day has a band per part of the day rather than one wide band for both.
- [ ] A Guide observation, a playbook trigger and an integration event when a fleet pattern opens.
- [ ] Open anomalies on the endpoint page, and in the triage queue once it exists (link by `/anomalies?id=`).
- [ ] Per-metric tuning (band width, sustain time) in settings; the defaults are fixed in internal/anomaly today.
- [ ] Use Telemetry's node_exporter series as a source where it is turned on (load, network, pressure stall), without making anomaly detection depend on it.

## SaaS Experience

- [ ] Publish the extension to the Chrome Web Store and Edge Add-ons, so it can be force-installed on Windows and macOS machines that are not domain-joined or MDM-managed.
- [ ] An Enforce policy kind that sets `ExtensionInstallForcelist` (registry on Windows, managed policy file on Linux) instead of copying the policy from Setup.
- [ ] Limit monitoring to computer groups (with the GroupDeleted behaviour: a deleted group must not turn it on fleet-wide); today it is on for every endpoint or none.
- [ ] Time single-page-app route changes (soft navigations), not only full page loads.
- [ ] Hourly rollups for long periods: a 30-day overview of a large fleet sums every five-minute row.
- [ ] Editable score thresholds and weights per app.
- [ ] Alerts and Guide items when an app's score falls, fleet-wide or for a site.
- [ ] Firefox and Safari.
- [ ] Run the extension and the native host on real Windows and macOS desktops with Chrome and Edge installed by policy; tested so far in headless Chromium on Linux with a stand-in agent listener.
