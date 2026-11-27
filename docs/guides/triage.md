# Triage queue
<!-- group: Manage endpoints; order: 15; pages: /triage -->

Work support tickets and alerts with the endpoint they are about in front of you: see its state, fix it, then ask for the same fix on the endpoints like it.

## Before you start

- Reading the queue needs **See the fleet** (`fleet.read`). Filing, editing and resolving items, adding notes and sending alerts over from the Guide needs **Triage alerts** (`alerts.triage`).
- Running a fix from an item also needs what running it anywhere needs: **Deploy software and run actions** (`deploy.manage`), the endpoint inside your management rights and the module's action group, and any approval policy's say. Asking for a fix on similar endpoints needs a console session, not an API token, because the approval runs as the person who asked.

## Where items come from

- **ServiceNow**: a business rule or flow in ServiceNow calls mustra's API when a ticket is opened or changes (below). mustra never polls ServiceNow.
- **The Guide**: **Send to triage** on any open Guide item. An item that links to an endpoint's page is attached to that endpoint. Sending it again opens the same item.
- **By hand**: **Triage → New item**, with the endpoint's hostname or serial number if you know it.
- **Any script**: `POST /api/triage/items` with an API token holding `alerts.triage` (see the API reference).

The same ticket sent twice (the same source and reference) updates its item rather than opening another; a note sent with the update lands on the item's timeline.

## How an item finds its endpoint

An item names its endpoint by agent ID, hostname or serial number (from the hardware sensor), in any combination. mustra attaches the endpoint only when the identifiers agree on exactly one:

- A hostname that two endpoints share, or a hostname and serial number that point at different machines, leaves the item **unattached**, with the candidates listed. Choose **This one** beside the right one, or attach another by hostname.
- A hostname matches in full, ignoring case; when nothing does, `web01` also finds `web01.corp.example`, and the other way round.
- Firmware placeholders such as "To Be Filled By O.E.M." are never used as serial numbers.
- An identifier that matches nothing is reported on the item and ignored, so a stale hostname in the CMDB does not hide a good serial number.

The **Unattached** tile on the queue counts open items waiting for somebody to choose.

## Work an item

The item page shows what was reported, and **The endpoint now**: online state, Performance score, pending patches, vulnerabilities, failing compliance checks, Enforce settings not holding, open Guide alerts, file changes in the last week, recent deployments and actions, recently installed software and the endpoint's other open items. Each links to the page it comes from. It is read from what mustra already holds; nothing new is collected.

**Work it** moves the item between **New**, **In progress**, **Waiting on someone** and **Resolved**, assigns it, and adds a note. A resolved item can be reopened to **In progress**. Every change is on the item's timeline and in the audit log.

## Fix this endpoint, then the others

1. Under **Fix this endpoint**, choose a playbook, an action package or a software package, then **Run on this endpoint**. It runs on the item's endpoint and nowhere else, as you, through the same checks as Deploy and Playbooks. A playbook runs only if its own targeting already includes the endpoint: naming the endpoint narrows a playbook's targets, never widens them. A patch or an Enforce policy runs as a playbook step. If an approval policy covers it, it waits for approval like any other run.
2. Its outcome comes from the run itself. Once it shows **succeeded**, **Apply to similar endpoints** appears.
3. Choose the fix and a computer group or a saved query, then **Show the endpoints**. The list leaves out the item's own endpoint and any endpoint outside your management rights or the module's action group.
4. **Ask for approval on these**. Nothing runs yet: the request waits under **Access → Approvals** (and the `/approve` page) for somebody else with **Decide approvals** (`approvals.decide`). You cannot approve your own request, and it expires after eight hours.

The request names the endpoints you saw. If the group is deleted or changes while it waits, the approved run still reaches exactly those endpoints and no others. A group already deleted cannot be chosen.

## Close the loop with ServiceNow

When you resolve an item that came from ServiceNow, mustra writes a work note on the ticket: who resolved it, your note, the endpoint, what was run on it, and a link to the item. The item says whether it arrived; if it did not, **Send it again**. mustra does not change the ticket's state, so a rule in ServiceNow can close it when the note arrives.

### Set it up

1. In ServiceNow, create an integration account with REST access that may read and write the tables your tickets live in (incident, or a request table).
2. In mustra, **Administration → Integrations**, add a **ServiceNow (incidents)** integration with the instance URL (`https://example.service-now.com`) and the account as `username:password`. The credentials are stored encrypted when a credential encryption key is set. If you also want mustra's alerts as incidents, choose the events; otherwise leave it enabled with a minimum severity no alert reaches.
3. In mustra, **Administration → API Tokens**, create a token holding only **Triage alerts** (`alerts.triage`). Keep it in ServiceNow's credential store, not in the script.
4. In ServiceNow, add a business rule (after insert and update) or a flow action on the table that calls mustra:

```javascript
(function executeRule(current, previous) {
  var r = new sn_ws.RESTMessageV2();
  r.setEndpoint('https://mustra.example.com/api/triage/items');
  r.setHttpMethod('POST');
  r.setRequestHeader('Authorization', 'Bearer ' + '<mustra API token>');
  r.setRequestHeader('Content-Type', 'application/json');
  r.setRequestBody(JSON.stringify({
    source: 'servicenow',
    external_ref: current.getUniqueValue(),        // the sys_id: resolutions are written back to it
    external_number: current.getValue('number'),
    external_table: current.getTableName(),
    external_url: gs.getProperty('glide.servlet.uri') + current.getLink(true),
    title: current.getValue('short_description'),
    description: current.getValue('description'),
    hostname: current.cmdb_ci.getDisplayValue(),
    serial: current.cmdb_ci.serial_number.toString()
  }));
  r.executeAsync();
})(current, previous);
```

`external_ref` must be the record's sys_id. When more than one ServiceNow integration is enabled, add `integration_id` with the one resolutions go through.

## Good to know

- The queue accepts items from other parts of mustra by source; Self Service does not file help requests yet.
- Removing an endpoint from inventory does not delete its items; the item says the endpoint is gone and you can attach another.
