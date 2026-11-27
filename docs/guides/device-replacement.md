# Replace a device
<!-- group: Deploy and patch; order: 33; pages: /device-replacement -->

Give someone a new laptop with the software their old one had: mustra compares the two, installs what is missing from your Software Catalog on the new one, and reports what it installed and what it could not.

## Before you start

- You need **Deploy software and run actions** (`deploy.manage`), and both endpoints within your management rights.
- Both endpoints need the agent, and the old one must have reported its installed software (any endpoint does within minutes of the agent starting). The old one can be offline or retired.
- The software you want moved needs a package in **Deploy → Software Catalog** whose detection recognises it, with a published version. See [Deploy software](deploy-software.md).

## Compare and install

1. Open **Deploy → Device Replacement**.
2. Under **Old endpoint** and **New endpoint**, pick each from the list or type its hostname.
3. Optionally enter the **Ticket** the replacement answers, such as `RITM0012345`.
4. Choose **Compare**. mustra lists:
   - **Will install:** catalog packages that detect software on the old endpoint that the new one lacks.
   - **No matching package:** software no package covers, or whose package cannot be used here (outside its computer groups, not in your content sets, no install for that system). Install these by hand.
   - **Already on the new endpoint.**
   Libraries, runtimes, drivers and system updates are left out: they come with the system or with the applications that need them.
5. Untick anything you do not want, then choose **Install N packages on** the new endpoint.

Endpoints running different systems (Windows to macOS) are refused unless you tick **Allow a different operating system**.

## Follow it

The **Replacements** table lists every job. Open one to see each package as **Installed**, **Failed**, **Timed out** or **No response** (the endpoint never took the job), with the detail from the endpoint. Each install is also an ordinary deployment under **Deploy → Deployments**. An install outside the endpoint's maintenance window waits for it. If an approval policy covers deployments to the new endpoint, the whole replacement waits for one approval under **Access → Approvals**.

A job finishes when every package has a result; one still installing after three hours counts as timed out, and one the endpoint never picked up as no response.

## Report to ServiceNow

When a ServiceNow integration is enabled under **Administration → Integrations** and the job names a ServiceNow ticket, the final report is added to the ticket's **work notes**: what was installed, what failed and why, and what had no package. Numbers starting INC, RITM, REQ, SCTASK or CHG are looked up in their table; a 32-character sys_id is taken to be an incident's. The integration's account needs to read and update those records. Other ticket references are kept on the job but not posted anywhere.

## Start one from ServiceNow

A ServiceNow flow (or any script) can start a replacement with an API token holding `deploy.manage` (**Administration → API tokens**). Name each endpoint by exactly one of its agent ID, hostname or hardware serial number:

```
curl -X POST https://mustra.example.com/api/device-replacements \
  -H "Authorization: Bearer $MUSTRA_TOKEN" -H "Content-Type: application/json" \
  -d '{"old_serial": "PF2RX8KD", "new_hostname": "FIN-LT-0142", "ticket": "RITM0012345"}'
```

A hostname or serial that matches more than one endpoint is refused with the matches listed; send the agent ID instead. `POST /api/device-replacements/preview` returns the comparison without installing anything. A token cannot wait for an approval: where a policy covers the new endpoint, the request is refused unless the token is approval-exempt.
