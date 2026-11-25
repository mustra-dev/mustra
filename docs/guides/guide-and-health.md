# Guide, notifications and performance
<!-- group: See your fleet; order: 21; pages: /guide, /health, /anomalies -->

Guide is the list of things that need attention across the fleet. Performance shows how healthy each endpoint is and how much risk it carries.

## Guide

The triangle in the top bar opens Guide; the number on it is how many items are open. **Guide** in the rail shows them all.

Items come from every module: a certificate about to expire, an agent behind the current version, a known-exploited vulnerability on an endpoint, a backup overdue, a dashboard alert, an endpoint whose operating system is out of support. Each item says what is wrong and links to where you fix it (**Open →**).

- Items **resolve themselves** when the condition clears. Items refresh every two minutes; **Re-evaluate now** refreshes them immediately.
- **dismiss** hides an item for everyone (it needs **Triage alerts** or **Manage settings**). **bring back** reverses it.
- Filter by kind (guidance or observation), source, and open or all items from the last 30 days.

## Your notifications

The bell is for you personally: approvals waiting for you, access you were granted, reports you asked for. Selecting a notification marks it read.

## Performance

- **Endpoint Health** rates each endpoint from its recent CPU, memory and disk use, and how well its agent is keeping up. Use it to find machines that need attention before their users complain.
- **Risk Score** combines each endpoint's vulnerabilities, compliance failures and exposure, weighted by its **criticality**. Set criticality here (for example *critical* for a domain controller); setting it needs **Manage patches**.
- **Anomalies** lists endpoints that moved well outside their own normal: CPU, memory or system disk use, running processes, failed services, or restarts. Each endpoint is compared only with its own last two weeks, so a busy build server is not flagged for being busy. A new endpoint learns for two days first.
  - The ranked list puts the same problem on many endpoints first, and says when most of them had the same deployment or update shortly before. Open a row for its endpoints, and an endpoint for a chart of its value against its normal band.
  - From a group, **Run a package or action…** and **Apply patches** open Deploy or Patch with those endpoints already chosen; **Investigate** opens the endpoint page where the metric shows (processes, disks, services).
  - **Acknowledge** marks anomalies as looked at, with a note; they stay listed but no longer count toward the rank. **Suppress on a group…** hides one metric's anomalies on a computer group for a while. Both need **Triage alerts** and are in the audit log.
