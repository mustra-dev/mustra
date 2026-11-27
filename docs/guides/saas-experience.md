# SaaS Experience
<!-- group: See your fleet; order: 28; pages: /saas -->

See how the web apps your people use every day perform in their browsers, scored per app, per endpoint and over time, from a browser extension that measures only the apps you list.

## Before you start

- Reading scores needs **See the fleet**; changing the app library, turning monitoring on and uploading the extension need **Manage settings**.
- Endpoints need an agent with SaaS monitoring, its Self Service listener on (the default), and Chrome, Edge or Chromium.
- Set the console's public URL (Administration → Settings → Agent identity): browsers download the extension from it.
- Force-installing an extension from outside the browser stores works on Windows machines joined to a domain or managed by an MDM, on Macs through an MDM profile, and on any Linux machine.

## Choose what is measured

1. Open **SaaS Experience → App Library**. A few common apps are there to start with.
2. Add, edit or delete apps. Each app is a name and its domains; a domain covers its subdomains, so `slack.com` includes `app.slack.com`. A domain can belong to one app.
3. Nothing outside the library is measured, and incognito windows never are. Only the app and the library domain that matched leave the browser, never a page's address, title or content.

## Pack and upload the extension

1. On a machine with the mustra source and Go, make a signing key once: `go run ./cmd/saas-extension-pack -genkey saas-monitor.pem`. Keep it safe: it decides the extension's ID, and every later version must be packed with it. Never upload it.
2. Pack the extension with the command shown under **SaaS Experience → Setup → Extension package**. It writes your console's update URL into it.
3. Upload the `.crx` file there. mustra checks its signatures and shows its ID and version.

## Install it in the browsers

1. Under **Setup → Force-install policy**, copy or download the policy for each platform: a `.reg` file for Chrome and Edge on Windows, a JSON policy file for Linux, and a configuration profile for your macOS MDM.
2. Deploy it the way you deploy other browser policies, for example with Group Policy, your MDM, or a mustra software package.
3. Where an `ExtensionInstallForcelist` policy already exists, add the entry to it instead of replacing it.

## Turn it on

1. Under **Setup → Monitoring**, tick **Measure the apps in the library** and save.
2. Within five minutes each agent registers the extension's native messaging host and hands the extension the library. Data appears once people use the apps; each browser sends every five minutes.
3. To stop, untick it: agents remove the host registration and discard what was not yet sent.

## Read the scores

1. **Overview** ranks the apps, worst experience first, for the last 24 hours, 7 days or 30 days.
2. A score is 0 to 100: 30% time to first byte, 30% load time (both at the 75th percentile), 30% error rate (5xx responses and failed loads and requests) and 10% script errors per page load. 85 and above is good, 60 to 84 fair, below 60 poor. Fewer than 5 page loads gives no score.
3. Pick an app for its trend and its endpoints, worst first, to tell an app that is slow for everyone from one that is slow on some machines.

## Keep data for longer or shorter

Five-minute data is kept 30 days by default. Change **Keep five-minute data for** under **Setup** (1 to 365 days).
