# mustra SaaS experience monitor

A Manifest V3 extension for Chrome, Edge and Chromium that measures how the
web apps in your mustra app library perform for the people using them, and
hands the numbers to the local mustra agent. Plain JavaScript, no bundler, no
dependencies, no remotely loaded code.

## What it records

For each page load on an allow-listed app (top-level frame only):

- time to first byte, DOMContentLoaded and load, from the page's own
  Navigation Timing entry;
- the main-frame response's status class (4xx, 5xx, or a load that failed
  without a response);
- XHR and fetch requests made by the app's pages, by status class;
- the number of uncaught script errors and unhandled promise rejections.

It aggregates these in the browser per app, per browser and per five-minute
window: timing histograms over fixed buckets and counters. That is all that
leaves the browser, together with the app's ID and the **library domain** that
matched (copied from the library, never from the page). Never a URL path,
query, fragment, page title, page content, form data, header, cookie or
request body. The native host and the agent refuse a report carrying any
field outside this protocol.

Sites not in the library are ignored entirely: the content scripts are
registered only for the library's domains, and request counting only matches
library domains. Incognito windows are never measured: the manifest sets
`"incognito": "not_allowed"`, so the extension cannot run there at all.

## Permissions, and why each is needed

| Permission | Why |
| --- | --- |
| `nativeMessaging` | The only way out of the browser: it talks to the local agent's native messaging host (`dev.mustra.saas_monitor`) and nothing else. The extension makes no network requests of its own. |
| `storage` | Keeps the app library and up to a day of unsent five-minute aggregates across service-worker restarts (`chrome.storage.local`, at most 500 windows). |
| `alarms` | Wakes the service worker every five minutes to refresh the library and send closed windows; a Manifest V3 worker cannot keep a timer of its own. |
| `scripting` | Registers the two content scripts for the library's domains only, and re-registers them when the library changes. Without it the scripts would have to be declared for every site. |
| `webRequest` | Observes (never blocks or modifies) main-frame and XHR/fetch completions to count status classes. No bodies or headers are read. |
| host `https://*/*` | The library is set by your administrator and changes without a new extension version, so the extension cannot list its domains in advance. Everything outside the library is ignored. To narrow it further, use the browsers' `runtime_allowed_hosts`/`runtime_blocked_hosts` extension settings policy. |

## How it reaches mustra

```
page ─ content.js / content-main.js ─▶ background.js (aggregates)
        │ chrome.runtime.sendNativeMessage("dev.mustra.saas_monitor")
        ▼
mustra-agent, started by the browser as the signed-in user (host mode)
        │ http://127.0.0.1:<self-service port>  (token, JSON only)
        ▼
mustra agent service ─▶ durable outbox ─▶ server (saas_experience sensor)
```

The agent registers the host for Chrome, Edge and Chromium while SaaS
monitoring is on (SaaS Experience → Setup) and removes it when it is off. The
host admits only the extension ID the server names. The agent's Self Service
listener (`--self-service-addr`, on by default) must be enabled.

## Packing it

The extension ID is derived from the key the package is signed with, so
generate one key and keep it; every later version must be packed with it.
The key never goes to the server or into git (`*.pem` is ignored).

```sh
# once
go run ./cmd/saas-extension-pack -genkey saas-monitor.pem
# each version
go run ./cmd/saas-extension-pack -key saas-monitor.pem \
    -update-url https://<console>/saas-extension/update.xml \
    -out dist extension/saas-monitor
```

Upload `dist/mustra-saas-monitor-<version>.crx` under SaaS Experience → Setup.
The server checks its signatures, takes its ID and version, and serves it at
`/saas-extension/mustra-saas-monitor.crx` with an update manifest at
`/saas-extension/update.xml`. To release a new version, raise `version` in
`manifest.json` (or pass `-version`), pack with the same key and upload; the
browsers pick it up on their next update check. Chrome Web Store and Edge
Add-ons publishing are not done yet.

## Installing it

Force-install it with the `ExtensionInstallForcelist` policy, set to
`<extension id>;https://<console>/saas-extension/update.xml`. SaaS
Experience → Setup shows ready-made policies with your ID and URL: a `.reg`
file for Chrome and Edge on Windows, a managed policy JSON for Linux, and a
configuration profile for your macOS MDM. Chrome and Edge honour a
force-install from outside their stores only on Windows machines joined to a
domain or managed by an MDM, and on macOS only from a profile an MDM
installed; Linux has no such restriction.

## Testing

```sh
node --test extension/saas-monitor/test/      # aggregation, matching, privacy
go test ./internal/saasmon/                    # runs the above, and checks the
                                               # report against the Go validator
```

## Limits

- Full page loads only: a single-page app's in-app route changes are not
  timed, though their XHR/fetch calls are counted.
- A page could fire the script-error event itself; that only makes its own
  app look worse.
- Requests are attributed to the app of the page that made them (its
  origin), so a library app's calls to a third-party API count toward it.
