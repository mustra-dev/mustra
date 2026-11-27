// The SaaS monitor's service worker: it learns the app library from the
// local mustra agent, counts page loads, responses and script errors on
// those apps' pages, and every five minutes hands the closed windows to
// the agent. All of it through Chrome native messaging; the extension
// never talks to the network itself.
"use strict";
importScripts("lib.js");

const HOST = "dev.mustra.saas_monitor";
const L = self.SaaSLib;
const VERSION = chrome.runtime.getManifest().version;
const SCRIPT_ID = "mustra-saas-timing";

let browser = "chromium";
try { browser = L.browserName(navigator.userAgentData && navigator.userAgentData.brands); } catch (e) { /* older browser */ }

// State lives in chrome.storage.local, because a service worker is
// stopped whenever it is idle. Every change goes through one queue so two
// events never overwrite each other's counts.
let queue = Promise.resolve();
function withState(fn) {
  const run = queue.then(async () => {
    const s = await chrome.storage.local.get({ config: { enabled: false, revision: "", apps: [] }, pending: {} });
    const changed = await fn(s);
    if (changed !== false) await chrome.storage.local.set({ config: s.config, pending: s.pending });
  });
  queue = run.catch(() => {});
  return run;
}

function native(msg) {
  return new Promise(resolve => {
    try {
      chrome.runtime.sendNativeMessage(HOST, msg, reply => {
        if (chrome.runtime.lastError) resolve({ type: "error", error: chrome.runtime.lastError.message });
        else resolve(reply || { type: "error", error: "no reply" });
      });
    } catch (e) {
      resolve({ type: "error", error: String(e) });
    }
  });
}

// The content script runs only on the apps' own pages, registered from the
// library, so no other site ever has the extension's code in it.
async function syncContentScripts(apps) {
  const matches = L.contentScriptMatches(apps);
  const ids = [SCRIPT_ID, SCRIPT_ID + "-main"];
  const existing = await chrome.scripting.getRegisteredContentScripts({ ids }).catch(() => []);
  const same = existing.length === 2 && existing.every(s => JSON.stringify([...(s.matches || [])].sort()) === JSON.stringify(matches));
  if (same) return;
  if (existing.length) await chrome.scripting.unregisterContentScripts({ ids: existing.map(s => s.id) }).catch(() => {});
  if (!matches.length) return;
  // The isolated script first, so it is listening when the page-world one
  // starts reporting errors.
  await chrome.scripting.registerContentScripts([
    { id: SCRIPT_ID, matches, js: ["content.js"], runAt: "document_start", allFrames: false, persistAcrossSessions: true },
    { id: SCRIPT_ID + "-main", matches, js: ["content-main.js"], runAt: "document_start", allFrames: false, persistAcrossSessions: true, world: "MAIN" },
  ]);
}

async function refreshConfig() {
  const reply = await native({ type: "hello", extension_version: VERSION, browser });
  if (reply.type !== "config") return; // the agent is unreachable: keep what we had
  const cfg = L.sanitizeConfig(reply.config);
  if (!cfg) return;
  await withState(s => {
    s.config = cfg;
    if (!cfg.enabled) s.pending = {};
  });
  await syncContentScripts(cfg.apps);
}

async function flush() {
  let keys = [], msg = null;
  await withState(s => {
    L.prune(s.pending, Date.now());
    keys = L.closed(s.pending, Date.now());
    if (keys.length) msg = L.buildReport(s.pending, keys, VERSION);
  });
  if (!msg) return;
  if (!msg.report.aggregates.length) {
    await withState(s => { for (const k of keys) delete s.pending[k]; });
    return;
  }
  const reply = await native(msg);
  if (reply.type === "ack" || (reply.type === "error" && /^invalid report|off$/.test(reply.error || ""))) {
    // Sent, or refused for good (the agent will not take it however often
    // it is asked): either way it is done.
    await withState(s => { for (const k of keys) delete s.pending[k]; });
  }
}

async function tick() {
  await refreshConfig();
  await flush();
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create("tick", { periodInMinutes: 5, delayInMinutes: 0.1 });
});
chrome.runtime.onStartup.addListener(() => {
  chrome.alarms.create("tick", { periodInMinutes: 5, delayInMinutes: 0.1 });
});
chrome.alarms.onAlarm.addListener(a => { if (a.name === "tick") tick(); });

function record(url, fn) {
  return withState(s => {
    if (!s.config.enabled) return false;
    const m = L.matchApp(L.hostOf(url), s.config.apps);
    if (!m) return false;
    return fn(s.pending, m) ? undefined : false;
  });
}

// Timings and error counts from the content script. The page's address is
// taken from the browser's own record of the sender, not from the message.
chrome.runtime.onMessage.addListener((msg, sender) => {
  if (!sender || sender.id !== chrome.runtime.id || !sender.tab || sender.tab.incognito || sender.frameId !== 0) return;
  if (!msg || typeof msg !== "object") return;
  const url = sender.url || sender.tab.url;
  if (msg.type === "nav") {
    record(url, (p, m) => L.recordNavigation(p, m, browser, Date.now(), { ttfb: msg.ttfb, dcl: msg.dcl, load: msg.load }));
  } else if (msg.type === "js") {
    record(url, (p, m) => L.recordJSErrors(p, m, browser, Date.now(), msg.count));
  }
});

// Responses by status class. Observed only (no blocking, no bodies, no
// headers), and only for tabs: requests from other extensions or the
// browser itself have no tab.
const filter = { urls: ["https://*/*"], types: ["main_frame", "xmlhttprequest"] };
function onResponse(d, status) {
  if (d.tabId < 0 || d.incognito) return;
  // A page's API calls count toward the app the page belongs to.
  const url = d.type === "main_frame" ? d.url : (d.initiator || d.url);
  record(url, (p, m) => L.recordResponse(p, m, browser, Date.now(), d.type, status));
}
chrome.webRequest.onCompleted.addListener(d => onResponse(d, d.statusCode || 0), filter);
chrome.webRequest.onErrorOccurred.addListener(d => {
  // A navigation the user cancelled, or a request the page aborted, is not
  // the app failing.
  if (d.error === "net::ERR_ABORTED") return;
  onResponse(d, 0);
}, filter);
