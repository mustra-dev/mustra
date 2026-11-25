// The SaaS monitor's logic, without browser APIs, so it can be tested in
// Node: which app a host belongs to, the five-minute aggregates, and the
// report the native host receives.
//
// Privacy is decided here. An aggregate holds the app's ID, the library
// domain that matched (copied from the library, never from the page), the
// browser's name, counts and timing histograms. No URL, path, query, title
// or content is ever put into one, and the native host refuses any field
// that is not in the protocol.
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.SaaSLib = api;
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  // Must equal proto.SaaSBucketsMs and proto.SaaSWindowSeconds.
  const BUCKETS_MS = [100, 200, 300, 500, 800, 1000, 1500, 1800, 2500, 3000, 4000, 6000, 8000, 12000, 20000];
  const HIST_LEN = BUCKETS_MS.length + 1;
  const WINDOW_SECONDS = 300;
  // What the extension keeps while the agent cannot be reached.
  const MAX_AGE_MS = 24 * 3600 * 1000;
  const MAX_PENDING = 500;
  // Caps that keep an aggregate inside what the agent accepts.
  const MAX_NAVIGATIONS = 50000;
  const MAX_REQUESTS = 1000000;

  const APP_ID = /^[a-z0-9][a-z0-9_-]{0,63}$/;
  const LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

  function validDomain(d) {
    if (typeof d !== "string" || d.length > 253) return false;
    const labels = d.split(".");
    return labels.length >= 2 && labels.every(l => LABEL.test(l));
  }

  // sanitizeConfig keeps only a well-formed config, or returns null. What
  // the agent hands over is checked again here: an extension that measured
  // whatever it was told would be the weakest link.
  function sanitizeConfig(c) {
    if (!c || typeof c !== "object") return null;
    const out = { enabled: c.enabled === true, revision: typeof c.revision === "string" ? c.revision.slice(0, 64) : "", apps: [] };
    if (!Array.isArray(c.apps)) return out;
    for (const a of c.apps.slice(0, 500)) {
      if (!a || !APP_ID.test(a.id) || !Array.isArray(a.domains)) continue;
      const domains = a.domains.filter(validDomain).slice(0, 50);
      if (domains.length) out.apps.push({ id: a.id, domains });
    }
    if (!out.enabled) out.apps = [];
    return out;
  }

  // matchApp returns the app a hostname belongs to, by its longest matching
  // library domain, or null. A domain matches itself and its subdomains, so
  // "slack.com" matches "app.slack.com" but never "notslack.com".
  function matchApp(host, apps) {
    if (typeof host !== "string" || !host) return null;
    host = host.toLowerCase().replace(/\.$/, "");
    let best = null;
    for (const a of apps || []) {
      for (const d of a.domains) {
        if ((host === d || host.endsWith("." + d)) && (!best || d.length > best.domain.length)) best = { app: a.id, domain: d };
      }
    }
    return best;
  }

  // hostOf reads the hostname of an https URL or origin; anything else
  // (http, file, chrome://, an extension page) is not measured.
  function hostOf(url) {
    if (typeof url !== "string") return "";
    try {
      const u = new URL(url);
      return u.protocol === "https:" ? u.hostname : "";
    } catch (e) {
      return "";
    }
  }

  function bucketIndex(ms) {
    for (let i = 0; i < BUCKETS_MS.length; i++) if (ms <= BUCKETS_MS[i]) return i;
    return BUCKETS_MS.length;
  }

  function windowStart(nowMs) {
    return Math.floor(nowMs / 1000 / WINDOW_SECONDS) * WINDOW_SECONDS;
  }

  function rfc3339(sec) {
    return new Date(sec * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
  }

  function emptyHist() {
    return new Array(HIST_LEN).fill(0);
  }

  function keyOf(app, browser, ws) {
    return app + "|" + browser + "|" + ws;
  }

  // aggregateFor returns (creating it) the pending aggregate for a match in
  // the window containing nowMs. pending is a plain object: key → aggregate
  // in exactly the shape the native host accepts.
  function aggregateFor(pending, match, browser, nowMs) {
    const ws = windowStart(nowMs);
    const k = keyOf(match.app, browser, ws);
    let a = pending[k];
    if (!a) {
      if (Object.keys(pending).length >= MAX_PENDING) return null;
      a = pending[k] = {
        app: match.app, domain: match.domain, browser, window_start: rfc3339(ws), window_seconds: WINDOW_SECONDS,
        navigations: 0, ttfb_hist: emptyHist(), dcl_hist: emptyHist(), load_hist: emptyHist(),
        nav_4xx: 0, nav_5xx: 0, nav_failed: 0, requests: 0, req_4xx: 0, req_5xx: 0, req_failed: 0, js_errors: 0,
      };
    }
    return a;
  }

  const finite = v => typeof v === "number" && isFinite(v) && v >= 0;

  // recordNavigation adds one timed page load. A timing the page never
  // reached (a load that was abandoned) is left out of its histogram.
  function recordNavigation(pending, match, browser, nowMs, t) {
    const a = aggregateFor(pending, match, browser, nowMs);
    if (!a || a.navigations >= MAX_NAVIGATIONS) return false;
    a.navigations++;
    if (finite(t.ttfb)) a.ttfb_hist[bucketIndex(t.ttfb)]++;
    if (finite(t.dcl) && t.dcl > 0) a.dcl_hist[bucketIndex(t.dcl)]++;
    if (finite(t.load) && t.load > 0) a.load_hist[bucketIndex(t.load)]++;
    return true;
  }

  // recordResponse counts a main-frame or XHR/fetch outcome: status is the
  // HTTP status, or 0 for a request that failed without one.
  function recordResponse(pending, match, browser, nowMs, kind, status) {
    const a = aggregateFor(pending, match, browser, nowMs);
    if (!a) return false;
    if (kind === "main_frame") {
      if (status === 0) a.nav_failed = Math.min(MAX_NAVIGATIONS, a.nav_failed + 1);
      else if (status >= 500) a.nav_5xx = Math.min(MAX_NAVIGATIONS, a.nav_5xx + 1);
      else if (status >= 400) a.nav_4xx = Math.min(MAX_NAVIGATIONS, a.nav_4xx + 1);
      return true;
    }
    if (a.requests >= MAX_REQUESTS) return false;
    a.requests++;
    if (status === 0) a.req_failed++;
    else if (status >= 500) a.req_5xx++;
    else if (status >= 400) a.req_4xx++;
    return true;
  }

  function recordJSErrors(pending, match, browser, nowMs, n) {
    const a = aggregateFor(pending, match, browser, nowMs);
    if (!a) return false;
    n = Math.max(0, Math.min(1000, Math.floor(Number(n) || 0)));
    a.js_errors = Math.min(MAX_REQUESTS, a.js_errors + n);
    return true;
  }

  // closed returns the keys of windows that have ended, oldest first.
  function closed(pending, nowMs) {
    const now = Math.floor(nowMs / 1000);
    return Object.keys(pending)
      .filter(k => Date.parse(pending[k].window_start) / 1000 + WINDOW_SECONDS <= now)
      .sort((x, y) => Date.parse(pending[x].window_start) - Date.parse(pending[y].window_start));
  }

  // prune drops windows older than MAX_AGE_MS: what the agent could not take
  // within a day is not kept forever in the browser profile.
  function prune(pending, nowMs) {
    let dropped = 0;
    for (const k of Object.keys(pending)) {
      if (nowMs - Date.parse(pending[k].window_start) > MAX_AGE_MS) {
        delete pending[k];
        dropped++;
      }
    }
    return dropped;
  }

  // empty reports whether an aggregate has nothing worth sending.
  function empty(a) {
    return !a.navigations && !a.requests && !a.nav_4xx && !a.nav_5xx && !a.nav_failed && !a.js_errors;
  }

  // buildReport is the native host's "report" message for these keys.
  function buildReport(pending, keys, version) {
    const aggregates = keys.map(k => pending[k]).filter(a => a && !empty(a)).slice(0, 1000);
    const msg = { type: "report", report: { aggregates } };
    if (typeof version === "string" && /^[0-9]{1,5}(\.[0-9]{1,5}){0,3}$/.test(version)) msg.report.extension_version = version;
    return msg;
  }

  // browserName reads the brand from User-Agent Client Hints.
  function browserName(brands) {
    const names = (brands || []).map(b => b && b.brand);
    if (names.includes("Microsoft Edge")) return "edge";
    if (names.includes("Google Chrome")) return "chrome";
    return "chromium";
  }

  // contentScriptMatches are the match patterns for the apps' pages.
  function contentScriptMatches(apps) {
    const out = new Set();
    for (const a of apps || []) for (const d of a.domains) { out.add("https://" + d + "/*"); out.add("https://*." + d + "/*"); }
    return [...out].sort();
  }

  return {
    BUCKETS_MS, HIST_LEN, WINDOW_SECONDS, MAX_PENDING, MAX_AGE_MS,
    sanitizeConfig, matchApp, hostOf, bucketIndex, windowStart, rfc3339,
    recordNavigation, recordResponse, recordJSErrors, closed, prune, buildReport, browserName, contentScriptMatches,
  };
});
