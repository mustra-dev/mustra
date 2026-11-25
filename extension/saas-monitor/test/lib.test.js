// Run with: node --test extension/saas-monitor/test/
"use strict";
const test = require("node:test");
const assert = require("node:assert");
const L = require("../lib.js");

const apps = [
  { id: "slack", domains: ["slack.com"] },
  { id: "google-mail", domains: ["mail.google.com"] },
  { id: "google-docs", domains: ["docs.google.com"] },
];
const T0 = Date.UTC(2026, 10, 25, 12, 1, 30); // 12:01:30, window 12:00

test("matches a domain and its subdomains, never a look-alike", () => {
  assert.deepStrictEqual(L.matchApp("slack.com", apps), { app: "slack", domain: "slack.com" });
  assert.deepStrictEqual(L.matchApp("app.SLACK.com.", apps), { app: "slack", domain: "slack.com" });
  assert.strictEqual(L.matchApp("notslack.com", apps), null);
  assert.strictEqual(L.matchApp("slack.com.evil.example", apps), null);
  assert.strictEqual(L.matchApp("google.com", apps), null);
  assert.strictEqual(L.matchApp("www.google.com", apps), null);
  assert.deepStrictEqual(L.matchApp("mail.google.com", apps), { app: "google-mail", domain: "mail.google.com" });
  // The longest domain wins when two apps nest.
  const nested = [{ id: "m365", domains: ["office.com"] }, { id: "outlook", domains: ["outlook.office.com"] }];
  assert.strictEqual(L.matchApp("outlook.office.com", nested).app, "outlook");
  assert.strictEqual(L.matchApp("www.office.com", nested).app, "m365");
});

test("only https pages are measured", () => {
  assert.strictEqual(L.hostOf("https://app.slack.com/client/T1/C2?q=salary#x"), "app.slack.com");
  assert.strictEqual(L.hostOf("http://app.slack.com/"), "");
  assert.strictEqual(L.hostOf("chrome://settings"), "");
  assert.strictEqual(L.hostOf("not a url"), "");
});

test("an aggregate carries no URL, path, query or page data", () => {
  const p = {};
  const url = "https://app.slack.com/client/TEAMX9/CHANX7?q=salary+review#thread";
  const m = L.matchApp(L.hostOf(url), apps);
  L.recordNavigation(p, m, "chrome", T0, { ttfb: 120, dcl: 900, load: 2100 });
  L.recordResponse(p, m, "chrome", T0, "xmlhttprequest", 503);
  const text = JSON.stringify(L.buildReport(p, Object.keys(p), "1.0.0"));
  for (const leak of ["client", "TEAMX9", "CHANX7", "salary", "thread", "app.slack.com", "?", "#", "/"]) {
    assert.ok(!text.includes(leak), `report leaks ${leak}: ${text}`);
  }
  const a = Object.values(p)[0];
  assert.deepStrictEqual(Object.keys(a).sort(), ["app", "browser", "dcl_hist", "domain", "js_errors", "load_hist", "nav_4xx", "nav_5xx",
    "nav_failed", "navigations", "req_4xx", "req_5xx", "req_failed", "requests", "ttfb_hist", "window_seconds", "window_start"]);
  assert.strictEqual(a.domain, "slack.com");
});

test("aggregates per app, browser and five-minute window", () => {
  const p = {};
  const slack = L.matchApp("app.slack.com", apps);
  L.recordNavigation(p, slack, "chrome", T0, { ttfb: 150, dcl: 700, load: 1900 });
  L.recordNavigation(p, slack, "chrome", T0 + 60000, { ttfb: 2500, dcl: 4000, load: -1 });
  L.recordNavigation(p, slack, "edge", T0, { ttfb: 90, dcl: 100, load: 300 });
  L.recordNavigation(p, slack, "chrome", T0 + 5 * 60000, { ttfb: 90, dcl: 100, load: 300 });
  assert.strictEqual(Object.keys(p).length, 3);
  const a = p["slack|chrome|" + L.windowStart(T0)];
  assert.strictEqual(a.window_start, "2026-11-25T12:00:00Z");
  assert.strictEqual(a.window_seconds, 300);
  assert.strictEqual(a.navigations, 2);
  assert.strictEqual(a.ttfb_hist[L.bucketIndex(150)], 1);
  assert.strictEqual(a.ttfb_hist[L.bucketIndex(2500)], 1);
  // A load that never fired is not timed as fast.
  assert.strictEqual(a.load_hist.reduce((x, y) => x + y, 0), 1);
  assert.strictEqual(a.ttfb_hist.length, L.HIST_LEN);
});

test("histogram buckets are upper bounds, with an overflow bucket", () => {
  assert.strictEqual(L.bucketIndex(0), 0);
  assert.strictEqual(L.bucketIndex(100), 0);
  assert.strictEqual(L.bucketIndex(101), 1);
  assert.strictEqual(L.bucketIndex(800), 4);
  assert.strictEqual(L.bucketIndex(20000), 14);
  assert.strictEqual(L.bucketIndex(20001), 15);
});

test("responses are counted by status class", () => {
  const p = {};
  const m = L.matchApp("slack.com", apps);
  for (const [kind, status] of [["main_frame", 200], ["main_frame", 404], ["main_frame", 502], ["main_frame", 0],
    ["xmlhttprequest", 200], ["xmlhttprequest", 401], ["xmlhttprequest", 500], ["xmlhttprequest", 0]]) {
    L.recordResponse(p, m, "chrome", T0, kind, status);
  }
  L.recordJSErrors(p, m, "chrome", T0, 3);
  L.recordJSErrors(p, m, "chrome", T0, "lots");
  const a = Object.values(p)[0];
  assert.deepStrictEqual([a.nav_4xx, a.nav_5xx, a.nav_failed, a.requests, a.req_4xx, a.req_5xx, a.req_failed, a.js_errors], [1, 1, 1, 4, 1, 1, 1, 3]);
  assert.strictEqual(a.navigations, 0, "a response is not a timed navigation");
});

test("only closed windows are sent, and old ones are pruned", () => {
  const p = {};
  const m = L.matchApp("slack.com", apps);
  L.recordNavigation(p, m, "chrome", T0, { ttfb: 1, dcl: 1, load: 1 });
  assert.deepStrictEqual(L.closed(p, T0), []);
  assert.strictEqual(L.closed(p, Date.UTC(2026, 10, 25, 12, 5, 0)).length, 1);
  L.recordNavigation(p, m, "chrome", T0 - 25 * 3600 * 1000, { ttfb: 1, dcl: 1, load: 1 });
  assert.strictEqual(L.prune(p, T0), 1);
  assert.strictEqual(Object.keys(p).length, 1);
});

test("the pending set is bounded", () => {
  const p = {};
  const m = L.matchApp("slack.com", apps);
  for (let i = 0; i < L.MAX_PENDING + 20; i++) L.recordNavigation(p, m, "chrome", T0 - i * 300000, { ttfb: 1, dcl: 1, load: 1 });
  assert.strictEqual(Object.keys(p).length, L.MAX_PENDING);
});

test("a config is only trusted in its own shape", () => {
  assert.strictEqual(L.sanitizeConfig(null), null);
  const off = L.sanitizeConfig({ enabled: false, apps });
  assert.deepStrictEqual(off.apps, [], "when off, no app is measured");
  const c = L.sanitizeConfig({ enabled: true, revision: "r", apps: [
    { id: "ok", domains: ["ok.example", "*.bad.example", "https://x.example/", "UPPER.example"] },
    { id: "Bad Id", domains: ["x.example"] },
    { id: "nodomains", domains: [] },
    "junk",
  ] });
  assert.deepStrictEqual(c.apps, [{ id: "ok", domains: ["ok.example"] }]);
});

test("content scripts are registered for the apps' domains only", () => {
  assert.deepStrictEqual(L.contentScriptMatches([{ id: "slack", domains: ["slack.com"] }]), ["https://*.slack.com/*", "https://slack.com/*"]);
  assert.deepStrictEqual(L.contentScriptMatches([]), []);
});

test("the browser is named from client hints", () => {
  assert.strictEqual(L.browserName([{ brand: "Chromium" }, { brand: "Microsoft Edge" }]), "edge");
  assert.strictEqual(L.browserName([{ brand: "Google Chrome" }]), "chrome");
  assert.strictEqual(L.browserName(undefined), "chromium");
});

test("the report's aggregates skip empty ones and carry a valid version", () => {
  const p = {};
  const m = L.matchApp("slack.com", apps);
  L.recordJSErrors(p, m, "chrome", T0, 0);
  assert.strictEqual(L.buildReport(p, Object.keys(p), "1.0.0").report.aggregates.length, 0);
  assert.strictEqual(L.buildReport(p, Object.keys(p), "x<y").report.extension_version, undefined);
});
