// Runs only on the pages of apps in the library (background.js registers
// it for their domains). It reads the page load's own Navigation Timing
// entry and counts uncaught script errors; it reads nothing of the page's
// content, and sends only numbers. It runs at document_start so it is
// listening before the page's first script can throw.
(function () {
  "use strict";
  if (chrome.extension.inIncognitoContext || window.top !== window) return;

  let errors = 0, timer = 0;
  const flushErrors = () => {
    timer = 0;
    if (!errors) return;
    const count = errors;
    errors = 0;
    try { chrome.runtime.sendMessage({ type: "js", count }); } catch (e) { /* extension reloaded */ }
  };
  const countError = () => {
    errors++;
    if (!timer) timer = setTimeout(flushErrors, 5000);
  };
  // content-main.js, in the page's world, turns each uncaught error into
  // this event; this world never sees the errors themselves.
  document.addEventListener("mustra-saas-script-error", countError);
  window.addEventListener("pagehide", flushErrors);

  const report = () => {
    const nav = performance.getEntriesByType("navigation")[0];
    if (!nav) return;
    const ms = v => (typeof v === "number" && v > 0 ? Math.round(v - (nav.activationStart || 0)) : -1);
    try {
      chrome.runtime.sendMessage({ type: "nav", ttfb: ms(nav.responseStart), dcl: ms(nav.domContentLoadedEventStart), load: ms(nav.loadEventStart) });
    } catch (e) { /* extension reloaded */ }
  };
  // The load event's own timing is only final once the event has run.
  if (document.readyState === "complete") setTimeout(report, 0);
  else window.addEventListener("load", () => setTimeout(report, 0), { once: true });
})();
