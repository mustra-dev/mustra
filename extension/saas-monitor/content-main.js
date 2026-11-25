// Runs in the page's own world, on the apps' pages only, because uncaught
// errors and unhandled rejections are not delivered to an extension's
// isolated world. It reads nothing: each one becomes a bare event that
// content.js counts. A page could fire the event itself, which would only
// make its own app look worse.
(function () {
  "use strict";
  const fire = () => {
    try { document.dispatchEvent(new Event("mustra-saas-script-error")); } catch (e) { /* never break the page */ }
  };
  // ErrorEvent only: a failed image or stylesheet fires a plain Event.
  window.addEventListener("error", e => { if (e instanceof ErrorEvent) fire(); }, true);
  window.addEventListener("unhandledrejection", fire, true);
})();
