package proto

import "time"

// SaaS experience monitoring: how the web applications people use all day
// actually perform on their machines.
//
// A browser extension (extension/saas-monitor) measures page loads and
// request errors for the apps in an allow-list the server pushes, and
// aggregates them per app per five-minute window in the browser. It hands
// those aggregates to the local agent over Chrome native messaging; the
// agent publishes them on its durable outbox as the saas_experience sensor.
// Nothing about a page beyond which allow-listed app it belongs to ever
// leaves the browser: no URL path, query, title, content or form data.

// SensorSaaS is the snapshot kind the aggregates travel on. Like Reveal it
// is not collected on a timer by the sensor loop: the agent publishes what
// the extension handed it, every five minutes, while there is any.
const SensorSaaS SensorKind = "saas_experience"

// SaaSWindowSeconds is the aggregation window. Fixed, so that windows from
// different endpoints and browsers line up and add.
const SaaSWindowSeconds = 300

// SaaSBucketsMs are the upper bounds, in milliseconds, of the timing
// histograms; a histogram has one more count than there are bounds, for
// everything slower than the last. The bounds include the scoring
// thresholds (internal/saasmon), so a percentile at a threshold is exact.
// Changing them breaks every stored histogram: add a new field instead.
var SaaSBucketsMs = []int{100, 200, 300, 500, 800, 1000, 1500, 1800, 2500, 3000, 4000, 6000, 8000, 12000, 20000}

// SaaSHistogramLen is the length of every timing histogram.
var SaaSHistogramLen = len(SaaSBucketsMs) + 1

// SaaSApp is one entry of the app library: a name and the domains that
// belong to it. A domain matches itself and its subdomains.
type SaaSApp struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
}

// SaaSConfig is what the server tells an agent, and the agent tells the
// extension: whether to measure, and what.
type SaaSConfig struct {
	Enabled bool `json:"enabled"`
	// Revision changes whenever anything below does, so the agent can tell
	// a new library from the one it already applied.
	Revision string `json:"revision,omitempty"`
	// ExtensionID is the Chrome/Edge extension ID the native messaging host
	// admits (its allowed_origins). Empty: the host is not registered,
	// because a host that admits any extension is not one to install.
	ExtensionID   string    `json:"extension_id,omitempty"`
	WindowSeconds int       `json:"window_seconds,omitempty"`
	Apps          []SaaSApp `json:"apps"`
}

// SaaSAggregate is one app's measurements in one browser over one window.
type SaaSAggregate struct {
	App string `json:"app"` // SaaSApp.ID
	// Domain is the library domain that matched, copied from the library:
	// never a hostname the page supplied.
	Domain        string    `json:"domain,omitempty"`
	Browser       string    `json:"browser,omitempty"` // chrome | edge | chromium
	WindowStart   time.Time `json:"window_start"`
	WindowSeconds int       `json:"window_seconds"`

	// Navigations are main-frame page loads the extension timed.
	Navigations int `json:"navigations"`
	// Histograms of time to first byte, DOMContentLoaded and load, over
	// SaaSBucketsMs. Each has SaaSHistogramLen counts.
	TTFBHist []int `json:"ttfb_hist"`
	DCLHist  []int `json:"dcl_hist"`
	LoadHist []int `json:"load_hist"`

	// Main-frame responses by status class, and loads that failed before a
	// response (DNS, TLS, connection reset).
	Nav4xx    int `json:"nav_4xx"`
	Nav5xx    int `json:"nav_5xx"`
	NavFailed int `json:"nav_failed"`
	// XHR and fetch requests made by the app's pages, the same way.
	Requests  int `json:"requests"`
	Req4xx    int `json:"req_4xx"`
	Req5xx    int `json:"req_5xx"`
	ReqFailed int `json:"req_failed"`
	// JSErrors counts uncaught errors and unhandled promise rejections on
	// the app's pages. Counted only: no message or stack is kept.
	JSErrors int `json:"js_errors"`
}

// SaaSReport is the saas_experience snapshot's data: a batch of aggregates.
type SaaSReport struct {
	// BatchID makes a redelivered batch idempotent: the server adds each
	// batch's counts once.
	BatchID          string          `json:"batch_id"`
	ExtensionVersion string          `json:"extension_version,omitempty"`
	Aggregates       []SaaSAggregate `json:"aggregates"`
}
