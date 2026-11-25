// Package saasmon holds what the native messaging host, the agent and the
// server all need to agree on about SaaS experience monitoring: what a
// well-formed aggregate is, how a score is computed from aggregates, and
// what a packaged extension (CRX3) looks like.
//
// The same validation runs three times on purpose. The host checks what
// the browser sent before it bothers the agent; the agent checks again,
// because its loopback listener can be reached by any local program and not
// only by the host; the server checks a last time against the app library,
// because the agent is not the authority on which apps exist.
package saasmon

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Caps on one aggregate. A person cannot load fifty thousand pages of one
// app in five minutes; a number past these is a bug or a forgery, and the
// whole aggregate is refused rather than clamped into something plausible.
const (
	MaxNavigations = 50_000
	MaxRequests    = 1_000_000
	MaxJSErrors    = 1_000_000
	// MaxAggregates bounds one report: apps × browsers × windows. The agent
	// flushes every five minutes, so a full report is already unusual.
	MaxAggregates = 1000
	// MaxReportBytes bounds the encoded report anywhere it travels.
	MaxReportBytes = 512 << 10
	// MaxApps and MaxDomainsPerApp bound the library a server may push.
	MaxApps          = 500
	MaxDomainsPerApp = 50
	// FutureSkew is how far ahead of the receiver's clock a window may
	// start: endpoint clocks drift.
	FutureSkew = 10 * time.Minute
)

var (
	appIDPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	batchIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
	versionPattern = regexp.MustCompile(`^[0-9]{1,5}(\.[0-9]{1,5}){0,3}$`)
	labelPattern   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	extIDPattern   = regexp.MustCompile(`^[a-p]{32}$`)
)

// Browsers are the browser names an aggregate may carry.
var Browsers = map[string]bool{"": true, "chrome": true, "edge": true, "chromium": true}

// ValidAppID reports whether id can name an app in the library.
func ValidAppID(id string) bool { return appIDPattern.MatchString(id) }

// ValidExtensionID reports whether id has the shape of a Chrome extension
// ID: 32 letters a to p.
func ValidExtensionID(id string) bool { return extIDPattern.MatchString(id) }

// ValidVersion reports whether v is a Chrome extension version string.
func ValidVersion(v string) bool { return versionPattern.MatchString(v) }

// NormalizeDomain turns what an administrator typed into a library
// domain: a lower-case hostname without a scheme, port, path or wildcard.
// "https://Slack.com/" is accepted as slack.com; "*.slack.com" is not,
// since a domain already matches its subdomains and a wildcard suggests
// otherwise.
func NormalizeDomain(raw string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(raw))
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimSuffix(d, "/")
	d = strings.TrimSuffix(d, ".")
	if d == "" {
		return "", errors.New("empty domain")
	}
	if len(d) > 253 {
		return "", fmt.Errorf("domain %q is too long", raw)
	}
	if strings.ContainsAny(d, "*/:?#@ ") {
		return "", fmt.Errorf("%q is not a plain domain: give a hostname such as example.com, which also matches its subdomains", raw)
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("%q needs at least two labels, such as example.com", raw)
	}
	for _, l := range labels {
		if !labelPattern.MatchString(l) {
			return "", fmt.Errorf("%q is not a valid domain (use the xn-- form for international names)", raw)
		}
	}
	return d, nil
}

// ValidateConfig checks a library before the agent hands it to a browser.
func ValidateConfig(c proto.SaaSConfig) error {
	if c.ExtensionID != "" && !ValidExtensionID(c.ExtensionID) {
		return fmt.Errorf("invalid extension id %q", c.ExtensionID)
	}
	if len(c.Apps) > MaxApps {
		return fmt.Errorf("%d apps; at most %d", len(c.Apps), MaxApps)
	}
	for _, a := range c.Apps {
		if !ValidAppID(a.ID) {
			return fmt.Errorf("invalid app id %q", a.ID)
		}
		if len(a.Domains) > MaxDomainsPerApp {
			return fmt.Errorf("app %q has %d domains; at most %d", a.ID, len(a.Domains), MaxDomainsPerApp)
		}
		for _, d := range a.Domains {
			if n, err := NormalizeDomain(d); err != nil || n != d {
				return fmt.Errorf("app %q: invalid domain %q", a.ID, d)
			}
		}
	}
	return nil
}

// Library is what an aggregate is checked against: app ID → its domains.
// A nil Library accepts any well-formed app ID (the host and the agent may
// hold no library yet; the server always passes one).
type Library map[string]map[string]bool

// NewLibrary indexes apps for ValidateAggregate.
func NewLibrary(apps []proto.SaaSApp) Library {
	lib := Library{}
	for _, a := range apps {
		ds := map[string]bool{}
		for _, d := range a.Domains {
			ds[d] = true
		}
		lib[a.ID] = ds
	}
	return lib
}

// ValidateAggregate reports why a is not one the receiver should accept.
// now is the receiver's clock; maxAge is how old a window may be (a laptop
// that was off the network for a week delivers a week-old window, and the
// server's retention decides whether that is still worth keeping).
func ValidateAggregate(a proto.SaaSAggregate, lib Library, now time.Time, maxAge time.Duration) error {
	if !ValidAppID(a.App) {
		return fmt.Errorf("invalid app id %q", a.App)
	}
	if lib != nil {
		domains, ok := lib[a.App]
		if !ok {
			return fmt.Errorf("app %q is not in the library", a.App)
		}
		if a.Domain != "" && !domains[a.Domain] {
			return fmt.Errorf("domain %q is not one of app %q's", a.Domain, a.App)
		}
	} else if a.Domain != "" {
		if n, err := NormalizeDomain(a.Domain); err != nil || n != a.Domain {
			return fmt.Errorf("invalid domain %q", a.Domain)
		}
	}
	if !Browsers[a.Browser] {
		return fmt.Errorf("unknown browser %q", a.Browser)
	}
	if a.WindowSeconds != proto.SaaSWindowSeconds {
		return fmt.Errorf("window_seconds is %d; the window is %d", a.WindowSeconds, proto.SaaSWindowSeconds)
	}
	if a.WindowStart.IsZero() || a.WindowStart.Unix()%proto.SaaSWindowSeconds != 0 || a.WindowStart.Nanosecond() != 0 {
		return errors.New("window_start is not aligned to a window")
	}
	if a.WindowStart.After(now.Add(FutureSkew)) {
		return errors.New("window_start is in the future")
	}
	if maxAge > 0 && a.WindowStart.Before(now.Add(-maxAge)) {
		return errors.New("window_start is older than the retention period")
	}
	if a.Navigations < 0 || a.Navigations > MaxNavigations {
		return fmt.Errorf("navigations %d out of range", a.Navigations)
	}
	for _, h := range []struct {
		name string
		v    []int
	}{{"ttfb_hist", a.TTFBHist}, {"dcl_hist", a.DCLHist}, {"load_hist", a.LoadHist}} {
		if len(h.v) != proto.SaaSHistogramLen {
			return fmt.Errorf("%s has %d buckets; expected %d", h.name, len(h.v), proto.SaaSHistogramLen)
		}
		sum := 0
		for _, c := range h.v {
			if c < 0 || c > MaxNavigations {
				return fmt.Errorf("%s has a count out of range", h.name)
			}
			sum += c
		}
		// Every timed navigation lands in each histogram at most once; a
		// load that never fired its load event is in ttfb but not in load.
		if sum > a.Navigations {
			return fmt.Errorf("%s counts %d loads, more than the %d navigations", h.name, sum, a.Navigations)
		}
	}
	for _, c := range []struct {
		name string
		v    int
		max  int
	}{
		{"nav_4xx", a.Nav4xx, MaxNavigations}, {"nav_5xx", a.Nav5xx, MaxNavigations}, {"nav_failed", a.NavFailed, MaxNavigations},
		{"requests", a.Requests, MaxRequests}, {"req_4xx", a.Req4xx, MaxRequests}, {"req_5xx", a.Req5xx, MaxRequests},
		{"req_failed", a.ReqFailed, MaxRequests}, {"js_errors", a.JSErrors, MaxJSErrors},
	} {
		if c.v < 0 || c.v > c.max {
			return fmt.Errorf("%s %d out of range", c.name, c.v)
		}
	}
	if a.Req4xx+a.Req5xx+a.ReqFailed > a.Requests {
		return errors.New("more failed requests than requests")
	}
	if a.Navigations == 0 && a.Requests == 0 && a.Nav4xx+a.Nav5xx+a.NavFailed+a.JSErrors == 0 {
		return errors.New("empty aggregate")
	}
	return nil
}

// ValidateReport checks a whole report. It stops at the first bad
// aggregate: a sender that produces one malformed aggregate is not one
// whose other numbers deserve trust.
func ValidateReport(r proto.SaaSReport, lib Library, now time.Time, maxAge time.Duration) error {
	if err := ValidateReportHeader(r); err != nil {
		return err
	}
	if len(r.Aggregates) == 0 {
		return errors.New("no aggregates")
	}
	if len(r.Aggregates) > MaxAggregates {
		return fmt.Errorf("%d aggregates; at most %d", len(r.Aggregates), MaxAggregates)
	}
	for i, a := range r.Aggregates {
		if err := ValidateAggregate(a, lib, now, maxAge); err != nil {
			return fmt.Errorf("aggregate %d: %w", i, err)
		}
	}
	return nil
}

// ValidateReportHeader checks a report's own fields, not its aggregates.
func ValidateReportHeader(r proto.SaaSReport) error {
	if r.BatchID != "" && !batchIDPattern.MatchString(r.BatchID) {
		return errors.New("invalid batch_id")
	}
	if r.ExtensionVersion != "" && !ValidVersion(r.ExtensionVersion) {
		return errors.New("invalid extension_version")
	}
	return nil
}

// AggregateKey identifies the aggregates that add up: the same app in the
// same browser over the same window.
type AggregateKey struct {
	App         string
	Browser     string
	WindowStart int64
}

// KeyOf returns a's merge key.
func KeyOf(a proto.SaaSAggregate) AggregateKey {
	return AggregateKey{App: a.App, Browser: a.Browser, WindowStart: a.WindowStart.Unix()}
}

// Merge adds b's counts into a (which must have the same key and valid
// histograms). Counts saturate at the caps instead of overflowing past
// what ValidateAggregate accepts.
func Merge(a *proto.SaaSAggregate, b proto.SaaSAggregate) {
	add := func(x, y, max int) int {
		if x+y > max {
			return max
		}
		return x + y
	}
	addHist := func(x, y []int) []int {
		out := make([]int, proto.SaaSHistogramLen)
		for i := range out {
			if i < len(x) {
				out[i] += x[i]
			}
			if i < len(y) {
				out[i] += y[i]
			}
		}
		return out
	}
	if a.Domain == "" {
		a.Domain = b.Domain
	}
	nav := a.Navigations + b.Navigations
	if nav > MaxNavigations {
		// Saturated: stop adding timings too, so the histograms never count
		// more loads than the navigations field says there were.
		return
	}
	a.Navigations = nav
	a.TTFBHist, a.DCLHist, a.LoadHist = addHist(a.TTFBHist, b.TTFBHist), addHist(a.DCLHist, b.DCLHist), addHist(a.LoadHist, b.LoadHist)
	a.Nav4xx = add(a.Nav4xx, b.Nav4xx, MaxNavigations)
	a.Nav5xx = add(a.Nav5xx, b.Nav5xx, MaxNavigations)
	a.NavFailed = add(a.NavFailed, b.NavFailed, MaxNavigations)
	if a.Requests+b.Requests <= MaxRequests {
		a.Requests += b.Requests
		a.Req4xx += b.Req4xx
		a.Req5xx += b.Req5xx
		a.ReqFailed += b.ReqFailed
	}
	a.JSErrors = add(a.JSErrors, b.JSErrors, MaxJSErrors)
}
