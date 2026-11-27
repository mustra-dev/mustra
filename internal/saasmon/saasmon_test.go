package saasmon

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

var now = time.Date(2026, 11, 25, 12, 7, 0, 0, time.UTC)

func hist(pairs ...int) []int {
	h := make([]int, proto.SaaSHistogramLen)
	for i := 0; i+1 < len(pairs); i += 2 {
		h[pairs[i]] = pairs[i+1]
	}
	return h
}

func goodAggregate() proto.SaaSAggregate {
	return proto.SaaSAggregate{
		App: "slack", Domain: "slack.com", Browser: "chrome",
		WindowStart: time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC), WindowSeconds: 300,
		Navigations: 10, TTFBHist: hist(2, 10), DCLHist: hist(6, 9), LoadHist: hist(8, 8),
		Requests: 40, Req4xx: 2, Req5xx: 1, JSErrors: 3,
	}
}

var lib = NewLibrary([]proto.SaaSApp{{ID: "slack", Name: "Slack", Domains: []string{"slack.com", "slack-edge.com"}}})

func TestValidateAggregate(t *testing.T) {
	if err := ValidateAggregate(goodAggregate(), lib, now, 48*time.Hour); err != nil {
		t.Fatalf("good aggregate refused: %v", err)
	}
	cases := map[string]func(a *proto.SaaSAggregate){
		"unknown app":          func(a *proto.SaaSAggregate) { a.App = "zoom" },
		"bad app id":           func(a *proto.SaaSAggregate) { a.App = "Slack!" },
		"domain not the app's": func(a *proto.SaaSAggregate) { a.Domain = "evil.example" },
		"unknown browser":      func(a *proto.SaaSAggregate) { a.Browser = "firefox" },
		"wrong window length":  func(a *proto.SaaSAggregate) { a.WindowSeconds = 60 },
		"unaligned window":     func(a *proto.SaaSAggregate) { a.WindowStart = a.WindowStart.Add(time.Second) },
		"future window":        func(a *proto.SaaSAggregate) { a.WindowStart = now.Add(time.Hour).Truncate(5 * time.Minute) },
		"too old":              func(a *proto.SaaSAggregate) { a.WindowStart = now.Add(-72 * time.Hour).Truncate(5 * time.Minute) },
		"short histogram":      func(a *proto.SaaSAggregate) { a.TTFBHist = a.TTFBHist[:3] },
		"negative count":       func(a *proto.SaaSAggregate) { a.Nav5xx = -1 },
		"histogram > navs":     func(a *proto.SaaSAggregate) { a.LoadHist = hist(0, 11) },
		"negative bucket":      func(a *proto.SaaSAggregate) { a.DCLHist = hist(0, -1) },
		"too many navigations": func(a *proto.SaaSAggregate) { a.Navigations = MaxNavigations + 1 },
		"failures > requests":  func(a *proto.SaaSAggregate) { a.Req5xx = 50 },
		"empty": func(a *proto.SaaSAggregate) {
			*a = proto.SaaSAggregate{App: "slack", WindowStart: a.WindowStart, WindowSeconds: 300, TTFBHist: hist(), DCLHist: hist(), LoadHist: hist()}
		},
		"zero window start":      func(a *proto.SaaSAggregate) { a.WindowStart = time.Time{} },
		"sub-second window time": func(a *proto.SaaSAggregate) { a.WindowStart = a.WindowStart.Add(time.Millisecond) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := goodAggregate()
			mutate(&a)
			if err := ValidateAggregate(a, lib, now, 48*time.Hour); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	// Without a library, any well-formed app and domain passes.
	a := goodAggregate()
	a.App, a.Domain = "zoom", "zoom.us"
	if err := ValidateAggregate(a, nil, now, 0); err != nil {
		t.Fatalf("no library: %v", err)
	}
	a.Domain = "https://zoom.us/path"
	if err := ValidateAggregate(a, nil, now, 0); err == nil {
		t.Fatal("a URL is not a domain")
	}
}

func TestValidateReport(t *testing.T) {
	r := proto.SaaSReport{BatchID: "abcdefgh12", ExtensionVersion: "1.0.2", Aggregates: []proto.SaaSAggregate{goodAggregate()}}
	if err := ValidateReport(r, lib, now, 0); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(r *proto.SaaSReport){
		"no aggregates": func(r *proto.SaaSReport) { r.Aggregates = nil },
		"bad batch":     func(r *proto.SaaSReport) { r.BatchID = "x" },
		"bad version":   func(r *proto.SaaSReport) { r.ExtensionVersion = "1.0<script>" },
		"too many":      func(r *proto.SaaSReport) { r.Aggregates = make([]proto.SaaSAggregate, MaxAggregates+1) },
		"one bad of many": func(r *proto.SaaSReport) {
			b := goodAggregate()
			b.App = "nope"
			r.Aggregates = append(r.Aggregates, b)
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := r
			mutate(&c)
			if ValidateReport(c, lib, now, 0) == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestNormalizeDomain(t *testing.T) {
	ok := map[string]string{"Slack.com": "slack.com", " https://app.slack.com/ ": "app.slack.com", "xn--bcher-kva.example.": "xn--bcher-kva.example"}
	for in, want := range ok {
		if got, err := NormalizeDomain(in); err != nil || got != want {
			t.Errorf("%q: got %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "com", "*.slack.com", "slack.com/path", "slack.com:443", "user@slack.com", "-a.com", "a_b.com", strings.Repeat("a.", 130) + "com"} {
		if _, err := NormalizeDomain(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestValidateConfig(t *testing.T) {
	good := proto.SaaSConfig{Enabled: true, ExtensionID: strings.Repeat("a", 32), Apps: []proto.SaaSApp{{ID: "slack", Domains: []string{"slack.com"}}}}
	if err := ValidateConfig(good); err != nil {
		t.Fatal(err)
	}
	bad := good
	bad.ExtensionID = "short"
	if ValidateConfig(bad) == nil {
		t.Fatal("bad extension id accepted")
	}
	bad = good
	bad.Apps = []proto.SaaSApp{{ID: "slack", Domains: []string{"Slack.com"}}}
	if ValidateConfig(bad) == nil {
		t.Fatal("unnormalized domain accepted")
	}
}

func TestMerge(t *testing.T) {
	a, b := goodAggregate(), goodAggregate()
	Merge(&a, b)
	if a.Navigations != 20 || a.TTFBHist[2] != 20 || a.Requests != 80 || a.Req5xx != 2 || a.JSErrors != 6 {
		t.Fatalf("merged %+v", a)
	}
	if err := ValidateAggregate(a, lib, now, 0); err != nil {
		t.Fatalf("a merge of valid aggregates must stay valid: %v", err)
	}
	// Saturation keeps the result valid rather than overflowing the caps.
	c := goodAggregate()
	c.Navigations = MaxNavigations
	c.TTFBHist = hist(0, MaxNavigations)
	Merge(&c, goodAggregate())
	if err := ValidateAggregate(c, lib, now, 0); err != nil {
		t.Fatalf("saturated merge invalid: %v", err)
	}
}

func TestPercentile(t *testing.T) {
	if _, ok := Percentile(make([]int64, proto.SaaSHistogramLen), 0.75); ok {
		t.Fatal("empty histogram has no percentile")
	}
	h := make([]int64, proto.SaaSHistogramLen)
	h[0] = 100 // all within 0-100 ms
	if v, _ := Percentile(h, 0.5); v != 50 {
		t.Fatalf("p50 of uniform 0-100 = %v", v)
	}
	// Three quarters at or under 800 ms (bucket index 4 is 500-800): the
	// estimate for p75 must not exceed 800, so the threshold comparison is
	// exact.
	h = make([]int64, proto.SaaSHistogramLen)
	h[4], h[10] = 75, 25
	if v, _ := Percentile(h, 0.75); v > TTFBGoodMs {
		t.Fatalf("p75 %v crosses the good threshold", v)
	}
	h = make([]int64, proto.SaaSHistogramLen)
	h[proto.SaaSHistogramLen-1] = 4
	if v, _ := Percentile(h, 0.75); v != 20000 {
		t.Fatalf("overflow bucket reports its lower bound, got %v", v)
	}
}

func totals(navs int, ttfbBucket, loadBucket int, errRequests, requests, js int) Totals {
	var t Totals
	a := proto.SaaSAggregate{Navigations: navs, TTFBHist: hist(ttfbBucket, navs), DCLHist: hist(), LoadHist: hist(loadBucket, navs),
		Requests: requests, Req5xx: errRequests, JSErrors: js}
	t.Add(a)
	return t
}

func TestComputeScore(t *testing.T) {
	// Fast, error-free: 100.
	r := Compute(totals(100, 1, 3, 0, 500, 0))
	if r.Score == nil || *r.Score != 100 || r.Band != "good" {
		t.Fatalf("perfect app scored %+v", r)
	}
	// Everything at or past "poor": 0.
	r = Compute(totals(100, proto.SaaSHistogramLen-1, proto.SaaSHistogramLen-1, 100, 100, 1000))
	if r.Score == nil || *r.Score != 0 || r.Band != "poor" {
		t.Fatalf("worst app scored %v", *r.Score)
	}
	// Fast but erroring: only the 0.30 error component is lost.
	r = Compute(totals(100, 1, 3, 50, 100, 0))
	if *r.Score != 70 || r.Band != "fair" {
		t.Fatalf("erroring app scored %d (%s)", *r.Score, r.Band)
	}
	// Too few loads: no score, never a pass.
	r = Compute(totals(MinNavigations-1, 1, 3, 0, 0, 0))
	if r.Score != nil || r.Band != "no_data" {
		t.Fatalf("thin data scored %+v", r)
	}
	// Error rate's denominator includes requests and main-frame failures.
	var tt Totals
	tt.Add(proto.SaaSAggregate{Navigations: 10, NavFailed: 10, Requests: 80, Req5xx: 10, TTFBHist: hist(0, 10), DCLHist: hist(), LoadHist: hist(0, 10)})
	if got := Compute(tt).ErrorRate; math.Abs(got-0.2) > 1e-9 {
		t.Fatalf("error rate %v, want 0.2", got)
	}
}

func testArchive(t *testing.T, manifest string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("manifest.json")
	w.Write([]byte(manifest))
	w2, _ := zw.Create("background.js")
	w2.Write([]byte("// nothing"))
	zw.Close()
	return buf.Bytes()
}

func TestCRXRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	crx, id, err := BuildCRX(testArchive(t, `{"manifest_version":3,"name":"mustra SaaS","version":"1.2.3"}`), key)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if id != ExtensionID(pub) || !ValidExtensionID(id) {
		t.Fatalf("id %q", id)
	}
	info, err := ParseCRX(crx)
	if err != nil {
		t.Fatal(err)
	}
	if info.ID != id || info.Version != "1.2.3" || info.Name != "mustra SaaS" {
		t.Fatalf("parsed %+v", info)
	}

	// One byte changed in the archive: the signature no longer verifies.
	tampered := append([]byte(nil), crx...)
	tampered[len(tampered)-30] ^= 0xFF
	if _, err := ParseCRX(tampered); err == nil {
		t.Fatal("tampered package accepted")
	}
	// Not a CRX at all.
	if _, err := ParseCRX([]byte("PK\x03\x04 not a crx")); err == nil {
		t.Fatal("zip accepted as crx")
	}
	// A header length past the end.
	bad := append([]byte(nil), crx[:12]...)
	bad[8], bad[9], bad[10], bad[11] = 0xFF, 0xFF, 0, 0
	if _, err := ParseCRX(bad); err == nil {
		t.Fatal("bad header length accepted")
	}
	// Manifest V2 is refused.
	crx2, _, _ := BuildCRX(testArchive(t, `{"manifest_version":2,"name":"old","version":"1.0"}`), key)
	if _, err := ParseCRX(crx2); err == nil || !strings.Contains(err.Error(), "Manifest V3") {
		t.Fatalf("MV2 accepted: %v", err)
	}
}

// Chrome's own documented example: the ID is the first 128 bits of the
// SHA-256 of the key, written with a-p for 0-f.
func TestIDAlphabet(t *testing.T) {
	if got := idFromCRXID([]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0, 0, 0, 0, 0, 0, 0, 0xff}); got != "abcdefghijklmnopaaaaaaaaaaaaaapp" {
		t.Fatalf("got %q", got)
	}
}
