package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/mdm"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/server/vault"
	"github.com/mustra-dev/mustra/internal/store"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const mdmTestTopic = "com.apple.mgmt.External.3c1f6b2e-8a4d-4e7f-9b0c-5d2a1e6f8c34"

const (
	mdmUDIDA = "0000FE00-AAAA-4000-8000-00000000000A"
	mdmUDIDB = "0000FE00-BBBB-4000-8000-00000000000B"
	mdmUDIDC = "0000FE00-CCCC-4000-8000-00000000000C"
)

// mdmTestServer is a server with Apple MDM set up and on, pushing to a
// local HTTP/2 stand-in for APNs, against the disposable database.
type mdmTestServer struct {
	s      *Server
	h      http.Handler
	st     *store.Store
	pushes atomic.Int32
}

func newMDMTestServer(t *testing.T) *mdmTestServer {
	t.Helper()
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	v, err := vault.New(st, key)
	if err != nil {
		t.Fatal(err)
	}
	ts := &mdmTestServer{st: st}
	s := &Server{logger: slog.Default(), store: st, vault: v, live: &liveConfig{}, syslog: &syslogSink{},
		trust: &agentTrust{publicURLEnv: "https://console.example.com"}}
	s.auth = auth.New(ctx, st, nil, false, slog.Default())

	apns := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && r.Header.Get("apns-push-type") == "mdm" && r.Header.Get("apns-topic") == mdmTestTopic {
			ts.pushes.Add(1)
		}
	}))
	apns.EnableHTTP2 = true
	apns.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	apns.StartTLS()
	t.Cleanup(apns.Close)
	roots := x509.NewCertPool()
	roots.AddCert(apns.Certificate())
	s.mdmRT.apnsBase, s.mdmRT.apnsRoots = apns.URL, roots

	// The configuration is one global row, and the test devices have fixed
	// UDIDs: start and end without either.
	wipe := func() {
		_ = st.SaveMDMConfig(context.Background(), store.MDMConfig{})
		for _, u := range []string{mdmUDIDA, mdmUDIDB, mdmUDIDC} {
			_, _ = st.DeleteMDMDevice(context.Background(), u)
		}
	}
	wipe()
	t.Cleanup(wipe)

	caPEM, caKey, err := mdm.NewCA("Test Org")
	if err != nil {
		t.Fatal(err)
	}
	pushCertPEM, pushKeyPEM := fakePushCert(t)
	cfg := store.MDMConfig{Enabled: true, Organization: "Test Org", CACertPEM: caPEM, PushCertPEM: pushCertPEM, PushTopic: mdmTestTopic}
	if cfg.CAKeySealed, err = s.mdmSeal(mdmAADCAKey, caKey); err != nil {
		t.Fatal(err)
	}
	if cfg.PushKeySealed, err = s.mdmSeal(mdmAADPushKey, pushKeyPEM); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(300 * 24 * time.Hour)
	cfg.PushExpiresAt = &exp
	if err := st.SaveMDMConfig(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	ts.s, ts.h = s, s.routes()
	return ts
}

func fakePushCert(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(42),
		Subject: pkix.Name{CommonName: "APSP:test", ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}, Value: mdmTestTopic}}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(300 * 24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	keyPEM, _ = mdm.KeyPEM(key)
	return mdm.CertPEM(cert), keyPEM
}

// fakeMac is a Mac holding the identity from an enrollment profile.
type fakeMac struct {
	udid string
	cert *x509.Certificate
	key  any
}

// enroll downloads an enrollment profile with token and installs its
// identity, as System Settings would.
func (ts *mdmTestServer) enroll(t *testing.T, token, udid string) *fakeMac {
	t.Helper()
	rec := ts.do(httptest.NewRequest(http.MethodGet, "/mdm/enroll/"+token, nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/x-apple-aspen-config" {
		t.Fatalf("enrollment profile: %d %s", rec.Code, rec.Body)
	}
	var prof struct{ PayloadContent []map[string]any }
	if err := mdm.Decode(rec.Body.Bytes(), &prof); err != nil {
		t.Fatal(err)
	}
	key, cert, _, err := pkcs12.DecodeChain(prof.PayloadContent[0]["PayloadContent"].([]byte), prof.PayloadContent[0]["Password"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if prof.PayloadContent[1]["ServerURL"] != "https://console.example.com/mdm/connect" {
		t.Fatalf("server URL %v", prof.PayloadContent[1]["ServerURL"])
	}
	return &fakeMac{udid: udid, cert: cert, key: key}
}

func (ts *mdmTestServer) do(r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	ts.h.ServeHTTP(rec, r)
	return rec
}

// send signs body as the Mac and PUTs it.
func (m *fakeMac) send(t *testing.T, ts *mdmTestServer, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	sig, err := mdm.SignBody([]byte(body), m.cert, m.key)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPut, path, strings.NewReader(body))
	r.Header.Set("Mdm-Signature", sig)
	return ts.do(r)
}

func tokenUpdatePlist(udid string) string {
	return `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>
<key>MessageType</key><string>TokenUpdate</string><key>Topic</key><string>` + mdmTestTopic + `</string>
<key>UDID</key><string>` + udid + `</string><key>Token</key><data>3q2+7w==</data><key>PushMagic</key><string>MAGIC</string>
</dict></plist>`
}

func reportPlist(udid, status, uuid, extra string) string {
	cmd := ""
	if uuid != "" {
		cmd = `<key>CommandUUID</key><string>` + uuid + `</string>`
	}
	return `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>
<key>UDID</key><string>` + udid + `</string><key>Status</key><string>` + status + `</string>` + cmd + extra + `</dict></plist>`
}

func (ts *mdmTestServer) mintToken(t *testing.T, uses int) string {
	t.Helper()
	tok := newMDMEnrollToken()
	if err := ts.st.CreateMDMEnrollToken(context.Background(), store.MDMEnrollToken{ID: idgen.New("mdmt-"), MaxUses: uses,
		ExpiresAt: time.Now().Add(time.Hour)}, hashToken(tok)); err != nil {
		t.Fatal(err)
	}
	return tok
}

// commandIn reads the command a connect response carries.
func commandIn(t *testing.T, rec *httptest.ResponseRecorder) (uuid, requestType string, cmd map[string]any) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("connect: %d %s", rec.Code, rec.Body)
	}
	if rec.Body.Len() == 0 {
		return "", "", nil
	}
	var env struct {
		CommandUUID string
		Command     map[string]any
	}
	if err := mdm.Decode(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	rt, _ := env.Command["RequestType"].(string)
	return env.CommandUUID, rt, env.Command
}

// The whole device conversation, and every way a device is refused.
func TestMDMCheckinAndCommandQueue(t *testing.T) {
	ts := newMDMTestServer(t)
	ctx := context.Background()
	const udidA, udidB = mdmUDIDA, mdmUDIDB

	// An unknown, then a used-up token gets no profile.
	if rec := ts.do(httptest.NewRequest(http.MethodGet, "/mdm/enroll/mdm_nope", nil)); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown token: %d", rec.Code)
	}
	tok := ts.mintToken(t, 2)
	mac := ts.enroll(t, tok, udidA)
	other := ts.enroll(t, tok, udidB)
	if rec := ts.do(httptest.NewRequest(http.MethodGet, "/mdm/enroll/"+tok, nil)); rec.Code != http.StatusNotFound {
		t.Fatalf("token past max_uses still handed out a profile: %d", rec.Code)
	}

	// Unsigned, badly signed, and signed by a certificate no one issued.
	auth := authenticatePlist(udidA, mdmTestTopic)
	if rec := ts.do(httptest.NewRequest(http.MethodPut, "/mdm/checkin", strings.NewReader(auth))); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned check-in: %d", rec.Code)
	}
	sig, _ := mdm.SignBody([]byte(auth), mac.cert, mac.key)
	r := httptest.NewRequest(http.MethodPut, "/mdm/checkin", strings.NewReader(strings.Replace(auth, "test-mac", "evil-mac", 1)))
	r.Header.Set("Mdm-Signature", sig)
	if rec := ts.do(r); rec.Code != http.StatusUnauthorized {
		t.Fatalf("signature over another body: %d", rec.Code)
	}
	otherCAPEM, otherKey, _ := mdm.NewCA("stranger")
	sca, _ := mdm.ParseCA(otherCAPEM, otherKey)
	sid, _ := sca.Issue("s")
	skey, scert, _, _ := pkcs12.DecodeChain(sid.P12, sid.Password)
	stranger := &fakeMac{udid: udidA, cert: scert, key: skey}
	if rec := stranger.send(t, ts, "/mdm/checkin", auth); rec.Code != http.StatusUnauthorized {
		t.Fatalf("identity from another CA: %d", rec.Code)
	}
	// Another server's topic.
	if rec := mac.send(t, ts, "/mdm/checkin", authenticatePlist(udidA, "com.apple.mgmt.External.other")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("foreign topic: %d", rec.Code)
	}

	// Enrollment: Authenticate, then TokenUpdate.
	if rec := mac.send(t, ts, "/mdm/checkin", auth); rec.Code != http.StatusOK {
		t.Fatalf("authenticate: %d %s", rec.Code, rec.Body)
	}
	// The identity now belongs to A: it cannot speak for B, and B's own
	// identity cannot speak for A.
	if rec := mac.send(t, ts, "/mdm/checkin", authenticatePlist(udidB, mdmTestTopic)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("A's identity authenticated B: %d", rec.Code)
	}
	if rec := other.send(t, ts, "/mdm/checkin", tokenUpdatePlist(udidA)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("B's identity sent A's token update: %d", rec.Code)
	}
	if rec := mac.send(t, ts, "/mdm/checkin", tokenUpdatePlist(udidA)); rec.Code != http.StatusOK {
		t.Fatalf("token update: %d %s", rec.Code, rec.Body)
	}
	// Another (unbound) identity cannot take over the enrolled Mac's UDID.
	if rec := other.send(t, ts, "/mdm/checkin", authenticatePlist(udidA, mdmTestTopic)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a second identity re-enrolled an enrolled UDID: %d", rec.Code)
	}
	dev, _ := ts.st.GetMDMDevice(ctx, udidA)
	if dev == nil || !dev.Enrolled || !dev.HasPushToken || dev.SerialNumber != "C02TESTSERIAL" {
		t.Fatalf("device after enrollment: %+v", dev)
	}
	// Enrolling queued the first inventory and woke the Mac through APNs.
	deadline := time.Now().Add(5 * time.Second)
	for ts.pushes.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if ts.pushes.Load() == 0 {
		t.Fatal("no push reached the APNs stand-in")
	}

	// A command report naming another device is refused.
	if rec := mac.send(t, ts, "/mdm/connect", reportPlist(udidB, "Idle", "", "")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("A's identity reported for B: %d", rec.Code)
	}

	// Idle → the first command, DeviceInformation.
	uuid1, rt, cmd := commandIn(t, mac.send(t, ts, "/mdm/connect", reportPlist(udidA, "Idle", "", "")))
	if rt != mdm.CmdDeviceInformation || cmd["Queries"] == nil {
		t.Fatalf("first command %s %v", rt, cmd)
	}
	// Acknowledged with its answer → stored on the device; the next one.
	uuid2, rt, _ := commandIn(t, mac.send(t, ts, "/mdm/connect", reportPlist(udidA, "Acknowledged", uuid1,
		`<key>QueryResponses</key><dict><key>OSVersion</key><string>15.2</string><key>DeviceName</key><string>renamed-mac</string></dict>`)))
	if rt != mdm.CmdSecurityInfo {
		t.Fatalf("second command %s", rt)
	}
	dev, _ = ts.st.GetMDMDevice(ctx, udidA)
	if dev.OSVersion != "15.2" || dev.DeviceName != "renamed-mac" || !bytes.Contains(dev.DeviceInfo, []byte("renamed-mac")) {
		t.Fatalf("device info not stored: %+v %s", dev, dev.DeviceInfo)
	}
	// NotNow defers it; the queue moves on to the third.
	uuid3, rt, _ := commandIn(t, mac.send(t, ts, "/mdm/connect", reportPlist(udidA, "NotNow", uuid2, "")))
	if rt != mdm.CmdProfileList {
		t.Fatalf("third command %s", rt)
	}
	// Error is recorded with its chain; nothing else is waiting now.
	u, _, _ := commandIn(t, mac.send(t, ts, "/mdm/connect", reportPlist(udidA, "Error", uuid3,
		`<key>ErrorChain</key><array><dict><key>ErrorCode</key><integer>12021</integer><key>ErrorDomain</key><string>MCMDMErrorDomain</string><key>LocalizedDescription</key><string>nope</string></dict></array>`)))
	if u != "" {
		t.Fatalf("a deferred command was offered again in the same session: %s", u)
	}
	c3, _ := ts.st.GetMDMCommand(ctx, uuid3)
	if c3.State != mdm.StateError || !bytes.Contains(c3.ErrorChain, []byte("12021")) {
		t.Fatalf("errored command %+v %s", c3, c3.ErrorChain)
	}
	// A repeated report does not overwrite the outcome.
	mac.send(t, ts, "/mdm/connect", reportPlist(udidA, "Acknowledged", uuid3, ""))
	if c3, _ = ts.st.GetMDMCommand(ctx, uuid3); c3.State != mdm.StateError {
		t.Fatalf("a repeated report changed a finished command to %s", c3.State)
	}
	// The next session (Idle) offers the deferred command again.
	u, rt, _ = commandIn(t, mac.send(t, ts, "/mdm/connect", reportPlist(udidA, "Idle", "", "")))
	if u != uuid2 || rt != mdm.CmdSecurityInfo {
		t.Fatalf("after idle: %s %s, want the deferred %s", u, rt, uuid2)
	}
	// Sent and never answered: offered again on idle until it has been
	// delivered MaxDeliveries times (twice so far), then failed.
	for i := 3; i <= mdm.MaxDeliveries; i++ {
		u, _, _ = commandIn(t, mac.send(t, ts, "/mdm/connect", reportPlist(udidA, "Idle", "", "")))
		if u != uuid2 {
			t.Fatalf("delivery %d: got %q", i, u)
		}
	}
	u, _, _ = commandIn(t, mac.send(t, ts, "/mdm/connect", reportPlist(udidA, "Idle", "", "")))
	c2, _ := ts.st.GetMDMCommand(ctx, uuid2)
	if u != "" || c2.State != mdm.StateError {
		t.Fatalf("an unanswered command was delivered past the limit: %q %s", u, c2.State)
	}

	// Check-out: the device is no longer enrolled, its queue is closed and
	// its identity is refused for commands.
	if _, err := ts.s.mdmEnqueue(ctx, dev, mdm.CmdProfileList, mdm.CommandParams{}, "", "alice", ""); err != nil {
		t.Fatal(err)
	}
	if rec := mac.send(t, ts, "/mdm/checkin", `<?xml version="1.0"?><plist version="1.0"><dict><key>MessageType</key><string>CheckOut</string><key>Topic</key><string>`+mdmTestTopic+`</string><key>UDID</key><string>`+udidA+`</string></dict></plist>`); rec.Code != http.StatusOK {
		t.Fatalf("check-out: %d", rec.Code)
	}
	dev, _ = ts.st.GetMDMDevice(ctx, udidA)
	if dev.Enrolled || dev.PendingCommands != 0 {
		t.Fatalf("after check-out: enrolled=%v pending=%d", dev.Enrolled, dev.PendingCommands)
	}
	if rec := mac.send(t, ts, "/mdm/connect", reportPlist(udidA, "Idle", "", "")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a checked-out device fetched commands: %d", rec.Code)
	}

	// Turned off, the same device and endpoints are gone.
	cfg, _ := ts.st.GetMDMConfig(ctx)
	cfg.Enabled = false
	_ = ts.st.SaveMDMConfig(ctx, *cfg)
	if rec := mac.send(t, ts, "/mdm/checkin", auth); rec.Code != http.StatusNotFound {
		t.Fatalf("check-in with the MDM off: %d", rec.Code)
	}
}

// Locking and erasing always wait for a second person, even without an
// approval policy; an erase must name the Mac; a token cannot ask; and
// the approved replay queues the command with a sealed PIN only someone
// with enforce.recovery_keys can read.
func TestMDMDestructiveCommandsNeedApproval(t *testing.T) {
	ts := newMDMTestServer(t)
	ctx := context.Background()
	const udid = mdmUDIDC
	mac := ts.enroll(t, ts.mintToken(t, 1), udid)
	if rec := mac.send(t, ts, "/mdm/checkin", authenticatePlist(udid, mdmTestTopic)); rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	if rec := mac.send(t, ts, "/mdm/checkin", tokenUpdatePlist(udid)); rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}

	newUser := func(perms ...string) *store.User {
		u, err := ts.st.CreateLocalUser(ctx, idgen.New("usr-"), idgen.New("mdm-"), "", "mdm test")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ts.st.DeleteUser(context.Background(), u.ID) })
		role, err := ts.st.CreateRole(ctx, idgen.New("role-"), idgen.New("mdm-role-"), "", perms, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ts.st.DeleteRole(context.Background(), role.ID) })
		if err := ts.st.AssignUserRole(ctx, u.ID, role.ID); err != nil {
			t.Fatal(err)
		}
		return u
	}
	operator := newUser(auth.PermDeployManage, auth.PermFleetRead)
	viewer := newUser(auth.PermFleetRead)

	var route http.Handler
	for _, e := range ts.s.routeLog.entries {
		if e.Pattern == mdmCommandRoute {
			route = e.Handler
		}
	}
	send := func(u *store.User, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/mdm/devices/"+udid+"/commands", strings.NewReader(body))
		r.SetPathValue("id", udid)
		r = r.WithContext(auth.WithUser(ctx, u))
		rec := httptest.NewRecorder()
		route.ServeHTTP(rec, r)
		return rec
	}

	// Without deploy.manage: refused outright.
	if rec := send(viewer, `{"request_type":"DeviceInformation"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer sent a command: %d %s", rec.Code, rec.Body)
	}
	// A query is queued at once.
	if rec := send(operator, `{"request_type":"DeviceInformation"}`); rec.Code != http.StatusOK {
		t.Fatalf("query: %d %s", rec.Code, rec.Body)
	}
	// An erase that does not name the Mac.
	if rec := send(operator, `{"request_type":"EraseDevice","confirm":"WRONG"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("erase without the serial: %d %s", rec.Code, rec.Body)
	}
	// Lock: parked, nothing queued.
	before, _ := ts.st.ListMDMCommands(ctx, udid, 100)
	rec := send(operator, `{"request_type":"DeviceLock","message":"Call IT"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("lock: %d %s, want 202 parked", rec.Code, rec.Body)
	}
	var parked mdmParkedResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &parked)
	after, _ := ts.st.ListMDMCommands(ctx, udid, 100)
	if len(after) != len(before) {
		t.Fatal("a lock was queued before anyone approved it")
	}
	req, err := ts.st.GetApprovalRequest(ctx, parked.RequestID)
	if err != nil || req == nil || req.Module != "mdm" || req.PolicyID != mdmApprovalPolicyID || req.State != "pending" {
		t.Fatalf("approval request %+v %v", req, err)
	}
	// An erase with the serial is parked too.
	if rec := send(operator, `{"request_type":"EraseDevice","confirm":"c02testserial"}`); rec.Code != http.StatusAccepted {
		t.Fatalf("erase: %d %s", rec.Code, rec.Body)
	}
	// An API token cannot ask at all, approval-exempt or not.
	tokCtx := auth.WithUser(ctx, &store.User{ID: auth.APITokenUserID, Username: "token:test"})
	r := httptest.NewRequest(http.MethodPost, "/api/mdm/devices/"+udid+"/commands", strings.NewReader(`{"request_type":"DeviceLock"}`))
	r.SetPathValue("id", udid)
	rec = httptest.NewRecorder()
	ts.s.handleMDMCommand(rec, r.WithContext(tokCtx))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("token lock: %d %s", rec.Code, rec.Body)
	}

	// Approved: replayed as the requester, queued with a sealed PIN.
	ts.s.runApproved(ctx, *req)
	done, _ := ts.st.GetApprovalRequest(ctx, req.ID)
	if done.State != "approved" {
		t.Fatalf("replay: %s %s", done.State, done.Outcome)
	}
	if strings.Contains(done.Outcome, `"pin"`) {
		t.Fatal("the PIN leaked into the approval outcome")
	}
	cmds, _ := ts.st.ListMDMCommands(ctx, udid, 100)
	var lock *store.MDMCommand
	for i := range cmds {
		if cmds[i].RequestType == mdm.CmdDeviceLock {
			lock = &cmds[i]
		}
	}
	if lock == nil || !lock.HasPIN || lock.ApprovalID != req.ID || lock.RequestedBy != operator.Username {
		t.Fatalf("approved lock: %+v", lock)
	}
	full, _ := ts.st.GetMDMCommand(ctx, lock.UUID)
	if !full.PayloadSealed || bytes.Contains(full.Payload, []byte("DeviceLock")) {
		t.Fatal("the lock command is stored readable")
	}
	// The Mac receives it, PIN and all, in the clear over its own channel.
	var got map[string]any
	for i := 0; i < 5; i++ {
		u, rt, cmd := commandIn(t, mac.send(t, ts, "/mdm/connect", reportPlist(udid, "Idle", "", "")))
		if u == "" {
			break
		}
		if rt == mdm.CmdDeviceLock {
			got = cmd
			break
		}
		mac.send(t, ts, "/mdm/connect", reportPlist(udid, "Acknowledged", u, ""))
	}
	if got == nil || len(got["PIN"].(string)) != 6 || got["Message"] != "Call IT" {
		t.Fatalf("delivered lock %v", got)
	}

	// Reading the PIN back is enforce.recovery_keys, and audited.
	var reveal http.Handler
	for _, e := range ts.s.routeLog.entries {
		if e.Pattern == "POST /api/mdm/commands/{id}/reveal-pin" {
			reveal = e.Handler
		}
	}
	read := func(u *store.User) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/mdm/commands/"+lock.UUID+"/reveal-pin", nil)
		r.SetPathValue("id", lock.UUID)
		rec := httptest.NewRecorder()
		reveal.ServeHTTP(rec, r.WithContext(auth.WithUser(ctx, u)))
		return rec
	}
	if rec := read(operator); rec.Code != http.StatusForbidden {
		t.Fatalf("deploy.manage read a PIN: %d", rec.Code)
	}
	keeper := newUser(auth.PermRecoveryKeys, auth.PermFleetRead)
	rec = read(keeper)
	var pin mdmPINResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &pin)
	if rec.Code != http.StatusOK || pin.PIN != got["PIN"] {
		t.Fatalf("PIN read: %d %+v", rec.Code, pin)
	}
	_, _ = io.Copy(io.Discard, rec.Body)
}
