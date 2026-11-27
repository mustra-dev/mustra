package mdm

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"crypto/rand"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// A device's messages, as a Mac writes them (apple/device-management
// checkin/*.yaml). Token is <data>, so it must come back as bytes.
const authenticateXML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>MessageType</key><string>Authenticate</string>
<key>Topic</key><string>com.apple.mgmt.External.0b1c2d3e-0000-4000-8000-000000000001</string>
<key>UDID</key><string>0000FE00-1234-5678-9ABC-DEF012345678</string>
<key>SerialNumber</key><string>C02XL0EXAMPL</string>
<key>Model</key><string>Mac14,2</string>
<key>ModelName</key><string>MacBook Air</string>
<key>ProductName</key><string>Mac14,2</string>
<key>OSVersion</key><string>15.1</string>
<key>BuildVersion</key><string>24B83</string>
<key>DeviceName</key><string>Test Mac</string>
</dict></plist>`

const tokenUpdateXML = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>MessageType</key><string>TokenUpdate</string>
<key>Topic</key><string>com.apple.mgmt.External.0b1c2d3e-0000-4000-8000-000000000001</string>
<key>UDID</key><string>0000FE00-1234-5678-9ABC-DEF012345678</string>
<key>Token</key><data>3q2+7w==</data>
<key>PushMagic</key><string>5F2C2E5C-7A1E-4C6F-9A24-ABCDEF012345</string>
<key>AwaitingConfiguration</key><false/>
</dict></plist>`

const testTopic = "com.apple.mgmt.External.0b1c2d3e-0000-4000-8000-000000000001"

func TestParseCheckin(t *testing.T) {
	m, err := ParseCheckin([]byte(authenticateXML))
	if err != nil {
		t.Fatal(err)
	}
	if m.MessageType != MsgAuthenticate || m.SerialNumber != "C02XL0EXAMPL" || m.ModelName != "MacBook Air" || m.OSVersion != "15.1" {
		t.Fatalf("decoded %+v", m)
	}
	if err := m.CheckTopic(testTopic); err != nil {
		t.Fatal(err)
	}
	if err := m.CheckTopic("com.apple.mgmt.External.other"); err == nil {
		t.Fatal("another server's topic was accepted")
	}

	m, err = ParseCheckin([]byte(tokenUpdateXML))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.Token, []byte{0xde, 0xad, 0xbe, 0xef}) || m.PushMagic == "" {
		t.Fatalf("token update decoded as %+v", m)
	}

	bad := map[string]string{
		"no type":           `<plist version="1.0"><dict><key>UDID</key><string>0000FE00-1234</string></dict></plist>`,
		"unknown type":      `<plist version="1.0"><dict><key>MessageType</key><string>DeclarativeManagement</string><key>UDID</key><string>0000FE00-1234</string></dict></plist>`,
		"bad udid":          `<plist version="1.0"><dict><key>MessageType</key><string>Authenticate</string><key>UDID</key><string>../../etc</string></dict></plist>`,
		"token without one": `<plist version="1.0"><dict><key>MessageType</key><string>TokenUpdate</string><key>UDID</key><string>0000FE00-1234</string></dict></plist>`,
		"openstep":          `{ MessageType = Authenticate; UDID = "0000FE00-1234"; }`,
		"empty":             ``,
	}
	for name, body := range bad {
		if _, err := ParseCheckin([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The user channel is answered as Apple documents for a server
	// without it, which needs the caller to recognise it.
	_, err = ParseCheckin([]byte(`<plist version="1.0"><dict><key>MessageType</key><string>UserAuthenticate</string><key>UDID</key><string>0000FE00-1234</string><key>UserID</key><string>u</string></dict></plist>`))
	if !errors.Is(err, ErrUserChannel) {
		t.Fatalf("user channel: %v", err)
	}
}

func TestPlistRoundTripAndJSON(t *testing.T) {
	when := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	in := map[string]any{"S": "x", "N": int64(3), "B": true, "D": []byte{1, 2, 3}, "T": when, "A": []any{"a", map[string]any{"k": []byte{9}}}}
	data, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("<data>AQID</data>")) {
		t.Fatalf("data not encoded as <data>: %s", data)
	}
	var out map[string]any
	if err := Decode(data, &out); err != nil {
		t.Fatal(err)
	}
	j, err := json.Marshal(JSONValue(out, 1))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"A":["a",{"k":"CQ=="}],"B":true,"D":"[3 bytes of data]","N":3,"S":"x","T":"2026-11-01T12:00:00Z"}`
	if string(j) != want {
		t.Fatalf("JSON\n got %s\nwant %s", j, want)
	}
}

func TestBuildCommand(t *testing.T) {
	id := NewCommandUUID()
	data, err := BuildCommand(id, CmdDeviceLock, CommandParams{Message: "Call IT", PhoneNumber: "+1 555 0100"}, "123456")
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		CommandUUID string
		Command     map[string]any
	}
	if err := Decode(data, &env); err != nil {
		t.Fatal(err)
	}
	if env.CommandUUID != id || env.Command["RequestType"] != CmdDeviceLock || env.Command["PIN"] != "123456" || env.Command["Message"] != "Call IT" {
		t.Fatalf("lock command %+v", env)
	}
	if _, err := BuildCommand(id, CmdDeviceLock, CommandParams{}, ""); err == nil {
		t.Fatal("lock without a PIN built")
	}
	if _, err := BuildCommand(id, CmdEraseDevice, CommandParams{}, "12a456"); err == nil {
		t.Fatal("erase with a malformed PIN built")
	}
	if _, err := BuildCommand(id, CmdRestartDevice, CommandParams{}, "123456"); err == nil {
		t.Fatal("restart carrying a PIN built")
	}
	if _, err := BuildCommand(id, "ClearPasscode", CommandParams{}, ""); err == nil {
		t.Fatal("an unsupported command built")
	}
	if _, err := BuildCommand(id, CmdRemoveProfile, CommandParams{Identifier: "a b"}, ""); err == nil {
		t.Fatal("a malformed identifier accepted")
	}
	if _, err := BuildCommand(id, CmdDeviceInformation, CommandParams{Message: "x"}, ""); err == nil {
		t.Fatal("a parameter of another command accepted")
	}
	data, err = BuildCommand(id, CmdInstallProfile, CommandParams{Profile: []byte("<plist/>")}, "")
	if err != nil || !bytes.Contains(data, []byte("<key>Payload</key>")) {
		t.Fatalf("install profile: %v %s", err, data)
	}
	pin, err := NewPIN()
	if err != nil || len(pin) != 6 || strings.Trim(pin, "0123456789") != "" {
		t.Fatalf("PIN %q %v", pin, err)
	}
}

// The command queue's state machine: what each report status does to a
// command, and what a new session (Idle) does to one left hanging.
func TestQueueStateMachine(t *testing.T) {
	cases := []struct {
		from, status, want string
		err                error
	}{
		{StateSent, StatusAcknowledged, StateAcknowledged, nil},
		{StateSent, StatusError, StateError, nil},
		{StateSent, StatusCommandFormatError, StateFormatError, nil},
		{StateSent, StatusNotNow, StateNotNow, nil},
		{StateNotNow, StatusAcknowledged, StateAcknowledged, nil},
		// Cancelled after delivery: the device's outcome still counts,
		// and a NotNow leaves it cancelled rather than queued again.
		{StateCancelled, StatusAcknowledged, StateAcknowledged, nil},
		{StateCancelled, StatusNotNow, StateCancelled, nil},
		// A repeated report never overwrites the first.
		{StateAcknowledged, StatusError, StateAcknowledged, ErrAlreadyFinal},
		{StateError, StatusAcknowledged, StateError, ErrAlreadyFinal},
		{StateExpired, StatusAcknowledged, StateExpired, ErrAlreadyFinal},
	}
	for _, c := range cases {
		got, err := ReportTransition(c.from, c.status)
		if got != c.want || !errors.Is(err, c.err) {
			t.Errorf("%s + %s = %s (%v), want %s (%v)", c.from, c.status, got, err, c.want, c.err)
		}
	}
	if _, err := ReportTransition(StateSent, "Maybe"); err == nil {
		t.Error("unknown status accepted")
	}

	if s, ok := IdleTransition(StateNotNow, 1); !ok || s != StateQueued {
		t.Errorf("not_now on idle → %s %v", s, ok)
	}
	if s, ok := IdleTransition(StateSent, 1); !ok || s != StateQueued {
		t.Errorf("sent once, unanswered, on idle → %s %v", s, ok)
	}
	if s, ok := IdleTransition(StateSent, MaxDeliveries); !ok || s != StateError {
		t.Errorf("sent %d times, unanswered, on idle → %s %v; want error (no restart loop)", MaxDeliveries, s, ok)
	}
	for _, st := range []string{StateQueued, StateAcknowledged, StateCancelled} {
		if _, ok := IdleTransition(st, 0); ok {
			t.Errorf("idle changed %s", st)
		}
	}
}

func TestParseReport(t *testing.T) {
	body := `<plist version="1.0"><dict>
<key>UDID</key><string>0000FE00-1234-5678-9ABC-DEF012345678</string>
<key>Status</key><string>Acknowledged</string>
<key>CommandUUID</key><string>ABC</string>
<key>QueryResponses</key><dict><key>OSVersion</key><string>15.1</string></dict>
</dict></plist>`
	r, err := ParseReport([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	qr, _ := r.Raw[ResultKey(CmdDeviceInformation)].(map[string]any)
	if r.Status != StatusAcknowledged || r.CommandUUID != "ABC" || qr["OSVersion"] != "15.1" {
		t.Fatalf("report %+v", r)
	}
	errBody := `<plist version="1.0"><dict>
<key>UDID</key><string>0000FE00-1234</string><key>Status</key><string>Error</string><key>CommandUUID</key><string>X</string>
<key>ErrorChain</key><array><dict><key>ErrorCode</key><integer>12021</integer><key>ErrorDomain</key><string>MCMDMErrorDomain</string><key>LocalizedDescription</key><string>Unknown command</string></dict></array>
</dict></plist>`
	r, err = ParseReport([]byte(errBody))
	if err != nil || len(r.ErrorChain) != 1 || r.ErrorChain[0].ErrorCode != 12021 {
		t.Fatalf("error report %+v %v", r, err)
	}
	if _, err := ParseReport([]byte(`<plist version="1.0"><dict><key>UDID</key><string>0000FE00-1234</string><key>Status</key><string>Acknowledged</string></dict></plist>`)); err == nil {
		t.Fatal("an acknowledgement without CommandUUID accepted")
	}
}

func newTestCA(t *testing.T) *CA {
	t.Helper()
	certPEM, keyPEM, err := NewCA("Example Org")
	if err != nil {
		t.Fatal(err)
	}
	ca, err := ParseCA(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

// keyOf recovers the private key from an issued identity, the way the Mac
// has it after installing the profile.
func keyOf(t *testing.T, id *Identity) *rsa.PrivateKey {
	t.Helper()
	key, cert, _, err := pkcs12.DecodeChain(id.P12, id.Password)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.Equal(id.Cert) {
		t.Fatal("the .p12 holds another certificate")
	}
	return key.(*rsa.PrivateKey)
}

func TestVerifyRequest(t *testing.T) {
	ca := newTestCA(t)
	id, err := ca.Issue("t1")
	if err != nil {
		t.Fatal(err)
	}
	key := keyOf(t, id)
	body := []byte(authenticateXML)
	sig, err := SignBody(body, id.Cert, key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	got, err := VerifyRequest(ca.Cert, body, sig, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if SerialHex(got) != SerialHex(id.Cert) {
		t.Fatal("verified as another certificate")
	}

	// The same signature over another body.
	if _, err := VerifyRequest(ca.Cert, []byte(tokenUpdateXML), sig, nil, now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("signature moved to another body: %v", err)
	}
	// Garbage in the header.
	if _, err := VerifyRequest(ca.Cert, body, "bm90IGNtcw==", nil, now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("garbage signature: %v", err)
	}
	// A valid signature by an identity another CA issued.
	other := newTestCA(t)
	oid, _ := other.Issue("t2")
	osig, _ := SignBody(body, oid.Cert, keyOf(t, oid))
	if _, err := VerifyRequest(ca.Cert, body, osig, nil, now); !errors.Is(err, ErrUntrustedCert) {
		t.Fatalf("foreign identity: %v", err)
	}
	// An expired identity.
	if _, err := VerifyRequest(ca.Cert, body, sig, nil, now.Add(2*identityValidity)); !errors.Is(err, ErrUntrustedCert) {
		t.Fatalf("expired identity: %v", err)
	}
	// Nothing at all.
	if _, err := VerifyRequest(ca.Cert, body, "", nil, now); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("no identity: %v", err)
	}
	// A TLS client certificate is accepted when it chains to the CA, and
	// refused otherwise.
	if _, err := VerifyRequest(ca.Cert, body, "", []*x509.Certificate{id.Cert}, now); err != nil {
		t.Fatalf("client certificate: %v", err)
	}
	if _, err := VerifyRequest(ca.Cert, body, "", []*x509.Certificate{oid.Cert}, now); !errors.Is(err, ErrUntrustedCert) {
		t.Fatalf("foreign client certificate: %v", err)
	}
	// The CA's own certificate is not a device identity.
	if _, err := VerifyRequest(ca.Cert, body, "", []*x509.Certificate{ca.Cert}, now); err == nil {
		t.Fatal("the CA certificate was accepted as a device")
	}
}

func TestEnrollmentProfile(t *testing.T) {
	ca := newTestCA(t)
	id, _ := ca.Issue("t1")
	data, err := EnrollmentProfile(EnrollmentOptions{ServerURL: "https://console.example.com/mdm/connect",
		CheckInURL: "https://console.example.com/mdm/checkin", Topic: testTopic, Identity: id, Organization: "Example"})
	if err != nil {
		t.Fatal(err)
	}
	var top struct {
		PayloadType    string
		PayloadScope   string
		PayloadContent []map[string]any
	}
	if err := Decode(data, &top); err != nil {
		t.Fatal(err)
	}
	if top.PayloadType != "Configuration" || top.PayloadScope != "System" || len(top.PayloadContent) != 2 {
		t.Fatalf("profile %+v", top)
	}
	ident, mdmp := top.PayloadContent[0], top.PayloadContent[1]
	if ident["PayloadType"] != "com.apple.security.pkcs12" || mdmp["PayloadType"] != "com.apple.mdm" {
		t.Fatalf("payloads %v / %v", ident["PayloadType"], mdmp["PayloadType"])
	}
	if mdmp["IdentityCertificateUUID"] != ident["PayloadUUID"] || mdmp["SignMessage"] != true || mdmp["Topic"] != testTopic {
		t.Fatalf("mdm payload %v", mdmp)
	}
	if _, _, _, err := pkcs12.DecodeChain(ident["PayloadContent"].([]byte), ident["Password"].(string)); err != nil {
		t.Fatalf("embedded identity does not open with its password: %v", err)
	}
	// The library refuses it: it carries an MDM payload.
	if _, err := ParseProfile(data); err == nil {
		t.Fatal("an enrollment profile was accepted into the library")
	}
	if _, err := EnrollmentProfile(EnrollmentOptions{ServerURL: "http://x/mdm/connect", CheckInURL: "https://x", Topic: testTopic, Identity: id}); err == nil {
		t.Fatal("plain http accepted")
	}
}

const wifiProfile = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>PayloadType</key><string>Configuration</string>
<key>PayloadVersion</key><integer>1</integer>
<key>PayloadIdentifier</key><string>com.example.screensaver</string>
<key>PayloadUUID</key><string>7A3B0A3C-0000-4000-8000-000000000002</string>
<key>PayloadDisplayName</key><string>Screen saver</string>
<key>PayloadContent</key><array><dict>
<key>PayloadType</key><string>com.apple.screensaver</string>
<key>PayloadIdentifier</key><string>com.example.screensaver.1</string>
<key>PayloadUUID</key><string>7A3B0A3C-0000-4000-8000-000000000003</string>
<key>PayloadVersion</key><integer>1</integer>
<key>idleTime</key><integer>300</integer>
</dict></array>
</dict></plist>`

func TestParseProfile(t *testing.T) {
	info, err := ParseProfile([]byte(wifiProfile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Identifier != "com.example.screensaver" || info.Signed || len(info.PayloadTypes) != 1 || info.PayloadTypes[0] != "com.apple.screensaver" {
		t.Fatalf("info %+v", info)
	}
	// Signed, it reads the same and says so.
	ca := newTestCA(t)
	signer, _ := ca.Issue("signer")
	signed, err := SignProfile([]byte(wifiProfile), signer.Cert, keyOf(t, signer), []*x509.Certificate{ca.Cert})
	if err != nil {
		t.Fatal(err)
	}
	info, err = ParseProfile(signed)
	if err != nil || !info.Signed || info.Identifier != "com.example.screensaver" {
		t.Fatalf("signed: %+v %v", info, err)
	}
	// Tampered with after signing.
	bad := bytes.Replace(signed, []byte("idleTime"), []byte("idleTimf"), 1)
	if _, err := ParseProfile(bad); err == nil {
		t.Fatal("a tampered signed profile was accepted")
	}
	if _, err := ParseProfile([]byte(strings.Replace(wifiProfile, "Configuration", "Something", 1))); err == nil {
		t.Fatal("a non-configuration plist accepted")
	}
}

// pushCert makes a certificate shaped like Apple's MDM push certificate:
// the topic in the subject's UID.
func pushCert(t *testing.T) *PushCert {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject: pkix.Name{CommonName: "APSP:test", ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: oidUID, Value: testTopic}}},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, _ := KeyPEM(key)
	cert, _ := x509.ParseCertificate(der)
	pc, err := ParsePushCertPEM(CertPEM(cert), keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return pc
}

// The push, against a local HTTP/2 server standing in for APNs: the
// request must arrive over HTTP/2 with the push certificate as client
// certificate, the MDM headers and {"mdm": PushMagic}.
func TestPushAgainstHTTP2StandIn(t *testing.T) {
	pc := pushCert(t)
	if pc.Topic != testTopic {
		t.Fatalf("topic %q", pc.Topic)
	}
	type seen struct {
		proto, path, topic, pushType, priority, body string
		clientCert                                   *x509.Certificate
	}
	got := make(chan seen, 2)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s := seen{proto: r.Proto, path: r.URL.Path, topic: r.Header.Get("apns-topic"), pushType: r.Header.Get("apns-push-type"),
			priority: r.Header.Get("apns-priority"), body: string(b)}
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			s.clientCert = r.TLS.PeerCertificates[0]
		}
		got <- s
		if strings.HasSuffix(r.URL.Path, "/00") {
			w.WriteHeader(http.StatusGone)
			_, _ = w.Write([]byte(`{"reason":"Unregistered"}`))
			return
		}
		w.Header().Set("apns-id", "11111111-2222-3333-4444-555555555555")
	}))
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	srv.StartTLS()
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())

	p := NewPusher(pc, srv.URL, roots)
	token := []byte{0xde, 0xad, 0xbe, 0xef}
	id, err := p.Push(context.Background(), token, "MAGIC-1")
	if err != nil {
		t.Fatal(err)
	}
	if id == "" {
		t.Fatal("no apns-id returned")
	}
	s := <-got
	if s.proto != "HTTP/2.0" {
		t.Fatalf("pushed over %s; APNs needs HTTP/2", s.proto)
	}
	if s.path != "/3/device/"+hex.EncodeToString(token) || s.topic != testTopic || s.pushType != "mdm" || s.priority != "10" {
		t.Fatalf("request %+v", s)
	}
	if s.body != `{"mdm":"MAGIC-1"}` {
		t.Fatalf("body %s", s.body)
	}
	if s.clientCert == nil || !s.clientCert.Equal(pc.Cert) {
		t.Fatal("the push certificate was not presented")
	}

	_, err = p.Push(context.Background(), []byte{0}, "MAGIC-1")
	var pe *PushError
	if !errors.As(err, &pe) || !pe.Unregistered() {
		t.Fatalf("unregistered token: %v", err)
	}
	<-got
	if _, err := p.Push(context.Background(), nil, "x"); err == nil {
		t.Fatal("pushed without a token")
	}
}

func TestPushCSRAndCertParsing(t *testing.T) {
	csrPEM, keyPEM, err := NewPushCSR("Example", "it@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(csrPEM, "CERTIFICATE REQUEST") {
		t.Fatal("no CSR")
	}
	if _, err := ParseKeyPEM(keyPEM); err != nil {
		t.Fatal(err)
	}
	// A certificate without a topic is not a push certificate.
	ca := newTestCA(t)
	caKey, _ := KeyPEM(ca.Key)
	if _, err := ParsePushCertPEM(CertPEM(ca.Cert), caKey); err == nil {
		t.Fatal("a CA certificate was accepted as a push certificate")
	}
	// A key that is not the certificate's.
	pc := pushCert(t)
	if _, err := ParsePushCertPEM(CertPEM(pc.Cert), caKey); err == nil {
		t.Fatal("a mismatched key accepted")
	}
	// The same certificate as a .p12.
	p12, err := pkcs12.Modern.Encode(pc.Key, pc.Cert, nil, "pw")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParsePushCertP12(p12, "pw")
	if err != nil || got.Topic != testTopic {
		t.Fatalf(".p12: %v %v", got, err)
	}
	if _, err := ParsePushCertP12(p12, "wrong"); err == nil {
		t.Fatal("wrong .p12 password accepted")
	}
}
