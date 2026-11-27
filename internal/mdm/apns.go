package mdm

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// The APNs push that wakes a device.
//
// An MDM server never reaches a device directly: it asks Apple Push
// Notification service to tell the device to connect, and the device then
// fetches its commands from the ServerURL. The push is an HTTP/2 POST to
// /3/device/<token> on api.push.apple.com, authenticated with the MDM push
// certificate as a TLS client certificate, with apns-topic set to the
// certificate's topic, apns-push-type "mdm" and the JSON body
// {"mdm":"<PushMagic>"} (Apple: "Sending MDM commands to a device" and
// "Sending notification requests to APNs").

// ProductionAPNs is Apple's production push gateway. MDM push certificates
// from the Apple Push Certificates Portal work only there.
const ProductionAPNs = "https://api.push.apple.com"

// oidUID is the X.500 userId attribute (0.9.2342.19200300.100.1.1). Apple
// puts the push topic, com.apple.mgmt.External.<uuid>, in the MDM push
// certificate's subject under it.
var oidUID = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}

// PushCert is the MDM push certificate with its key.
type PushCert struct {
	Cert  *x509.Certificate
	Key   crypto.Signer
	Topic string
}

// TopicFromCert reads the push topic from the certificate's subject.
func TopicFromCert(c *x509.Certificate) (string, error) {
	for _, n := range c.Subject.Names {
		if n.Type.Equal(oidUID) {
			if s, ok := n.Value.(string); ok && strings.HasPrefix(s, "com.apple.mgmt.") {
				return s, nil
			}
		}
	}
	return "", errors.New("this is not an MDM push certificate: its subject has no com.apple.mgmt. topic (UID)")
}

// ParsePushCertPEM reads a push certificate and its key from PEM.
func ParsePushCertPEM(certPEM, keyPEM string) (*PushCert, error) {
	cert, err := ParseCertPEM(certPEM)
	if err != nil {
		return nil, err
	}
	key, err := ParseKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	return newPushCert(cert, key)
}

// ParsePushCertP12 reads a push certificate and its key from a PKCS#12
// file, as Keychain Access exports it.
func ParsePushCertP12(data []byte, password string) (*PushCert, error) {
	key, cert, _, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		return nil, fmt.Errorf("reading the .p12: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("unsupported private key in the .p12")
	}
	return newPushCert(cert, signer)
}

func newPushCert(cert *x509.Certificate, key crypto.Signer) (*PushCert, error) {
	if !publicKeysEqual(cert.PublicKey, key.Public()) {
		return nil, errors.New("the private key does not belong to this certificate")
	}
	topic, err := TopicFromCert(cert)
	if err != nil {
		return nil, err
	}
	return &PushCert{Cert: cert, Key: key, Topic: topic}, nil
}

// NewPushCSR makes the key and certificate signing request an operator
// takes to an MDM vendor to be signed, the first step to a push
// certificate (see docs/guides/apple-mdm.md). The key stays with the server.
func NewPushCSR(org, email string) (csrPEM, keyPEM string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	if org == "" {
		org = "mustra"
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: org + " MDM push", Organization: []string{org}}}
	if email != "" {
		tmpl.EmailAddresses = []string{email}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return "", "", err
	}
	keyPEM, err = KeyPEM(key)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), keyPEM, nil
}

// Pusher sends MDM pushes.
type Pusher struct {
	base   string
	topic  string
	client *http.Client
}

// NewPusher returns a pusher authenticating with the push certificate to
// base (ProductionAPNs outside tests). rootCAs, when set, replaces the
// system roots, for a test stand-in.
func NewPusher(pc *PushCert, base string, rootCAs *x509.CertPool) *Pusher {
	tr := &http.Transport{
		// Egress often goes through a proxy; APNs over HTTP/2 works
		// through an HTTPS CONNECT proxy like any other TLS.
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{{Certificate: [][]byte{pc.Cert.Raw}, PrivateKey: pc.Key, Leaf: pc.Cert}},
			RootCAs:      rootCAs,
		},
		// APNs speaks only HTTP/2. A custom TLS config turns Go's
		// automatic HTTP/2 off unless asked for.
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     5 * time.Minute,
	}
	return &Pusher{base: strings.TrimRight(base, "/"), topic: pc.Topic, client: &http.Client{Transport: tr, Timeout: 20 * time.Second}}
}

// PushRequest builds the push for one device.
func PushRequest(ctx context.Context, base, topic string, token []byte, pushMagic string) (*http.Request, error) {
	if len(token) == 0 || pushMagic == "" {
		return nil, errors.New("the device has not sent a push token yet")
	}
	body, err := json.Marshal(map[string]string{"mdm": pushMagic})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+"/3/device/"+hex.EncodeToString(token), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apns-topic", topic)
	req.Header.Set("apns-push-type", "mdm")
	req.Header.Set("apns-priority", "10")
	// A push only says "connect"; one that could not be delivered within a
	// day is superseded by the next.
	req.Header.Set("apns-expiration", fmt.Sprint(time.Now().Add(24*time.Hour).Unix()))
	return req, nil
}

// PushError is APNs refusing a push.
type PushError struct {
	Status int
	Reason string
}

func (e *PushError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("APNs refused the push: HTTP %d %s", e.Status, e.Reason)
	}
	return fmt.Sprintf("APNs refused the push: HTTP %d", e.Status)
}

// Unregistered reports a token APNs says is no longer valid: the device
// left (or was erased) without checking out.
func (e *PushError) Unregistered() bool {
	return e.Status == http.StatusGone || e.Reason == "BadDeviceToken" || e.Reason == "Unregistered"
}

// Push wakes one device. It returns APNs' apns-id on success.
func (p *Pusher) Push(ctx context.Context, token []byte, pushMagic string) (string, error) {
	req, err := PushRequest(ctx, p.base, p.topic, token, pushMagic)
	if err != nil {
		return "", err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return resp.Header.Get("apns-id"), nil
	}
	var r struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&r)
	return "", &PushError{Status: resp.StatusCode, Reason: r.Reason}
}
