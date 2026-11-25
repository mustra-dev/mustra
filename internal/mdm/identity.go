package mdm

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/smallstep/pkcs7"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// Device identity.
//
// Every enrolled Mac holds an identity certificate that mustra's MDM CA
// issued into its enrollment profile (a com.apple.security.pkcs12 payload
// the com.apple.mdm payload's IdentityCertificateUUID names). The device
// proves it on every check-in and command report in one of two ways,
// both described in Apple's "Mdm-Signature" documentation
// (https://developer.apple.com/documentation/devicemanagement/implementing-device-management/using-the-mdm-signature-header-to-authenticate-requests,
// and SignMessage in mdm/profiles/com.apple.mdm.yaml):
//
//   - Mdm-Signature: with SignMessage set, the device adds this header, a
//     base64 CMS SignedData over the request body, detached, signed with
//     the identity's key and carrying its certificate.
//   - TLS client authentication: the identity is presented in the TLS
//     handshake with the ServerURL.
//
// mustra commonly sits behind a reverse proxy or tunnel that ends TLS, and
// the client certificate never reaches it then, so the enrollment profile
// sets SignMessage and the server requires Mdm-Signature. A client
// certificate is used only when mustra terminates TLS itself and no
// header was sent. Either way the certificate must chain to the MDM CA and
// be one this server issued and has not revoked (the caller checks that),
// and then belongs to exactly one UDID.

// CA is the MDM certificate authority, issuing device identities.
type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// identityValidity is how long a device identity lasts. A device whose
// identity expires stops being able to check in and must re-enroll;
// renewing it in place is listed as follow-up work (ToDo.md).
const identityValidity = 397 * 24 * time.Hour

// NewCA creates an MDM CA, returned with its certificate and PKCS#8 key as
// PEM.
func NewCA(org string) (certPEM, keyPEM string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return "", "", err
	}
	serial, err := randomSerial()
	if err != nil {
		return "", "", err
	}
	if org == "" {
		org = "mustra"
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: org + " MDM device identity CA", Organization: []string{org}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder})), nil
}

// ParseCA reads a CA from PEM.
func ParseCA(certPEM, keyPEM string) (*CA, error) {
	cert, err := ParseCertPEM(certPEM)
	if err != nil {
		return nil, err
	}
	key, err := ParseKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	if !publicKeysEqual(cert.PublicKey, key.Public()) {
		return nil, errors.New("the CA key does not match its certificate")
	}
	return &CA{Cert: cert, Key: key}, nil
}

// Identity is a newly issued device identity.
type Identity struct {
	Cert *x509.Certificate
	// P12 holds the certificate and key, encrypted with Password, in the
	// legacy PKCS#12 encryption (3DES and SHA-1) every macOS release this
	// slice supports imports; newer releases accept it too.
	P12      []byte
	Password string
}

// Issue creates a device identity. The certificate is for client
// authentication only and names nothing about the device, which does not
// exist yet: it is bound to a UDID on the first check-in it signs.
func (ca *CA) Issue(label string) (*Identity, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "mustra MDM device " + label},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(identityValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pw := make([]byte, 18)
	if _, err := rand.Read(pw); err != nil {
		return nil, err
	}
	password := base64.RawURLEncoding.EncodeToString(pw)
	p12, err := pkcs12.LegacyDES.Encode(key, cert, nil, password)
	if err != nil {
		return nil, err
	}
	return &Identity{Cert: cert, P12: p12, Password: password}, nil
}

// SerialHex is how a certificate's serial is stored and matched.
func SerialHex(c *x509.Certificate) string { return strings.ToLower(c.SerialNumber.Text(16)) }

// Fingerprint is a certificate's SHA-256, hex.
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// Errors VerifyRequest returns. Each is a refusal; the caller answers 401
// and never says which, so a probe learns nothing it can tune against.
var (
	ErrNoIdentity     = errors.New("the request carries neither an Mdm-Signature header nor a client certificate")
	ErrBadSignature   = errors.New("the Mdm-Signature does not verify over the request body")
	ErrUntrustedCert  = errors.New("the signing certificate was not issued by this server's MDM CA")
	ErrMultipleSigner = errors.New("the Mdm-Signature must have exactly one signer")
)

// VerifyRequest authenticates a check-in or command report and returns the
// device identity certificate that vouches for it. sigHeader is the
// Mdm-Signature header's value; peerCerts the TLS client chain, if any.
func VerifyRequest(ca *x509.Certificate, body []byte, sigHeader string, peerCerts []*x509.Certificate, now time.Time) (*x509.Certificate, error) {
	var leaf *x509.Certificate
	switch {
	case strings.TrimSpace(sigHeader) != "":
		der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigHeader))
		if err != nil {
			return nil, ErrBadSignature
		}
		p7, err := pkcs7.Parse(der)
		if err != nil {
			return nil, ErrBadSignature
		}
		if len(p7.Signers) != 1 {
			return nil, ErrMultipleSigner
		}
		// The signature is detached: the body it covers is the request's.
		p7.Content = body
		if err := p7.Verify(); err != nil {
			return nil, ErrBadSignature
		}
		leaf = p7.GetOnlySigner()
		if leaf == nil {
			return nil, ErrBadSignature
		}
	case len(peerCerts) > 0:
		leaf = peerCerts[0]
	default:
		return nil, ErrNoIdentity
	}
	if err := VerifyIdentityCert(ca, leaf, now); err != nil {
		return nil, err
	}
	return leaf, nil
}

// VerifyIdentityCert checks a device certificate against the MDM CA.
func VerifyIdentityCert(ca, leaf *x509.Certificate, now time.Time) error {
	if ca == nil || leaf == nil {
		return ErrUntrustedCert
	}
	// Only an end-entity issued for client authentication is a device;
	// the CA's own certificate verifies against itself and is not one.
	if leaf.IsCA || leaf.Equal(ca) || !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return ErrUntrustedCert
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return fmt.Errorf("%w: %v", ErrUntrustedCert, err)
	}
	return nil
}

// SignBody produces an Mdm-Signature header value the way a device does.
// The server never signs a request; tests use it to stand in for a Mac.
func SignBody(body []byte, cert *x509.Certificate, key crypto.PrivateKey) (string, error) {
	sd, err := pkcs7.NewSignedData(body)
	if err != nil {
		return "", err
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	if err := sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{}); err != nil {
		return "", err
	}
	sd.Detach()
	der, err := sd.Finish()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// ParseCertPEM reads the first certificate in PEM text.
func ParseCertPEM(s string) (*x509.Certificate, error) {
	certs, err := ParseCertsPEM(s)
	if err != nil {
		return nil, err
	}
	return certs[0], nil
}

// ParseCertsPEM reads every certificate in PEM text, in order.
func ParseCertsPEM(s string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := []byte(s)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no PEM certificate found")
	}
	return out, nil
}

// ParseKeyPEM reads a PKCS#8, PKCS#1 or SEC 1 private key from PEM text.
func ParseKeyPEM(s string) (crypto.Signer, error) {
	rest := []byte(s)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return nil, errors.New("no PEM private key found")
		}
		switch b.Type {
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
			if err != nil {
				return nil, err
			}
			s, ok := k.(crypto.Signer)
			if !ok {
				return nil, errors.New("unsupported private key type")
			}
			return s, nil
		case "RSA PRIVATE KEY":
			return x509.ParsePKCS1PrivateKey(b.Bytes)
		case "EC PRIVATE KEY":
			return x509.ParseECPrivateKey(b.Bytes)
		case "ENCRYPTED PRIVATE KEY":
			return nil, errors.New("the private key is encrypted; export it without a passphrase, or upload a .p12 with its password")
		}
	}
}

// KeyPEM encodes a private key as PKCS#8 PEM.
func KeyPEM(key crypto.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// CertPEM encodes a certificate as PEM.
func CertPEM(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	type eq interface{ Equal(crypto.PublicKey) bool }
	e, ok := a.(eq)
	return ok && e.Equal(b)
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

// KeyMatches reports whether key is the private half of cert's public key.
func KeyMatches(cert *x509.Certificate, key crypto.Signer) bool {
	return cert != nil && key != nil && publicKeysEqual(cert.PublicKey, key.Public())
}
