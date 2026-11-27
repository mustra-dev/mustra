package mdm

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/smallstep/pkcs7"
)

// AccessRightsAll is every right in com.apple.mdm's AccessRights (1 through
// 4096 OR-ed together). The commands in this slice need inspect and
// install profiles (1, 2), lock (4), erase (8), device and security
// queries (16, 1024) and inspect apps (256); asking for all of them now
// avoids re-enrolling every Mac when a later command needs another,
// since a right cannot be added to an installed enrollment.
const AccessRightsAll = 8191

// EnrollmentOptions describe one enrollment profile.
type EnrollmentOptions struct {
	// ServerURL and CheckInURL are the console's public URL plus
	// /mdm/connect and /mdm/checkin.
	ServerURL  string
	CheckInURL string
	Topic      string
	Identity   *Identity
	// Organization is shown in System Settings as who manages the Mac.
	Organization string
	// Identifier is the profile's PayloadIdentifier, the same on every
	// enrollment profile this server makes so a re-enrollment replaces the
	// previous one.
	Identifier string
}

type payload = map[string]any

// EnrollmentProfile returns the .mobileconfig a Mac installs to enroll: a
// Configuration profile holding the device identity (PKCS#12) and the MDM
// payload pointing at it. Key names follow mdm/profiles/com.apple.mdm.yaml
// and com.apple.security.pkcs12.yaml in apple/device-management.
func EnrollmentProfile(o EnrollmentOptions) ([]byte, error) {
	if o.Identity == nil {
		return nil, errors.New("no device identity")
	}
	if !strings.HasPrefix(o.ServerURL, "https://") || !strings.HasPrefix(o.CheckInURL, "https://") {
		return nil, errors.New("the MDM server and check-in URLs must be https")
	}
	if !strings.HasPrefix(o.Topic, "com.apple.mgmt.") {
		return nil, errors.New("the push topic must start with com.apple.mgmt.")
	}
	if o.Identifier == "" {
		o.Identifier = "com.mustra.mdm.enrollment"
	}
	org := o.Organization
	if org == "" {
		org = "mustra"
	}
	idUUID := strings.ToUpper(uuid.NewString())
	identity := payload{
		"PayloadType":        "com.apple.security.pkcs12",
		"PayloadVersion":     1,
		"PayloadIdentifier":  o.Identifier + ".identity",
		"PayloadUUID":        idUUID,
		"PayloadDisplayName": "MDM device identity",
		"PayloadContent":     o.Identity.P12,
		"Password":           o.Identity.Password,
	}
	mdm := payload{
		"PayloadType":             "com.apple.mdm",
		"PayloadVersion":          1,
		"PayloadIdentifier":       o.Identifier + ".mdm",
		"PayloadUUID":             strings.ToUpper(uuid.NewString()),
		"PayloadDisplayName":      "Device management",
		"IdentityCertificateUUID": idUUID,
		"Topic":                   o.Topic,
		"ServerURL":               o.ServerURL,
		"CheckInURL":              o.CheckInURL,
		// The server authenticates requests by this header, because a
		// proxy in front of it may end TLS (identity.go).
		"SignMessage":         true,
		"CheckOutWhenRemoved": true,
		"AccessRights":        AccessRightsAll,
	}
	top := payload{
		"PayloadType":         "Configuration",
		"PayloadVersion":      1,
		"PayloadIdentifier":   o.Identifier,
		"PayloadUUID":         strings.ToUpper(uuid.NewString()),
		"PayloadDisplayName":  org + " device management",
		"PayloadDescription":  "Lets " + org + " manage this Mac: read its inventory and security state, install and remove configuration profiles, restart it, and, with a second person's approval, lock or erase it.",
		"PayloadOrganization": org,
		"PayloadScope":        "System",
		"PayloadContent":      []any{identity, mdm},
	}
	return Encode(top)
}

// SignProfile wraps a profile in a CMS SignedData, the form macOS shows as
// "Verified" when it trusts the signer. The chain goes in with it so the
// Mac can build the path to a root it knows.
func SignProfile(profile []byte, cert *x509.Certificate, key crypto.PrivateKey, chain []*x509.Certificate) ([]byte, error) {
	sd, err := pkcs7.NewSignedData(profile)
	if err != nil {
		return nil, err
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	if err := sd.AddSignerChain(cert, key, chain, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, err
	}
	return sd.Finish()
}

// ProfileInfo is what the library shows about an uploaded profile.
type ProfileInfo struct {
	Identifier   string   `json:"identifier"`
	DisplayName  string   `json:"display_name"`
	Organization string   `json:"organization,omitempty"`
	Description  string   `json:"description,omitempty"`
	PayloadTypes []string `json:"payload_types"`
	Signed       bool     `json:"signed"`
}

// MaxProfileBytes bounds a library profile. Profiles carrying certificates
// and fonts run to a few hundred KB; past this it is not a profile.
const MaxProfileBytes = 1 << 20

// ParseProfile reads a .mobileconfig, signed or not, for the library. It
// refuses what cannot be a configuration profile, and profiles that would
// change the Mac's MDM enrollment itself.
func ParseProfile(data []byte) (*ProfileInfo, error) {
	if len(data) == 0 {
		return nil, errors.New("empty profile")
	}
	if len(data) > MaxProfileBytes {
		return nil, fmt.Errorf("profile larger than %d bytes", MaxProfileBytes)
	}
	content, signed := data, false
	trimmed := bytes.TrimSpace(data)
	if !bytes.HasPrefix(trimmed, []byte("<?xml")) && !bytes.HasPrefix(trimmed, []byte("<plist")) && !bytes.HasPrefix(data, []byte("bplist")) {
		p7, err := pkcs7.Parse(data)
		if err != nil {
			return nil, errors.New("not a property list or a signed profile")
		}
		if len(p7.Content) == 0 {
			return nil, errors.New("the signed profile has no content")
		}
		if err := p7.Verify(); err != nil {
			return nil, errors.New("the profile's signature does not verify")
		}
		content, signed = p7.Content, true
	}
	var top struct {
		PayloadType         string           `plist:"PayloadType"`
		PayloadIdentifier   string           `plist:"PayloadIdentifier"`
		PayloadDisplayName  string           `plist:"PayloadDisplayName"`
		PayloadOrganization string           `plist:"PayloadOrganization"`
		PayloadDescription  string           `plist:"PayloadDescription"`
		PayloadContent      []map[string]any `plist:"PayloadContent"`
	}
	if err := Decode(content, &top); err != nil {
		return nil, err
	}
	if top.PayloadType != "Configuration" {
		return nil, errors.New("not a configuration profile (PayloadType must be Configuration)")
	}
	if !validIdentifier(top.PayloadIdentifier) {
		return nil, errors.New("the profile has no usable PayloadIdentifier")
	}
	info := &ProfileInfo{Identifier: top.PayloadIdentifier, DisplayName: top.PayloadDisplayName,
		Organization: top.PayloadOrganization, Description: top.PayloadDescription, Signed: signed}
	for _, p := range top.PayloadContent {
		t, _ := p["PayloadType"].(string)
		if t == "com.apple.mdm" {
			// Installing it would point the Mac at another server, or
			// replace this server's enrollment with an unsigned copy.
			return nil, errors.New("the profile contains an MDM payload; enrollment is mustra's own profile, not a library profile")
		}
		if t != "" {
			info.PayloadTypes = append(info.PayloadTypes, t)
		}
	}
	if info.DisplayName == "" {
		info.DisplayName = info.Identifier
	}
	return info, nil
}
