package saasmon

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// CRX3, the package format Chrome and Edge install extensions from.
//
// The server serves the extension to browsers itself (an update manifest
// and the .crx it points to) so that it can be force-installed by policy
// without the Chrome Web Store. The operator packs it with a key of their
// own (cmd/saas-extension-pack); the extension's ID is derived from that
// key, so the same key gives the same ID for every later version, and the
// key never leaves the operator's machine.
//
// Layout: "Cr24", a little-endian uint32 version (3), a little-endian
// uint32 header length, a CrxFileHeader protobuf, then the zip archive.
// The header carries signatures over "CRX3 SignedData\x00", the length of
// the signed header data, the signed header data (a SignedData protobuf
// holding the 16-byte crx_id), and the archive. The ID is the first 16
// bytes of SHA-256 of the signing key's DER, written in the letters a-p.

const (
	crxMagic        = "Cr24"
	crxSignedPrefix = "CRX3 SignedData\x00"
	// MaxCRXBytes bounds an uploaded package. The extension is a few
	// kilobytes; this leaves room for icons and growth, not for anything
	// else to be served from here.
	MaxCRXBytes = 8 << 20
	maxHeader   = 64 << 10
	maxManifest = 256 << 10
	// Protobuf field numbers in CrxFileHeader and its messages.
	fieldRSAProof   = 2
	fieldECDSAProof = 3
	fieldSignedData = 10000
	fieldPublicKey  = 1
	fieldSignature  = 2
	fieldCRXID      = 1
)

// CRXInfo is what a package says about itself.
type CRXInfo struct {
	ID      string `json:"extension_id"`
	Version string `json:"version"`
	Name    string `json:"name"`
}

// ExtensionID is the ID Chrome gives an extension signed by this public
// key (DER SubjectPublicKeyInfo).
func ExtensionID(publicKeyDER []byte) string {
	sum := sha256.Sum256(publicKeyDER)
	return idFromCRXID(sum[:16])
}

func idFromCRXID(b []byte) string {
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, 'a'+c>>4, 'a'+c&0x0f)
	}
	return string(out)
}

// BuildCRX signs archive (a zip with manifest.json at its root) with key
// and returns the package and the extension ID.
func BuildCRX(archive []byte, key *rsa.PrivateKey) ([]byte, string, error) {
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(pub)
	crxID := sum[:16]
	signedData := pbBytes(nil, fieldCRXID, crxID)
	digest := signedDigest(signedData, archive)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	if err != nil {
		return nil, "", err
	}
	proof := pbBytes(nil, fieldPublicKey, pub)
	proof = pbBytes(proof, fieldSignature, sig)
	header := pbBytes(nil, fieldRSAProof, proof)
	header = pbBytes(header, fieldSignedData, signedData)

	var out bytes.Buffer
	out.WriteString(crxMagic)
	_ = binary.Write(&out, binary.LittleEndian, uint32(3))
	_ = binary.Write(&out, binary.LittleEndian, uint32(len(header)))
	out.Write(header)
	out.Write(archive)
	return out.Bytes(), idFromCRXID(crxID), nil
}

func signedDigest(signedData, archive []byte) []byte {
	h := sha256.New()
	h.Write([]byte(crxSignedPrefix))
	var n [4]byte
	binary.LittleEndian.PutUint32(n[:], uint32(len(signedData)))
	h.Write(n[:])
	h.Write(signedData)
	h.Write(archive)
	return h.Sum(nil)
}

// ParseCRX checks a package the way a browser would before installing it
// (format, every signature, the ID's key among the signers) and reads the
// ID, version and name from it. It refuses a Manifest V2 extension, which
// current browsers will not run.
func ParseCRX(data []byte) (CRXInfo, error) {
	var info CRXInfo
	if len(data) > MaxCRXBytes {
		return info, fmt.Errorf("the package is larger than %d MB", MaxCRXBytes>>20)
	}
	if len(data) < 12 || string(data[:4]) != crxMagic {
		return info, errors.New("not a CRX package (no Cr24 magic)")
	}
	if v := binary.LittleEndian.Uint32(data[4:8]); v != 3 {
		return info, fmt.Errorf("CRX version %d; only CRX3 is supported", v)
	}
	hlen := binary.LittleEndian.Uint32(data[8:12])
	if hlen > maxHeader || int(hlen) > len(data)-12 {
		return info, errors.New("CRX header length out of range")
	}
	header, archive := data[12:12+hlen], data[12+hlen:]

	fields, err := pbFields(header)
	if err != nil {
		return info, fmt.Errorf("CRX header: %w", err)
	}
	var signedData []byte
	var rsaProofs, ecProofs [][]byte
	for _, f := range fields {
		switch f.num {
		case fieldSignedData:
			signedData = f.val
		case fieldRSAProof:
			rsaProofs = append(rsaProofs, f.val)
		case fieldECDSAProof:
			ecProofs = append(ecProofs, f.val)
		}
	}
	if signedData == nil {
		return info, errors.New("CRX header has no signed header data")
	}
	sdFields, err := pbFields(signedData)
	if err != nil {
		return info, fmt.Errorf("CRX signed data: %w", err)
	}
	var crxID []byte
	for _, f := range sdFields {
		if f.num == fieldCRXID {
			crxID = f.val
		}
	}
	if len(crxID) != 16 {
		return info, errors.New("CRX signed data has no 16-byte ID")
	}
	digest := signedDigest(signedData, archive)
	idKeySigned := false
	verify := func(proof []byte, ec bool) error {
		pf, err := pbFields(proof)
		if err != nil {
			return err
		}
		var pubDER, sig []byte
		for _, f := range pf {
			switch f.num {
			case fieldPublicKey:
				pubDER = f.val
			case fieldSignature:
				sig = f.val
			}
		}
		pub, err := x509.ParsePKIXPublicKey(pubDER)
		if err != nil {
			return fmt.Errorf("signer key: %w", err)
		}
		switch k := pub.(type) {
		case *rsa.PublicKey:
			if ec {
				return errors.New("an ECDSA proof holds an RSA key")
			}
			if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, digest, sig); err != nil {
				return errors.New("a signature does not verify: the package was changed after it was signed")
			}
		case *ecdsa.PublicKey:
			if !ec {
				return errors.New("an RSA proof holds an ECDSA key")
			}
			if !ecdsa.VerifyASN1(k, digest, sig) {
				return errors.New("a signature does not verify: the package was changed after it was signed")
			}
		default:
			return errors.New("unsupported signer key type")
		}
		sum := sha256.Sum256(pubDER)
		if bytes.Equal(sum[:16], crxID) {
			idKeySigned = true
		}
		return nil
	}
	if len(rsaProofs) == 0 {
		return info, errors.New("the package is not signed")
	}
	for _, p := range rsaProofs {
		if err := verify(p, false); err != nil {
			return info, err
		}
	}
	for _, p := range ecProofs {
		if err := verify(p, true); err != nil {
			return info, err
		}
	}
	if !idKeySigned {
		return info, errors.New("the package's ID does not belong to any key that signed it")
	}
	info.ID = idFromCRXID(crxID)

	m, err := readManifest(archive)
	if err != nil {
		return info, err
	}
	if m.ManifestVersion != 3 {
		return info, fmt.Errorf("manifest_version %d; browsers only run Manifest V3 extensions", m.ManifestVersion)
	}
	if !ValidVersion(m.Version) {
		return info, fmt.Errorf("manifest version %q is not a valid extension version", m.Version)
	}
	info.Version, info.Name = m.Version, m.Name
	if len(info.Name) > 75 {
		info.Name = info.Name[:75]
	}
	return info, nil
}

type extManifest struct {
	ManifestVersion int    `json:"manifest_version"`
	Version         string `json:"version"`
	Name            string `json:"name"`
}

func readManifest(archive []byte) (extManifest, error) {
	var m extManifest
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return m, fmt.Errorf("the package's archive is not a zip: %w", err)
	}
	for _, f := range zr.File {
		if f.Name != "manifest.json" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return m, err
		}
		defer rc.Close()
		raw, err := io.ReadAll(io.LimitReader(rc, maxManifest+1))
		if err != nil {
			return m, err
		}
		if len(raw) > maxManifest {
			return m, errors.New("manifest.json is too large")
		}
		if err := json.Unmarshal(raw, &m); err != nil {
			return m, fmt.Errorf("manifest.json: %w", err)
		}
		return m, nil
	}
	return m, errors.New("the package has no manifest.json at its root")
}

// --- the few protobuf pieces CRX3 needs: length-delimited fields only ---

type pbField struct {
	num int
	val []byte
}

func pbBytes(b []byte, num int, val []byte) []byte {
	b = binary.AppendUvarint(b, uint64(num)<<3|2)
	b = binary.AppendUvarint(b, uint64(len(val)))
	return append(b, val...)
}

// pbFields reads a message's length-delimited fields. Varint and fixed
// fields are skipped; groups are refused.
func pbFields(b []byte) ([]pbField, error) {
	var out []pbField
	for len(b) > 0 {
		key, n := binary.Uvarint(b)
		if n <= 0 {
			return nil, errors.New("malformed field key")
		}
		b = b[n:]
		num, wire := int(key>>3), key&7
		switch wire {
		case 0:
			_, n := binary.Uvarint(b)
			if n <= 0 {
				return nil, errors.New("malformed varint")
			}
			b = b[n:]
		case 1:
			if len(b) < 8 {
				return nil, errors.New("truncated fixed64")
			}
			b = b[8:]
		case 5:
			if len(b) < 4 {
				return nil, errors.New("truncated fixed32")
			}
			b = b[4:]
		case 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || l > uint64(len(b)-n) {
				return nil, errors.New("truncated field")
			}
			out = append(out, pbField{num: num, val: b[n : n+int(l)]})
			b = b[n+int(l):]
		default:
			return nil, fmt.Errorf("unsupported wire type %d", wire)
		}
	}
	return out, nil
}
