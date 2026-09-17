package jwe

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/idfoundry/oid4vcgo/internal/jwk"
)

// Alg identifies a JWE key management algorithm this package supports.
type Alg string

// ECDHES is Direct Key Agreement using ECDH-ES (RFC 7518 §4.6): the
// content encryption key is derived directly from the ECDH shared
// secret via the Concat KDF, with no separate wrapped-key segment.
const ECDHES Alg = "ECDH-ES"

// Enc identifies a JWE content encryption algorithm this package
// supports — all AES-GCM (RFC 7518 §5.3), varying only in key size.
type Enc string

const (
	A128GCM Enc = "A128GCM"
	A192GCM Enc = "A192GCM"
	A256GCM Enc = "A256GCM"
)

// Zip identifies a JWE compression algorithm this package supports.
type Zip string

// DEF is raw DEFLATE (RFC 1951, no zlib/gzip wrapper) — RFC 7516's
// only registered "zip" value.
const DEF Zip = "DEF"

var b64 = base64.RawURLEncoding

const (
	gcmIVSize  = 12 // RFC 7518 §5.3: a 96-bit IV.
	gcmTagSize = 16 // RFC 7518 §5.3: a full 128-bit authentication tag.
)

func encKeyLen(enc Enc) (int, error) {
	switch enc {
	case A128GCM:
		return 16, nil
	case A192GCM:
		return 24, nil
	case A256GCM:
		return 32, nil
	default:
		return 0, fmt.Errorf("jwe: unsupported enc %q", enc)
	}
}

// EncryptOptions configures Encrypt.
type EncryptOptions struct {
	// Zip, when set, compresses the payload (RFC 7516's own "zip")
	// before encryption. Only DEF is supported.
	Zip Zip

	// KeyID, when set, is echoed into the JWE header's own "kid" — the
	// recipient public key's own key ID, per OID4VCI 1.0 §10's "If the
	// selected public key contains a kid parameter, the JWE MUST
	// include the same value in the kid JWE Header Parameter."
	KeyID string
}

// Encrypt encrypts payload for recipientPub — a P-256 EC public key —
// using ECDH-ES key agreement (RFC 7518 §4.6) with a fresh ephemeral
// key pair, and enc content encryption (RFC 7518 §5.3), producing JWE
// Compact Serialization (RFC 7516 §7.1):
// header.<empty>.iv.ciphertext.tag — the second segment (JWE Encrypted
// Key) is always empty, since ECDH-ES Direct Key Agreement derives the
// content encryption key itself rather than wrapping one.
func Encrypt(recipientPub *ecdsa.PublicKey, enc Enc, payload []byte, opts EncryptOptions) (string, error) {
	keyLen, err := encKeyLen(enc)
	if err != nil {
		return "", err
	}
	if opts.Zip != "" && opts.Zip != DEF {
		return "", fmt.Errorf("jwe: unsupported zip %q", opts.Zip)
	}

	recipientECDH, err := recipientPub.ECDH()
	if err != nil {
		return "", fmt.Errorf("jwe: recipient public key: %w", err)
	}
	ephemeralPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("jwe: generate ephemeral key: %w", err)
	}
	z, err := ephemeralPriv.ECDH(recipientECDH)
	if err != nil {
		return "", fmt.Errorf("jwe: ecdh: %w", err)
	}
	cek, err := concatKDF(z, string(enc), nil, nil, keyLen)
	if err != nil {
		return "", err
	}

	header := map[string]any{
		"alg": string(ECDHES),
		"enc": string(enc),
		"epk": jwkFromECDHPublicKey(ephemeralPriv.PublicKey()),
	}
	if opts.KeyID != "" {
		header["kid"] = opts.KeyID
	}
	if opts.Zip != "" {
		header["zip"] = string(opts.Zip)
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("jwe: marshal header: %w", err)
	}
	encHeader := b64.EncodeToString(headerJSON)

	plaintext := payload
	if opts.Zip == DEF {
		plaintext, err = deflate(payload)
		if err != nil {
			return "", err
		}
	}

	gcm, err := newGCM(cek)
	if err != nil {
		return "", err
	}
	iv := make([]byte, gcmIVSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("jwe: generate iv: %w", err)
	}
	sealed := gcm.Seal(nil, iv, plaintext, []byte(encHeader))
	ciphertext, tag := sealed[:len(sealed)-gcmTagSize], sealed[len(sealed)-gcmTagSize:]

	return strings.Join([]string{
		encHeader,
		"",
		b64.EncodeToString(iv),
		b64.EncodeToString(ciphertext),
		b64.EncodeToString(tag),
	}, "."), nil
}

// Decrypt decrypts a JWE Compact Serialization produced by Encrypt
// (ECDH-ES + AES-GCM only — see the package doc comment), using priv,
// the recipient's own P-256 private key, to redo the ECDH-ES key
// agreement against the sender's ephemeral public key conveyed in the
// header's own "epk".
func Decrypt(priv *ecdsa.PrivateKey, compact string) ([]byte, error) {
	header, encHeader, ivB64, ctB64, tagB64, err := splitCompact(compact)
	if err != nil {
		return nil, err
	}

	if algStr, _ := header["alg"].(string); algStr != string(ECDHES) {
		return nil, fmt.Errorf("jwe: unsupported alg %q", header["alg"])
	}
	encStr, _ := header["enc"].(string)
	keyLen, err := encKeyLen(Enc(encStr))
	if err != nil {
		return nil, err
	}

	senderPub, err := decodeEPK(header)
	if err != nil {
		return nil, err
	}
	apu, err := decodePartyInfo(header, "apu")
	if err != nil {
		return nil, err
	}
	apv, err := decodePartyInfo(header, "apv")
	if err != nil {
		return nil, err
	}
	privECDH, err := priv.ECDH()
	if err != nil {
		return nil, fmt.Errorf("jwe: recipient private key: %w", err)
	}
	z, err := privECDH.ECDH(senderPub)
	if err != nil {
		return nil, fmt.Errorf("jwe: ecdh: %w", err)
	}
	cek, err := concatKDF(z, encStr, apu, apv, keyLen)
	if err != nil {
		return nil, err
	}

	iv, err := b64.DecodeString(ivB64)
	if err != nil {
		return nil, fmt.Errorf("jwe: decode iv: %w", err)
	}
	if len(iv) != gcmIVSize {
		return nil, fmt.Errorf("jwe: iv has unexpected length %d, want %d", len(iv), gcmIVSize)
	}
	ciphertext, err := b64.DecodeString(ctB64)
	if err != nil {
		return nil, fmt.Errorf("jwe: decode ciphertext: %w", err)
	}
	tag, err := b64.DecodeString(tagB64)
	if err != nil {
		return nil, fmt.Errorf("jwe: decode tag: %w", err)
	}
	if len(tag) != gcmTagSize {
		return nil, fmt.Errorf("jwe: tag has unexpected length %d, want %d", len(tag), gcmTagSize)
	}

	gcm, err := newGCM(cek)
	if err != nil {
		return nil, err
	}
	sealed := make([]byte, 0, len(ciphertext)+len(tag))
	sealed = append(sealed, ciphertext...)
	sealed = append(sealed, tag...)
	plaintext, err := gcm.Open(nil, iv, sealed, []byte(encHeader))
	if err != nil {
		return nil, fmt.Errorf("jwe: decrypt: %w", err)
	}

	if zipStr, _ := header["zip"].(string); zipStr != "" {
		if zipStr != string(DEF) {
			return nil, fmt.Errorf("jwe: unsupported zip %q", zipStr)
		}
		plaintext, err = inflate(plaintext)
		if err != nil {
			return nil, err
		}
	}
	return plaintext, nil
}

// DecodeHeader decodes a JWE Compact Serialization's own header
// without decrypting anything — for a caller that needs to read "kid"
// to resolve which private key to decrypt with before calling Decrypt.
func DecodeHeader(compact string) (map[string]any, error) {
	header, _, _, _, _, err := splitCompact(compact)
	return header, err
}

func splitCompact(compact string) (header map[string]any, encHeader, iv, ciphertext, tag string, err error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 5 {
		return nil, "", "", "", "", fmt.Errorf("jwe: not a compact JWE (expected 5 parts, got %d)", len(parts))
	}
	if parts[1] != "" {
		return nil, "", "", "", "", fmt.Errorf("jwe: encrypted key segment must be empty for ECDH-ES direct key agreement")
	}
	raw, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, "", "", "", "", fmt.Errorf("jwe: decode header: %w", err)
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return nil, "", "", "", "", fmt.Errorf("jwe: unmarshal header: %w", err)
	}
	return header, parts[0], parts[2], parts[3], parts[4], nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("jwe: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("jwe: new gcm: %w", err)
	}
	return gcm, nil
}

// jwkFromECDHPublicKey encodes pub (a P-256 point) the same way
// internal/jwk.Marshal encodes a *ecdsa.PublicKey — the wire format is
// identical, only the Go type differs, so this stays local to jwe
// rather than teaching internal/jwk about crypto/ecdh.
func jwkFromECDHPublicKey(pub *ecdh.PublicKey) jwk.JWK {
	raw := pub.Bytes() // SEC1 uncompressed: 0x04 || X || Y.
	size := (len(raw) - 1) / 2
	return jwk.JWK{Kty: "EC", Crv: "P-256", X: b64.EncodeToString(raw[1 : 1+size]), Y: b64.EncodeToString(raw[1+size:])}
}

// decodeEPK extracts and decodes header's own "epk" member into a
// P-256 ECDH public key.
func decodeEPK(header map[string]any) (*ecdh.PublicKey, error) {
	epkVal, ok := header["epk"]
	if !ok {
		return nil, fmt.Errorf("jwe: header is missing epk")
	}
	epkJSON, err := json.Marshal(epkVal)
	if err != nil {
		return nil, fmt.Errorf("jwe: marshal epk: %w", err)
	}
	var epk jwk.JWK
	if err := json.Unmarshal(epkJSON, &epk); err != nil {
		return nil, fmt.Errorf("jwe: unmarshal epk: %w", err)
	}
	if epk.Kty != "EC" || epk.Crv != "P-256" {
		return nil, fmt.Errorf("jwe: epk has unsupported kty/crv (%q/%q); only EC P-256 is supported", epk.Kty, epk.Crv)
	}
	x, err := b64.DecodeString(epk.X)
	if err != nil {
		return nil, fmt.Errorf("jwe: epk: decode x: %w", err)
	}
	y, err := b64.DecodeString(epk.Y)
	if err != nil {
		return nil, fmt.Errorf("jwe: epk: decode y: %w", err)
	}
	if len(x) != 32 || len(y) != 32 {
		return nil, fmt.Errorf("jwe: epk has an EC coordinate of unexpected length")
	}
	uncompressed := make([]byte, 0, 65)
	uncompressed = append(uncompressed, 0x04)
	uncompressed = append(uncompressed, x...)
	uncompressed = append(uncompressed, y...)
	pub, err := ecdh.P256().NewPublicKey(uncompressed)
	if err != nil {
		return nil, fmt.Errorf("jwe: epk: %w", err)
	}
	return pub, nil
}

// decodePartyInfo reads header's own "apu" or "apv" member (RFC 7518
// §4.6.1.2/§4.6.1.3: base64url-encoded PartyUInfo/PartyVInfo octets)
// — nil, nil when the member is absent entirely (both are OPTIONAL),
// matching concatKDF's own "nil means absent" contract.
func decodePartyInfo(header map[string]any, member string) ([]byte, error) {
	raw, ok := header[member]
	if !ok {
		return nil, nil
	}
	s, ok := raw.(string)
	if !ok {
		return nil, fmt.Errorf("jwe: header %q is not a string", member)
	}
	decoded, err := b64.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("jwe: decode %s: %w", member, err)
	}
	return decoded, nil
}

func deflate(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return nil, fmt.Errorf("jwe: compress: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return nil, fmt.Errorf("jwe: compress: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("jwe: compress: %w", err)
	}
	return buf.Bytes(), nil
}

func inflate(data []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(data))
	defer func() { _ = r.Close() }()
	out, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("jwe: decompress: %w", err)
	}
	return out, nil
}
