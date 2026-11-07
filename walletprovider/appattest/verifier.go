package appattest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"slices"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/internal/strictcbor"
)

// Bounds on what Verify parses.
const (
	// MaxAttestationBytes bounds an attestation object. Apple's are
	// about 5 KiB, most of it the receipt.
	MaxAttestationBytes = 32 << 10
	// MaxAssertionBytes bounds an assertion. Apple's are about 120
	// bytes.
	MaxAssertionBytes = 1 << 10
	// MaxChainLength is the most certificates an attestation's x5c may
	// hold. Apple's hold two: the credential certificate and its
	// intermediate.
	MaxChainLength = 4
)

// NonceExtensionOID is the credential certificate's extension carrying
// the attestation's nonce.
var NonceExtensionOID = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}

// Environment is the App Attest environment an attestation is from.
type Environment string

const (
	// EnvironmentProduction: an app signed for distribution (App Store,
	// TestFlight, enterprise), or with the
	// com.apple.developer.devicecheck.appattest-environment entitlement
	// set to production.
	EnvironmentProduction Environment = "production"
	// EnvironmentDevelopment: an app built for development, with the
	// entitlement set to development. The key is still the Secure
	// Enclave's, attested by Apple; Apple only keeps the two
	// environments' keys apart, so a development build's attestations
	// can't pass for a released app's.
	EnvironmentDevelopment Environment = "development"
)

// The authenticator data's AAGUIDs (16 bytes) for each environment.
var (
	aaguidProduction  = append([]byte("appattest"), make([]byte, 7)...)
	aaguidDevelopment = []byte("appattestdevelop")
)

// Verifier checks Apple App Attest attestation objects and assertions,
// following Apple's "Validating apps that connect to your server". Its
// zero-valued fields are the strict choice.
type Verifier struct {
	// Apps are the App IDs accepted: an app's team ID and bundle ID,
	// "ABCDE12345.com.example.wallet". REQUIRED.
	Apps []string

	// AllowDevelopment accepts attestations from App Attest's
	// development environment as well as production. A development
	// build's key is a Secure Enclave key Apple attested all the same;
	// leave this unset in production so only a released build
	// registers.
	AllowDevelopment bool

	// Roots are the trust anchors; nil means AppleRoots().
	Roots []*x509.Certificate

	// Now is the clock certificate validity is judged by; nil means
	// time.Now.
	Now func() time.Time
}

// Attestation is a verified attestation object: an App Attest key a
// genuine copy of one of the Verifier's apps made on an Apple device.
type Attestation struct {
	// PublicKey is the attested P-256 key, which signs the app's
	// assertions. Keep it for VerifyAssertion.
	PublicKey *ecdsa.PublicKey
	// KeyID is the key's identifier, SHA-256 of its uncompressed point:
	// the keyId the app's DCAppAttestService has for it, base64.
	KeyID []byte
	// AppID is the app's App ID, one of Verifier.Apps.
	AppID string
	// Environment is the App Attest environment of the key.
	Environment Environment
	// Chain is the attestation's certificates, the credential
	// certificate first.
	Chain []*x509.Certificate
	// Receipt is the attestation's receipt, unchecked: what an app
	// exchanges with Apple for a fraud metric. Verifying it isn't part
	// of verifying the attestation.
	Receipt []byte
}

// Assertion is a verified assertion.
type Assertion struct {
	// AppID is the app's App ID, one of Verifier.Apps.
	AppID string
	// Counter is the assertion's counter: store it, and accept only a
	// later assertion with a larger one.
	Counter uint32
}

// attestationObject is the CBOR attestation object attestKey returns.
type attestationObject struct {
	Fmt      string  `cbor:"fmt"`
	AttStmt  attStmt `cbor:"attStmt"`
	AuthData []byte  `cbor:"authData"`
}

type attStmt struct {
	X5C     [][]byte `cbor:"x5c"`
	Receipt []byte   `cbor:"receipt"`
}

// assertionObject is the CBOR assertion generateAssertion returns.
type assertionObject struct {
	Signature         []byte `cbor:"signature"`
	AuthenticatorData []byte `cbor:"authenticatorData"`
}

// authData is the parsed authenticator data.
type authData struct {
	rpIDHash []byte
	counter  uint32
	// aaguid and credentialID, from the attested credential data
	// (attestations only).
	aaguid       []byte
	credentialID []byte
}

// The authenticator data's fixed part: rpIdHash (32), flags (1) and
// signCount (4); then, when flagAttestedCredential is set, the AAGUID
// (16), the credential ID's length (2) and the credential ID.
const (
	authDataMinBytes       = 37
	flagAttestedCredential = 0x40
)

var decMode = func() strictcbor.DecMode {
	mode, err := cbor.DecOptions{
		// The decoder's smallest bounds: decodeAttestation bounds x5c
		// itself.
		MaxNestedLevels:   4,
		MaxArrayElements:  16,
		MaxMapPairs:       16,
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		FieldNameMatching: cbor.FieldNameMatchingCaseSensitive,
	}.DecMode()
	if err != nil {
		panic("appattest: build CBOR decoder: " + err.Error())
	}
	return strictcbor.Wrap(mode)
}()

// VerifyAttestation checks attestationObject, as attestKey returned it,
// as an attestation over clientDataHash (ClientDataHash), and returns
// the key it attests. It checks, refusing with an error wrapping one of
// this package's Err values:
//
//   - the format, "apple-appattest", and the shape: at most
//     MaxAttestationBytes, and x5c of two to MaxChainLength
//     certificates;
//   - the certificates: the credential certificate chains through the
//     rest to one of Roots, every certificate valid at Now;
//   - the nonce: the credential certificate's NonceExtensionOID
//     extension holds SHA-256(authData ‖ clientDataHash);
//   - the key: the credential certificate's P-256 key, whose SHA-256 of
//     its uncompressed point is the authenticator data's credential ID;
//   - the app: the authenticator data's RP ID hash is the SHA-256 of
//     one of Apps;
//   - the counter, zero, and the AAGUID, production's, or
//     development's when AllowDevelopment is set.
func (v *Verifier) VerifyAttestation(attestationObject, clientDataHash []byte) (*Attestation, error) {
	if err := v.checkConfig(clientDataHash); err != nil {
		return nil, err
	}
	if len(attestationObject) == 0 || len(attestationObject) > MaxAttestationBytes {
		return nil, fail(ErrMalformed, "a %d-byte attestation object, want 1 to %d", len(attestationObject), MaxAttestationBytes)
	}
	obj, err := decodeAttestation(attestationObject)
	if err != nil {
		return nil, err
	}
	chain, err := v.verifyChain(obj.AttStmt.X5C)
	if err != nil {
		return nil, err
	}
	ad, err := parseAuthData(obj.AuthData, true)
	if err != nil {
		return nil, err
	}
	if err := checkNonce(chain[0], obj.AuthData, clientDataHash); err != nil {
		return nil, err
	}
	pub, ok := chain[0].PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, fail(ErrMalformed, "the credential certificate's key is a %T, not P-256", chain[0].PublicKey)
	}
	keyID := KeyID(pub)
	if subtle.ConstantTimeCompare(keyID, ad.credentialID) != 1 {
		return nil, fail(ErrKeyID, "the credential ID isn't the SHA-256 of the credential certificate's key")
	}
	app, err := v.appFor(ad.rpIDHash)
	if err != nil {
		return nil, err
	}
	if ad.counter != 0 {
		return nil, fail(ErrCounter, "an attestation's counter is %d, want 0", ad.counter)
	}
	env, err := v.environment(ad.aaguid)
	if err != nil {
		return nil, err
	}
	return &Attestation{
		PublicKey: pub, KeyID: keyID, AppID: app, Environment: env, Chain: chain,
		Receipt: slices.Clone(obj.AttStmt.Receipt),
	}, nil
}

// VerifyAssertion checks assertion, as generateAssertion returned it,
// as an assertion over clientDataHash by pub, an App Attest key a
// verified attestation returned, with a counter larger than
// lastCounter. It checks, refusing with an error wrapping one of this
// package's Err values: the shape (at most MaxAssertionBytes); the
// signature, ECDSA with SHA-256 by pub over the nonce
// SHA-256(authenticatorData ‖ clientDataHash); the RP ID hash, the
// SHA-256 of one of Apps; and the counter. It returns the App ID and
// the new counter.
func (v *Verifier) VerifyAssertion(assertion, clientDataHash []byte, pub *ecdsa.PublicKey, lastCounter uint32) (*Assertion, error) {
	if err := v.checkConfig(clientDataHash); err != nil {
		return nil, err
	}
	if pub == nil || pub.Curve != elliptic.P256() {
		return nil, fail(ErrConfig, "an assertion needs the attested P-256 key")
	}
	if len(assertion) == 0 || len(assertion) > MaxAssertionBytes {
		return nil, fail(ErrMalformed, "a %d-byte assertion, want 1 to %d", len(assertion), MaxAssertionBytes)
	}
	var obj assertionObject
	if err := decMode.Unmarshal(assertion, &obj); err != nil {
		return nil, fail(ErrMalformed, "assertion: %v", err)
	}
	if len(obj.Signature) == 0 {
		return nil, fail(ErrMalformed, "the assertion has no signature")
	}
	ad, err := parseAuthData(obj.AuthenticatorData, false)
	if err != nil {
		return nil, err
	}
	nonce := sha256.Sum256(slices.Concat(obj.AuthenticatorData, clientDataHash))
	digest := sha256.Sum256(nonce[:])
	if !ecdsa.VerifyASN1(pub, digest[:], obj.Signature) {
		return nil, fail(ErrSignature, "the signature doesn't verify over the expected client data")
	}
	app, err := v.appFor(ad.rpIDHash)
	if err != nil {
		return nil, err
	}
	if ad.counter <= lastCounter {
		return nil, fail(ErrCounter, "the assertion's counter %d doesn't exceed %d", ad.counter, lastCounter)
	}
	return &Assertion{AppID: app, Counter: ad.counter}, nil
}

// KeyID is an App Attest key's identifier: the SHA-256 of its
// uncompressed point (0x04 ‖ X ‖ Y).
func KeyID(pub *ecdsa.PublicKey) []byte {
	point, err := pub.Bytes()
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(point)
	return sum[:]
}

func (v *Verifier) checkConfig(clientDataHash []byte) error {
	if len(clientDataHash) != sha256.Size {
		return fail(ErrConfig, "a %d-byte client data hash, want %d", len(clientDataHash), sha256.Size)
	}
	if len(v.Apps) == 0 {
		return fail(ErrConfig, "no allowed apps")
	}
	for _, app := range v.Apps {
		team, bundle, ok := strings.Cut(app, ".")
		if !ok || team == "" || bundle == "" {
			return fail(ErrConfig, "allowed app %q isn't a team ID and a bundle ID", app)
		}
	}
	return nil
}

func decodeAttestation(raw []byte) (attestationObject, error) {
	var obj attestationObject
	if err := decMode.Unmarshal(raw, &obj); err != nil {
		return obj, fail(ErrMalformed, "attestation object: %v", err)
	}
	switch {
	case obj.Fmt != "apple-appattest":
		return obj, fail(ErrMalformed, "format %q, want apple-appattest", obj.Fmt)
	case len(obj.AttStmt.X5C) < 2 || len(obj.AttStmt.X5C) > MaxChainLength:
		return obj, fail(ErrMalformed, "x5c holds %d certificates, want 2 to %d", len(obj.AttStmt.X5C), MaxChainLength)
	}
	return obj, nil
}

// verifyChain parses der, the credential certificate first, and checks
// it chains through the rest to a root, valid now.
func (v *Verifier) verifyChain(der [][]byte) ([]*x509.Certificate, error) {
	chain := make([]*x509.Certificate, len(der))
	for i, d := range der {
		c, err := x509.ParseCertificate(d)
		if err != nil {
			return nil, fail(ErrMalformed, "certificate %d: %v", i, err)
		}
		chain[i] = c
	}
	roots := x509.NewCertPool()
	for _, r := range v.roots() {
		roots.AddCert(r)
	}
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, CurrentTime: v.now(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fail(ErrUntrustedRoot, "%v", err)
	}
	return chain, nil
}

// checkNonce checks the credential certificate's nonce extension, a
// SEQUENCE holding one [1] EXPLICIT OCTET STRING, is
// SHA-256(authData ‖ clientDataHash). No other certificate may carry
// one.
func checkNonce(cred *x509.Certificate, authData, clientDataHash []byte) error {
	var ext []byte
	for _, e := range cred.Extensions {
		if e.Id.Equal(NonceExtensionOID) {
			if ext != nil {
				return fail(ErrMalformed, "the credential certificate has two nonce extensions")
			}
			ext = e.Value
		}
	}
	if ext == nil {
		return fail(ErrMalformed, "the credential certificate has no nonce extension")
	}
	var seq struct {
		Nonce []byte `asn1:"tag:1,explicit"`
	}
	rest, err := asn1.Unmarshal(ext, &seq)
	if err != nil || len(rest) != 0 {
		return fail(ErrMalformed, "the nonce extension doesn't parse")
	}
	want := sha256.Sum256(slices.Concat(authData, clientDataHash))
	if subtle.ConstantTimeCompare(seq.Nonce, want[:]) != 1 {
		return fail(ErrNonce, "the attestation was made over other client data")
	}
	return nil
}

// parseAuthData parses authenticator data; attested, it requires the
// attested credential data an attestation's carries.
func parseAuthData(b []byte, attested bool) (authData, error) {
	if len(b) < authDataMinBytes {
		return authData{}, fail(ErrMalformed, "%d bytes of authenticator data, want at least %d", len(b), authDataMinBytes)
	}
	ad := authData{rpIDHash: b[:32], counter: binary.BigEndian.Uint32(b[33:37])}
	if !attested {
		return ad, nil
	}
	rest := b[authDataMinBytes:]
	if b[32]&flagAttestedCredential == 0 || len(rest) < 18 {
		return authData{}, fail(ErrMalformed, "the authenticator data has no attested credential data")
	}
	ad.aaguid = rest[:16]
	n := int(binary.BigEndian.Uint16(rest[16:18]))
	if len(rest) < 18+n {
		return authData{}, fail(ErrMalformed, "a %d-byte credential ID in %d bytes", n, len(rest)-18)
	}
	ad.credentialID = rest[18 : 18+n]
	return ad, nil
}

// appFor returns the App ID whose SHA-256 is rpIDHash.
func (v *Verifier) appFor(rpIDHash []byte) (string, error) {
	for _, app := range v.Apps {
		sum := sha256.Sum256([]byte(app))
		if subtle.ConstantTimeCompare(sum[:], rpIDHash) == 1 {
			return app, nil
		}
	}
	return "", fail(ErrAppNotAllowed, "the RP ID hash is none of the %d allowed apps'", len(v.Apps))
}

func (v *Verifier) environment(aaguid []byte) (Environment, error) {
	switch {
	case bytes.Equal(aaguid, aaguidProduction):
		return EnvironmentProduction, nil
	case bytes.Equal(aaguid, aaguidDevelopment):
		if !v.AllowDevelopment {
			return "", fail(ErrEnvironment, "a development environment key, and AllowDevelopment isn't set")
		}
		return EnvironmentDevelopment, nil
	}
	return "", fail(ErrEnvironment, "AAGUID %x is neither environment's", aaguid)
}

func (v *Verifier) roots() []*x509.Certificate {
	if v.Roots != nil {
		return v.Roots
	}
	return appleRoots()
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}
