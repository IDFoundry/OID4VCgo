package androidkey

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Bounds on the chain Verify takes.
const (
	// MaxChainLength is the most certificates in a chain. Android's
	// have three to five.
	MaxChainLength = 10
	// MaxCertificateBytes bounds one DER certificate.
	MaxCertificateBytes = 16 << 10
	// maxRSABits is the largest RSA key a chain may hold: Google's RSA
	// root is 4096 bits, and a check with a larger key costs far more.
	maxRSABits = 4096
)

// DefaultMinAttestationVersion is the oldest attestation version a
// Verifier takes unless MinAttestationVersion says otherwise: 3,
// Keymaster 4.0 (Android 9), the first with the verified boot hash.
const DefaultMinAttestationVersion = 3

// AllowedApp is an app a Verifier accepts keys from: an Android package
// name and the SHA-256 digests of the certificates it's signed with.
type AllowedApp struct {
	// Package is the application ID, e.g. "com.example.wallet".
	Package string
	// SigningCertificateDigests are SHA-256 digests (32 bytes each) of
	// the app's signing certificates; more than one across a signing
	// key rotation. Every digest the attestation names must be here.
	SigningCertificateDigests [][]byte
	// MinVersion, if set, is the oldest versionCode accepted.
	MinVersion int64
}

// Verifier checks Android Key Attestation certificate chains: the chain
// Android Keystore returns (KeyStore.getCertificateChain) for a key
// generated with an attestation challenge. Its zero-valued policy
// fields are the strict choice; each relaxation is a field to set.
type Verifier struct {
	// Roots are the trust anchors; nil means GoogleRoots(). A chain is
	// anchored when its last certificate has the public key of one of
	// them (it is that root, or a re-issue of it) or is signed by one.
	Roots []*x509.Certificate

	// Revocation provides Google's attestation status list; every
	// certificate in the chain is looked up in it. Required unless
	// RevocationOptional is set.
	Revocation StatusProvider
	// RevocationOptional verifies a chain without a status list when
	// Revocation is nil or has no current list, reporting it in
	// Result.RevocationChecked. Unset, Verify refuses such a chain with
	// ErrStatusUnavailable (or ErrConfig, for a nil Revocation).
	RevocationOptional bool

	// Apps are the apps whose keys are accepted; required.
	Apps []AllowedApp

	// AllowSoftware accepts a key or an attestation at the Software
	// level. Unset, both must be in the TEE or StrongBox.
	AllowSoftware bool
	// RequireStrongBox accepts only StrongBox keys and attestations.
	RequireStrongBox bool

	// AllowUntrustedBoot accepts a device whose bootloader is unlocked,
	// or whose boot wasn't verified, or a chain without a root of
	// trust. Unset, the device must be locked and its boot Verified
	// (or SelfSigned with one of TrustedBootKeys).
	AllowUntrustedBoot bool
	// TrustedBootKeys are verified boot keys accepted for a SelfSigned
	// boot state: an alternative OS whose signing key the provider
	// trusts.
	TrustedBootKeys [][]byte

	// MinAttestationVersion is the oldest attestation version accepted;
	// zero means DefaultMinAttestationVersion.
	MinAttestationVersion int
	// MinOSPatchLevel, if set, is the oldest OS patch level accepted,
	// as YYYYMM (e.g. 202501).
	MinOSPatchLevel int64
	// Curves are the elliptic curves an attested key may use; nil means
	// P-256 only.
	Curves []ECCurve

	// Now is the clock certificate validity is judged by; nil means
	// time.Now.
	Now func() time.Time
}

// Result is a verified attestation: what a Wallet Provider decides on.
type Result struct {
	// PublicKey is the attested key, the leaf certificate's: bind it to
	// the key the wallet presented.
	PublicKey crypto.PublicKey
	// Chain is the parsed chain, leaf first.
	Chain []*x509.Certificate
	// Root is the configured root the chain is anchored at.
	Root *x509.Certificate
	// KeyDescription is the leaf's attestation extension, with both
	// authorization lists and both security levels.
	KeyDescription *KeyDescription
	// Enforced is the authorization list the checks were made on: the
	// hardware-enforced one for a key in the TEE or StrongBox, the
	// software-enforced one otherwise. Its user authentication fields
	// (NoAuthRequired, UserAuthType, AuthTimeout,
	// UnlockedDeviceRequired, TrustedUserPresenceRequired) say how the
	// key's use is gated.
	Enforced *AuthorizationList
	// App is the attesting app's identity, as Keystore reported it.
	App *ApplicationID
	// RevocationChecked reports whether every certificate was looked up
	// in a current status list (always, unless RevocationOptional).
	RevocationChecked bool
}

// StrongBox reports whether both the key and its attestation are in
// StrongBox.
func (r *Result) StrongBox() bool {
	return r.KeyDescription.KeyMintSecurityLevel == StrongBox && r.KeyDescription.AttestationSecurityLevel == StrongBox
}

// Verify checks chain, DER certificates leaf first as Keystore returns
// them, as an attestation over challenge, and returns what it attests.
// Every check that fails is an error wrapping one of this package's
// Err values; a nil error means every one passed.
func (v *Verifier) Verify(ctx context.Context, chain [][]byte, challenge []byte) (*Result, error) {
	if err := v.checkConfig(challenge); err != nil {
		return nil, err
	}
	certs, err := parseChain(chain)
	if err != nil {
		return nil, err
	}
	root, err := v.anchor(certs)
	if err != nil {
		return nil, err
	}
	kd, err := keyDescriptionOf(certs)
	if err != nil {
		return nil, err
	}
	r := &Result{PublicKey: certs[0].PublicKey, Chain: certs, Root: root, KeyDescription: kd}
	for _, check := range []func(*Result) error{
		func(*Result) error { return checkChallenge(kd, challenge) },
		v.checkLevels,
		v.checkKey,
		v.checkBoot,
		v.checkApp,
	} {
		if err := check(r); err != nil {
			return nil, err
		}
	}
	if err := v.checkRevocation(ctx, r); err != nil {
		return nil, err
	}
	return r, nil
}

func (v *Verifier) checkConfig(challenge []byte) error {
	switch {
	case len(challenge) == 0 || len(challenge) > MaxChallengeBytes:
		return fail(ErrConfig, "a %d-byte challenge, want 1 to %d", len(challenge), MaxChallengeBytes)
	case len(v.Apps) == 0:
		return fail(ErrConfig, "no allowed apps")
	case v.Revocation == nil && !v.RevocationOptional:
		return fail(ErrConfig, "no Revocation status provider, and RevocationOptional isn't set")
	}
	for _, app := range v.Apps {
		if app.Package == "" || len(app.SigningCertificateDigests) == 0 {
			return fail(ErrConfig, "allowed app %q needs a package and signing certificate digests", app.Package)
		}
		for _, d := range app.SigningCertificateDigests {
			if len(d) != sha256.Size {
				return fail(ErrConfig, "allowed app %q has a %d-byte signing certificate digest, want SHA-256", app.Package, len(d))
			}
		}
	}
	return nil
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// parseChain parses and bounds the chain and checks each certificate
// is signed by the next.
func parseChain(chain [][]byte) ([]*x509.Certificate, error) {
	if len(chain) == 0 || len(chain) > MaxChainLength {
		return nil, fail(ErrMalformed, "a chain of %d certificates, want 1 to %d", len(chain), MaxChainLength)
	}
	certs := make([]*x509.Certificate, len(chain))
	for i, der := range chain {
		if len(der) > MaxCertificateBytes {
			return nil, fail(ErrMalformed, "certificate %d is %d bytes, more than %d", i, len(der), MaxCertificateBytes)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fail(ErrMalformed, "certificate %d: %v", i, err)
		}
		if err := boundedKey(c.PublicKey); err != nil {
			return nil, fail(ErrMalformed, "certificate %d: %v", i, err)
		}
		certs[i] = c
	}
	for i := 1; i < len(certs); i++ {
		// CheckSignature, not CheckSignatureFrom: Android's attestation
		// keys aren't always marked as CAs.
		if err := signedBy(certs[i-1], certs[i]); err != nil {
			return nil, fail(ErrChainSignature, "certificate %d isn't signed by certificate %d: %v", i-1, i, err)
		}
	}
	return certs, nil
}

func signedBy(c, parent *x509.Certificate) error {
	return parent.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature)
}

// boundedKey refuses an RSA key a signature check would be slow with,
// before any is made.
func boundedKey(pub any) error {
	if k, ok := pub.(*rsa.PublicKey); ok && (k.N.BitLen() > maxRSABits || k.E != 65537) {
		return fmt.Errorf("an RSA key of %d bits with exponent %d; want at most %d bits, and 65537", k.N.BitLen(), k.E, maxRSABits)
	}
	return nil
}

// anchor finds the root the chain ends at and checks every certificate
// is valid now. A certificate with a root's key is judged by the
// configured root's validity, not its own: Google's 2016 root
// certificate has expired, while its key lives on in the 2022 one.
func (v *Verifier) anchor(certs []*x509.Certificate) (*x509.Certificate, error) {
	roots := v.Roots
	if roots == nil {
		roots = googleRoots()
	}
	top := certs[len(certs)-1]
	root := rootWithKey(top, roots)
	if root == nil {
		root = rootSigning(top, roots)
	}
	if root == nil {
		return nil, fail(ErrUntrustedRoot, "the chain ends at %q", top.Subject.String())
	}
	now := v.now()
	if !within(root, now) {
		return nil, fail(ErrCertificateValidity, "root %q isn't valid at %s", root.Subject.String(), now.UTC().Format(time.RFC3339))
	}
	for i, c := range certs {
		if !within(c, now) && !bytes.Equal(c.RawSubjectPublicKeyInfo, root.RawSubjectPublicKeyInfo) {
			return nil, fail(ErrCertificateValidity, "certificate %d is valid from %s to %s, not at %s", i,
				c.NotBefore.UTC().Format(time.RFC3339), c.NotAfter.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
		}
	}
	return root, nil
}

func within(c *x509.Certificate, t time.Time) bool {
	return !t.Before(c.NotBefore) && !t.After(c.NotAfter)
}

func rootWithKey(c *x509.Certificate, roots []*x509.Certificate) *x509.Certificate {
	for _, r := range roots {
		if bytes.Equal(c.RawSubjectPublicKeyInfo, r.RawSubjectPublicKeyInfo) {
			return r
		}
	}
	return nil
}

func rootSigning(c *x509.Certificate, roots []*x509.Certificate) *x509.Certificate {
	for _, r := range roots {
		if signedBy(c, r) == nil {
			return r
		}
	}
	return nil
}

// keyDescriptionOf parses the leaf's attestation extension. No other
// certificate may carry one: otherwise an attested key could sign a
// "leaf" of its own, for another key, claiming whatever it liked.
func keyDescriptionOf(certs []*x509.Certificate) (*KeyDescription, error) {
	var ext []byte
	for i, c := range certs {
		for _, e := range c.Extensions {
			if !e.Id.Equal(ExtensionOID) {
				continue
			}
			if i != 0 {
				return nil, fail(ErrMalformed, "certificate %d, not the leaf, has an attestation extension", i)
			}
			ext = e.Value
		}
	}
	if ext == nil {
		return nil, fail(ErrMalformed, "the leaf has no attestation extension")
	}
	return ParseKeyDescription(ext)
}

func checkChallenge(kd *KeyDescription, challenge []byte) error {
	if subtle.ConstantTimeCompare(kd.AttestationChallenge, challenge) != 1 {
		return fail(ErrChallenge, "the attestation was made over another challenge")
	}
	return nil
}

func (v *Verifier) checkLevels(r *Result) error {
	kd := r.KeyDescription
	minVersion := v.MinAttestationVersion
	if minVersion == 0 {
		minVersion = DefaultMinAttestationVersion
	}
	if kd.AttestationVersion < minVersion {
		return fail(ErrAttestationVersion, "version %d, want at least %d", kd.AttestationVersion, minVersion)
	}
	levels := "attestation " + kd.AttestationSecurityLevel.String() + ", key " + kd.KeyMintSecurityLevel.String()
	switch {
	case v.RequireStrongBox && !r.StrongBox():
		return fail(ErrSoftwareLevel, "%s; want StrongBox", levels)
	case !v.AllowSoftware && (!kd.AttestationSecurityLevel.Hardware() || !kd.KeyMintSecurityLevel.Hardware()):
		return fail(ErrSoftwareLevel, "%s; want the TEE or StrongBox", levels)
	}
	r.Enforced = &kd.SoftwareEnforced
	if kd.KeyMintSecurityLevel.Hardware() {
		r.Enforced = &kd.HardwareEnforced
	}
	return nil
}

// checkKey checks the attested key is a signing key generated in the
// secure hardware, on an allowed curve, and is the leaf's key.
func (v *Verifier) checkKey(r *Result) error {
	l := r.Enforced
	pub, ok := r.PublicKey.(*ecdsa.PublicKey)
	switch {
	case !l.HasPurpose(PurposeSign):
		return fail(ErrKeyProperties, "purposes %v don't include SIGN", l.Purposes)
	case l.Algorithm == nil || *l.Algorithm != AlgorithmEC:
		return fail(ErrKeyProperties, "not an EC key")
	case !ok:
		return fail(ErrKeyProperties, "the leaf's key is a %T, not ECDSA", r.PublicKey)
	// Keymaster 4 may leave the curve out, attesting only the key size.
	case l.ECCurve != nil && *l.ECCurve != curveOf(pub),
		l.KeySize != nil && *l.KeySize != int64(pub.Curve.Params().BitSize):
		return fail(ErrKeyProperties, "the attested curve or key size isn't the leaf key's")
	case l.Origin == nil || *l.Origin != OriginGenerated:
		return fail(ErrKeyProperties, "the key wasn't generated in the secure hardware")
	}
	curves := v.Curves
	if curves == nil {
		curves = []ECCurve{CurveP256}
	}
	if !slices.Contains(curves, curveOf(pub)) {
		return fail(ErrKeyProperties, "curve %s isn't allowed", pub.Curve.Params().Name)
	}
	return nil
}

func curveOf(pub *ecdsa.PublicKey) ECCurve {
	switch pub.Curve {
	case elliptic.P224():
		return CurveP224
	case elliptic.P256():
		return CurveP256
	case elliptic.P384():
		return CurveP384
	case elliptic.P521():
		return CurveP521
	}
	return curveUnknown
}

func (v *Verifier) checkBoot(r *Result) error {
	if !v.AllowUntrustedBoot {
		if err := v.trustedBoot(r.Enforced.RootOfTrust); err != nil {
			return err
		}
	}
	if v.MinOSPatchLevel > 0 {
		level := r.Enforced.OSPatchLevel
		if level == nil || *level < v.MinOSPatchLevel {
			return fail(ErrPatchLevel, "want at least %d", v.MinOSPatchLevel)
		}
	}
	return nil
}

func (v *Verifier) trustedBoot(rot *RootOfTrust) error {
	switch {
	case rot == nil:
		return fail(ErrBootState, "no root of trust")
	case !rot.DeviceLocked:
		return fail(ErrBootState, "the bootloader is unlocked")
	case rot.VerifiedBootState == Verified:
		return nil
	case rot.VerifiedBootState == SelfSigned && slices.ContainsFunc(v.TrustedBootKeys, func(k []byte) bool { return bytes.Equal(k, rot.VerifiedBootKey) }):
		return nil
	}
	return fail(ErrBootState, "verified boot state %s", rot.VerifiedBootState)
}

// checkApp checks every package Keystore names for the key is an
// allowed one, at an allowed version, and that every signing
// certificate digest is allowed for it.
func (v *Verifier) checkApp(r *Result) error {
	id := r.KeyDescription.HardwareEnforced.ApplicationID
	if id == nil {
		id = r.KeyDescription.SoftwareEnforced.ApplicationID
	}
	if id == nil || len(id.Packages) == 0 || len(id.SignatureDigests) == 0 {
		return fail(ErrAppNotAllowed, "no attestation application ID")
	}
	for _, p := range id.Packages {
		if !slices.ContainsFunc(v.Apps, func(a AllowedApp) bool { return a.allows(p, id.SignatureDigests) }) {
			return fail(ErrAppNotAllowed, "package %q, version %d, with its signing certificates, isn't allowed", p.Name, p.Version)
		}
	}
	r.App = id
	return nil
}

func (a AllowedApp) allows(p PackageInfo, digests [][]byte) bool {
	if a.Package != p.Name || p.Version < a.MinVersion {
		return false
	}
	for _, d := range digests {
		if !slices.ContainsFunc(a.SigningCertificateDigests, func(allowed []byte) bool { return bytes.Equal(allowed, d) }) {
			return false
		}
	}
	return true
}

func (v *Verifier) checkRevocation(ctx context.Context, r *Result) error {
	if v.Revocation == nil {
		return nil // RevocationOptional, as checkConfig ensured
	}
	list, err := v.Revocation.Current(ctx)
	if err != nil || list == nil {
		if v.RevocationOptional {
			return nil
		}
		if err == nil {
			return fail(ErrStatusUnavailable, "no status list")
		}
		if errors.Is(err, ErrStatusUnavailable) {
			return err
		}
		return fmt.Errorf("%w: %w", ErrStatusUnavailable, err)
	}
	for i, c := range r.Chain {
		if e, ok := list.Lookup(c.SerialNumber); ok {
			return &RevokedError{Position: i, Serial: serialKey(c.SerialNumber), Entry: e}
		}
	}
	r.RevocationChecked = true
	return nil
}
