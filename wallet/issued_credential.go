package wallet

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// VerifyIssuedCredentialParams is the input to VerifyIssuedCredential.
type VerifyIssuedCredentialParams struct {
	// Configuration is the Credential Configuration the Wallet
	// requested, from the Credential Issuer Metadata: its Format and,
	// per format, VCT ("dc+sd-jwt") or DocType ("mso_mdoc") are what
	// the credential must be. REQUIRED.
	Configuration oid4vci.CredentialConfigurationMetadata

	// Credential is one credential exactly as the Credential Response
	// returned it: a compact SD-JWT VC, or base64url-encoded mdoc
	// IssuerSigned. REQUIRED.
	Credential string

	// HolderKey is the public key the Wallet proved possession of in
	// its Credential Request. When set, the credential must be bound to
	// it (SD-JWT "cnf.jwk", mdoc DeviceKey). REQUIRED when Configuration
	// declares cryptographic binding methods.
	HolderKey crypto.PublicKey

	// IssuerRoots are the trust anchors for issuer certificates: the
	// credential's signing certificate (SD-JWT "x5c", mdoc "x5chain")
	// must chain to one of them and must not be self-signed (HAIP 1.0
	// §6.1.1). REQUIRED.
	IssuerRoots *x509.CertPool

	// Now is the time validity is checked at; zero means time.Now.
	Now time.Time
}

// VerifiedIssuedCredential is what VerifyIssuedCredential established.
type VerifiedIssuedCredential struct {
	// IssuerCertificate is the credential's signing certificate, which
	// chains to IssuerRoots.
	IssuerCertificate *x509.Certificate

	// Claims are the credential's claims: for "dc+sd-jwt" the Processed
	// SD-JWT Payload with every disclosure resolved; for "mso_mdoc"
	// namespace → element identifier → value.
	Claims map[string]any

	// ValidUntil is when the credential expires — an SD-JWT VC's "exp",
	// an mdoc's validityInfo.validUntil — or zero when it doesn't say.
	ValidUntil time.Time

	// StatusList is where the issuer publishes the credential's
	// revocation status (Token Status List), or nil when it has none;
	// StatusListCWT is whether that list is a CWT, as an mdoc's is.
	StatusList    *statuslist.StatusListRef
	StatusListCWT bool
}

// VerifyIssuedCredential checks a credential a Credential Issuer just
// returned, before the Wallet keeps it: that it is signed by a
// certificate chaining to IssuerRoots (HAIP 1.0 §6.1.1 has the Wallet,
// too, support X.509 issuer key resolution), that it is the requested
// type and currently valid, and that it is bound to the key the Wallet
// proved possession of. A Credential Offer's issuer is not trusted just
// because it sent the offer (OID4VCI 1.0 §13.5), so neither is what it
// issues.
// issuerClockSkew is how far the wallet's clock may be from the
// issuer's when it checks a credential's validity window on receipt: an
// issuer that makes a credential valid from the moment it signs it
// would otherwise have it refused by a wallet whose clock is a second
// behind.
const issuerClockSkew = time.Minute

func VerifyIssuedCredential(ctx context.Context, p VerifyIssuedCredentialParams) (VerifiedIssuedCredential, error) {
	if p.IssuerRoots == nil {
		return VerifiedIssuedCredential{}, errors.New("wallet: verify issued credential: IssuerRoots is required")
	}
	if p.HolderKey == nil && len(p.Configuration.CryptographicBindingMethodsSupported) > 0 {
		return VerifiedIssuedCredential{}, errors.New("wallet: verify issued credential: HolderKey is required for a credential with cryptographic binding")
	}
	now := p.Now
	if now.IsZero() {
		now = time.Now()
	}
	var verified VerifiedIssuedCredential
	var err error
	switch p.Configuration.Format {
	case sdjwtvc.CredentialFormat:
		verified, err = verifyIssuedSDJWTVC(p, now)
	case mdoc.CredentialFormat:
		verified, err = verifyIssuedMdoc(p, now)
	default:
		err = fmt.Errorf("unsupported format %q", p.Configuration.Format)
	}
	if err != nil {
		return VerifiedIssuedCredential{}, fmt.Errorf("wallet: verify issued credential: %w", err)
	}
	return verified, nil
}

func verifyIssuedSDJWTVC(p VerifyIssuedCredentialParams, now time.Time) (VerifiedIssuedCredential, error) {
	pres, err := sdjwtvc.Parse(p.Credential)
	if err != nil {
		return VerifiedIssuedCredential{}, fmt.Errorf("parse: %w", err)
	}
	header, _, err := jose.DecodeUnverified(pres.IssuerJWT)
	if err != nil {
		return VerifiedIssuedCredential{}, fmt.Errorf("decode issuer JWT: %w", err)
	}
	chain, err := certchain.X5CDERsFromHeader(header)
	if err != nil {
		return VerifiedIssuedCredential{}, fmt.Errorf("issuer certificate: %w", err)
	}
	leaf, err := certchain.VerifyLeaf(chain, p.IssuerRoots)
	if err != nil {
		return VerifiedIssuedCredential{}, fmt.Errorf("issuer certificate: %w", err)
	}
	alg, err := joseAlgForKey(leaf.PublicKey)
	if err != nil {
		return VerifiedIssuedCredential{}, fmt.Errorf("issuer certificate: %w", err)
	}
	payload, _, err := sdjwtvc.Verify(p.Credential, leaf.PublicKey, alg, sdjwtvc.VerifyOptions{
		RequireKeyBinding: sdjwtvc.KeyBindingNotRequired, Now: func() time.Time { return now },
		MaxClockSkew: issuerClockSkew,
	})
	if err != nil {
		return VerifiedIssuedCredential{}, fmt.Errorf("verify: %w", err)
	}
	if vct, _ := payload["vct"].(string); vct != p.Configuration.VCT {
		return VerifiedIssuedCredential{}, fmt.Errorf("vct is %q, want %q", vct, p.Configuration.VCT)
	}
	if p.HolderKey != nil {
		if err := cnfIsKey(payload["cnf"], p.HolderKey); err != nil {
			return VerifiedIssuedCredential{}, err
		}
	}
	verified := VerifiedIssuedCredential{IssuerCertificate: leaf, Claims: payload, ValidUntil: numericDate(payload["exp"])}
	if status, ok := payload["status"].(map[string]any); ok {
		ref, err := statuslist.ParseStatusClaim(status)
		if err != nil {
			return VerifiedIssuedCredential{}, fmt.Errorf("status: %w", err)
		}
		verified.StatusList = &ref
	}
	return verified, nil
}

// numericDate is a JWT NumericDate claim's time, or zero when it isn't
// one.
func numericDate(v any) time.Time {
	var secs float64
	switch n := v.(type) {
	case float64:
		secs = n
	case int64:
		secs = float64(n)
	case json.Number:
		f, err := n.Float64()
		if err != nil {
			return time.Time{}
		}
		secs = f
	default:
		return time.Time{}
	}
	return time.Unix(int64(secs), 0).UTC()
}

func verifyIssuedMdoc(p VerifyIssuedCredentialParams, now time.Time) (VerifiedIssuedCredential, error) {
	raw, err := base64.RawURLEncoding.DecodeString(p.Credential)
	if err != nil {
		return VerifiedIssuedCredential{}, fmt.Errorf("decode: %w", err)
	}
	signed, err := mdoc.UnmarshalIssuerSigned(raw)
	if err != nil {
		return VerifiedIssuedCredential{}, fmt.Errorf("parse: %w", err)
	}
	protected, unprotected, _, err := cose.DecodeUnverified(signed.IssuerAuth)
	if err != nil {
		return VerifiedIssuedCredential{}, fmt.Errorf("decode issuerAuth: %w", err)
	}
	// ISO/IEC 18013-5 puts x5chain in the unprotected header; RFC 9360
	// allows either bucket.
	chain := unprotected.X5Chain
	if len(chain) == 0 {
		chain = protected.X5Chain
	}
	leaf, err := certchain.VerifyLeaf(chain, p.IssuerRoots)
	if err != nil {
		return VerifiedIssuedCredential{}, fmt.Errorf("issuer certificate: %w", err)
	}
	alg, err := coseAlgForKey(leaf.PublicKey)
	if err != nil {
		return VerifiedIssuedCredential{}, fmt.Errorf("issuer certificate: %w", err)
	}
	mso, err := mdoc.Verify(signed, p.Configuration.DocType, leaf.PublicKey, alg, mdoc.VerifyOptions{
		Now: func() time.Time { return now }, MaxClockSkew: issuerClockSkew,
	})
	if err != nil {
		return VerifiedIssuedCredential{}, fmt.Errorf("verify: %w", err)
	}
	if p.HolderKey != nil && !publicKeysEqual(mso.DeviceKey, p.HolderKey) {
		return VerifiedIssuedCredential{}, errors.New("the MSO's DeviceKey isn't the holder key")
	}
	claims := make(map[string]any, len(mso.NameSpaces))
	for ns, elements := range mso.NameSpaces {
		claims[ns] = elements
	}
	verified := VerifiedIssuedCredential{IssuerCertificate: leaf, Claims: claims, ValidUntil: mso.ValidityInfo.ValidUntil.UTC()}
	if mso.Status != nil && mso.Status.StatusList != nil {
		verified.StatusList = &statuslist.StatusListRef{Idx: mso.Status.StatusList.Idx, URI: mso.Status.StatusList.URI}
		verified.StatusListCWT = true
	}
	return verified, nil
}

// cnfIsKey checks an SD-JWT VC's "cnf" claim names holderKey as its
// "jwk" (RFC 7800).
func cnfIsKey(cnf any, holderKey crypto.PublicKey) error {
	cnfObj, _ := cnf.(map[string]any)
	rawJWK, ok := cnfObj["jwk"]
	if !ok {
		return errors.New("the credential has no cnf.jwk")
	}
	jwkJSON, err := json.Marshal(rawJWK)
	if err != nil {
		return fmt.Errorf("cnf.jwk: %w", err)
	}
	bound, err := jwk.ParsePublicKey(jwkJSON)
	if err != nil {
		return fmt.Errorf("cnf.jwk: %w", err)
	}
	if !publicKeysEqual(bound, holderKey) {
		return errors.New("cnf.jwk isn't the holder key")
	}
	return nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	eq, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && eq.Equal(b)
}

// joseAlgForKey and coseAlgForKey pick the signature algorithm from the
// verified certificate's key type, never from the credential's own
// (untrusted) header.
func joseAlgForKey(pub crypto.PublicKey) (jose.Alg, error) {
	switch pub.(type) {
	case *ecdsa.PublicKey:
		return jose.ES256, nil
	case ed25519.PublicKey:
		return jose.EdDSA, nil
	default:
		return "", fmt.Errorf("unsupported issuer key type %T", pub)
	}
}

func coseAlgForKey(pub crypto.PublicKey) (cose.Alg, error) {
	switch pub.(type) {
	case *ecdsa.PublicKey:
		return cose.ES256, nil
	case ed25519.PublicKey:
		return cose.EdDSA, nil
	default:
		return 0, fmt.Errorf("unsupported issuer key type %T", pub)
	}
}
