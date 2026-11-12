package statuslist

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// IssueTokenX5C is IssueToken with the signer's certificate chain in the
// token's "x5c" header instead of a "kid": HAIP 1.0 §6.1 requires the key that
// validates a Status List Token to be in its x5c header, and the trust
// anchor's certificate not to be. chain is the signer's certificate
// first, then any intermediates — not the trust anchor.
func IssueTokenX5C(signer crypto.Signer, alg oid4vci.JOSEAlg, claims TokenClaims, chain []*x509.Certificate) (string, error) {
	ders, err := certchain.SignerChainDERs(signer, chain)
	if err != nil {
		return "", fmt.Errorf("statuslist: %w", err)
	}
	x5c := make([]string, len(ders))
	for i, der := range ders {
		x5c[i] = base64.StdEncoding.EncodeToString(der)
	}
	return issueToken(signer, alg, claims, map[string]any{"typ": TokenTyp, "x5c": x5c})
}

// IssueTokenCWTX5Chain is IssueTokenCWT with the signer's certificate
// chain in the token's protected "x5chain" header (RFC 9360) instead of
// a "kid" — the CWT counterpart to IssueTokenX5C.
func IssueTokenCWTX5Chain(signer crypto.Signer, alg oid4vci.COSEAlg, claims TokenClaims, chain []*x509.Certificate) ([]byte, error) {
	ders, err := certchain.SignerChainDERs(signer, chain)
	if err != nil {
		return nil, fmt.Errorf("statuslist: %w", err)
	}
	return issueTokenCWT(signer, alg, claims, cose.Headers{Typ: CWTTokenMediaType, X5Chain: ders})
}

// CheckX5C is Check for a Status List Token that carries its signer's
// certificate chain in its x5c header (IssueTokenX5C, HAIP 1.0): the
// chain must verify to one of roots, and its leaf must not be
// self-signed; the leaf's key then validates the token.
func CheckX5C(token string, roots *x509.CertPool, ref StatusListRef, opts VerifyOptions) (StatusType, TokenClaims, error) {
	status, parsed, err := checkX5C(context.Background(), token, roots, ref, opts)
	return failClosed(status, parsed.claims, err)
}

// checkX5C is CheckX5C, before failClosed, with ctx for
// opts.Revocation.
func checkX5C(ctx context.Context, token string, roots *x509.CertPool, ref StatusListRef, opts VerifyOptions) (StatusType, parsedClaims, error) {
	signed, err := verifyX5C(ctx, token, roots, opts)
	if err != nil {
		return 0, parsedClaims{}, err
	}
	return checkClaims(signed.parsed, ref, nil)
}

// signedToken is what verifying a token found that depends on its bytes
// alone: the signer's chain, as the token carries it, whose leaf's key
// its signature verifies under, and its claims as parsed.
type signedToken struct {
	chain [][]byte
	// chainProtected is whether a CWT token's chain is from its
	// protected header.
	chainProtected bool
	parsed         parsedClaims
}

// verifyX5C is checkX5C short of sub and the status: the signer's
// chain to roots, on a path opts's policy approves and its Revocation
// passes, and its binding to the Referenced Token's issuer; the
// signature and typ; and the claims' iss and times.
func verifyX5C(ctx context.Context, token string, roots *x509.CertPool, opts VerifyOptions) (signedToken, error) {
	opts = opts.atOneInstant()
	trust, err := signerTrust(roots, opts)
	if err != nil {
		return signedToken{}, err
	}
	header, _, err := jose.DecodeUnverifiedMax(token, trust.MaxBytes)
	if err != nil {
		return signedToken{}, fmt.Errorf("statuslist: decode token: %w", err)
	}
	chain, err := certchain.X5CDERsFromHeader(header)
	if err != nil {
		return signedToken{}, fmt.Errorf("statuslist: token signer: %w", err)
	}
	leaf, _, err := trustedSigner(ctx, trust, chain, false, opts)
	if err != nil {
		return signedToken{}, err
	}
	alg, err := jose.AlgForKey(leaf.PublicKey)
	if err != nil {
		return signedToken{}, fmt.Errorf("statuslist: token signer: %w", err)
	}
	parsed, err := verifyToken(token, leaf.PublicKey, alg, opts)
	if err != nil {
		return signedToken{}, err
	}
	return signedToken{chain: chain, parsed: parsed}, nil
}

// CheckCWTX5Chain is CheckX5C for a Status List Token in CWT format
// carrying its signer's certificate chain in an x5chain header
// (IssueTokenCWTX5Chain) — protected or, as RFC 9360 allows,
// unprotected (protected only, with opts.X5ChainProtectedOnly); tagged
// or untagged.
func CheckCWTX5Chain(token []byte, roots *x509.CertPool, ref StatusListRef, opts VerifyOptions) (StatusType, TokenClaims, error) {
	status, parsed, err := checkCWTX5Chain(context.Background(), token, roots, ref, opts)
	return failClosed(status, parsed.claims, err)
}

// checkCWTX5Chain is CheckCWTX5Chain, before failClosed, with ctx for
// opts.Revocation.
func checkCWTX5Chain(ctx context.Context, token []byte, roots *x509.CertPool, ref StatusListRef, opts VerifyOptions) (StatusType, parsedClaims, error) {
	signed, err := verifyCWTX5Chain(ctx, token, roots, opts)
	if err != nil {
		return 0, parsedClaims{}, err
	}
	return checkClaims(signed.parsed, ref, nil)
}

// verifyCWTX5Chain is verifyX5C for the CWT form.
func verifyCWTX5Chain(ctx context.Context, token []byte, roots *x509.CertPool, opts VerifyOptions) (signedToken, error) {
	opts = opts.atOneInstant()
	trust, err := signerTrust(roots, opts)
	if err != nil {
		return signedToken{}, err
	}
	chain, protected, err := trust.Chain(token)
	if err != nil {
		return signedToken{}, fmt.Errorf("statuslist: %w", err)
	}
	leaf, alg, err := trustedSigner(ctx, trust, chain, true, opts)
	if err != nil {
		return signedToken{}, err
	}
	parsed, err := verifyTokenCWT(token, leaf.PublicKey, alg, opts)
	if err != nil {
		return signedToken{}, err
	}
	return signedToken{chain: chain, chainProtected: protected, parsed: parsed}, nil
}

// signerTrust is how a token's signer is verified under roots and opts,
// short of its binding to the Referenced Token's issuer
// (checkSignerIsIssuer).
func signerTrust(roots *x509.CertPool, opts VerifyOptions) (cose.X5ChainTrust, error) {
	policy, err := opts.signerPolicy()
	if err != nil {
		return cose.X5ChainTrust{}, err
	}
	limit, err := opts.maxTokenBytes()
	if err != nil {
		return cose.X5ChainTrust{}, err
	}
	return cose.X5ChainTrust{
		MaxBytes: limit, ProtectedOnly: opts.X5ChainProtectedOnly, Roots: roots,
		Policy: policy, Revocation: opts.Revocation, Now: opts.now(),
	}, nil
}

// trustedSigner is the leaf of a token's signer chain once trust
// verifies it and it's bound to the Referenced Token's issuer, with the
// COSE alg its key signs with when cwt is set.
func trustedSigner(ctx context.Context, trust cose.X5ChainTrust, chain [][]byte, cwt bool, opts VerifyOptions) (*x509.Certificate, cose.Alg, error) {
	var leaf *x509.Certificate
	var alg cose.Alg
	var err error
	if cwt {
		if leaf, alg, err = trust.Signer(ctx, chain); err != nil {
			return nil, 0, fmt.Errorf("statuslist: %w", err)
		}
	} else if leaf, _, err = certchain.VerifyTrustedChainsAt(ctx, chain, trust.Roots, trust.Policy, trust.Revocation, trust.Now); err != nil {
		return nil, 0, fmt.Errorf("statuslist: token signer: %w", err)
	}
	// Either form: Issuer and IssuerKey bind the signer.
	if err := checkSignerIsIssuer(leaf, opts); err != nil {
		return nil, 0, err
	}
	return leaf, alg, nil
}

// checkSignerIsIssuer checks a token's signer is the Referenced Token's
// issuer, as far as opts says who that is: it signs with IssuerKey, or
// its certificate names Issuer. With neither set, opts.UnboundSigner
// has already decided the signer (signerPolicy).
func checkSignerIsIssuer(leaf *x509.Certificate, opts VerifyOptions) error {
	if (opts.Issuer == "" && opts.IssuerKey == nil) || certchain.SameKey(leaf.PublicKey, opts.IssuerKey) {
		return nil
	}
	if opts.Issuer == "" {
		return errors.New("statuslist: token signer isn't the referenced token's issuer: it signs with another key")
	}
	// The status of this issuer's tokens is its own to sign.
	if err := certchain.CheckIssuerName(leaf, opts.Issuer); err != nil {
		return fmt.Errorf("statuslist: token signer isn't the referenced token's issuer: neither its key nor a name its certificate carries: %w", err)
	}
	return nil
}
