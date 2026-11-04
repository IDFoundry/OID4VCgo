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
	status, parsed, err := checkX5C(context.Background(), token, roots, ref, opts, nil)
	return failClosed(status, parsed.claims, err)
}

// checkX5C is CheckX5C, before failClosed, with ctx for opts.Revocation,
// given what a Cache remembers of the same token's bytes when memo isn't
// nil: the signer's chain and the signature are verified all the same.
func checkX5C(ctx context.Context, token string, roots *x509.CertPool, ref StatusListRef, opts VerifyOptions, memo *tokenMemo) (StatusType, parsedClaims, error) {
	opts = opts.atOneInstant()
	policy, err := opts.signerPolicy()
	if err != nil {
		return 0, parsedClaims{}, err
	}
	limit, err := opts.maxTokenBytes()
	if err != nil {
		return 0, parsedClaims{}, err
	}
	header, _, err := jose.DecodeUnverifiedMax(token, limit)
	if err != nil {
		return 0, parsedClaims{}, fmt.Errorf("statuslist: decode token: %w", err)
	}
	chain, err := certchain.X5CDERsFromHeader(header)
	if err != nil {
		return 0, parsedClaims{}, fmt.Errorf("statuslist: token signer: %w", err)
	}
	leaf, _, err := certchain.VerifyTrustedChainsAt(ctx, chain, roots, policy, opts.Revocation, opts.now())
	if err != nil {
		return 0, parsedClaims{}, fmt.Errorf("statuslist: token signer: %w", err)
	}
	if err := checkSignerIsIssuer(leaf, opts); err != nil {
		return 0, parsedClaims{}, err
	}
	eddsa, err := certchain.SignerKeyIsEdDSA(leaf.PublicKey)
	if err != nil {
		return 0, parsedClaims{}, fmt.Errorf("statuslist: token signer: %w", err)
	}
	alg := jose.ES256
	if eddsa {
		alg = jose.EdDSA
	}
	return checkJWT(token, leaf.PublicKey, alg, ref, opts, memo)
}

// CheckCWTX5Chain is CheckX5C for a Status List Token in CWT format
// carrying its signer's certificate chain in an x5chain header
// (IssueTokenCWTX5Chain) — protected or, as RFC 9360 allows,
// unprotected (protected only, with opts.X5ChainProtectedOnly); tagged
// or untagged.
func CheckCWTX5Chain(token []byte, roots *x509.CertPool, ref StatusListRef, opts VerifyOptions) (StatusType, TokenClaims, error) {
	status, parsed, err := checkCWTX5Chain(context.Background(), token, roots, ref, opts, nil)
	return failClosed(status, parsed.claims, err)
}

// checkCWTX5Chain is CheckCWTX5Chain, before failClosed, with ctx for
// opts.Revocation, given memo as checkX5C is.
func checkCWTX5Chain(ctx context.Context, token []byte, roots *x509.CertPool, ref StatusListRef, opts VerifyOptions, memo *tokenMemo) (StatusType, parsedClaims, error) {
	opts = opts.atOneInstant()
	policy, err := opts.signerPolicy()
	if err != nil {
		return 0, parsedClaims{}, err
	}
	limit, err := opts.maxTokenBytes()
	if err != nil {
		return 0, parsedClaims{}, err
	}
	leaf, alg, err := cose.X5ChainSigner(ctx, token, cose.X5ChainTrust{
		MaxBytes: limit, ProtectedOnly: opts.X5ChainProtectedOnly, Roots: roots,
		Policy: policy, Revocation: opts.Revocation, Now: opts.now(),
	})
	if err != nil {
		return 0, parsedClaims{}, fmt.Errorf("statuslist: %w", err)
	}
	// As for a JWT token: Issuer and IssuerKey bind the signer.
	if err := checkSignerIsIssuer(leaf, opts); err != nil {
		return 0, parsedClaims{}, err
	}
	return checkCWT(token, leaf.PublicKey, alg, ref, opts, memo)
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
