package statuslist

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// IssueTokenX5C is IssueToken with the signer's certificate chain in the
// token's "x5c" header instead of a "kid": HAIP 1.0 §6.1 requires the key that
// validates a Status List Token to be in its x5c header, and the trust
// anchor's certificate not to be. chain is the signer's certificate
// first, then any intermediates — not the trust anchor.
func IssueTokenX5C(signer crypto.Signer, alg jose.Alg, claims TokenClaims, chain []*x509.Certificate) (string, error) {
	ders, err := signerChain(signer, chain)
	if err != nil {
		return "", err
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
func IssueTokenCWTX5Chain(signer crypto.Signer, alg cose.Alg, claims TokenClaims, chain []*x509.Certificate) ([]byte, error) {
	ders, err := signerChain(signer, chain)
	if err != nil {
		return nil, err
	}
	return issueTokenCWT(signer, alg, claims, cose.Headers{Typ: CWTTokenMediaType, X5Chain: ders})
}

// signerChain checks chain is non-empty and starts with signer's own
// certificate, returning its DER encodings.
func signerChain(signer crypto.Signer, chain []*x509.Certificate) ([][]byte, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("statuslist: a certificate chain is required")
	}
	pub, ok := chain[0].PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(signer.Public()) {
		return nil, fmt.Errorf("statuslist: the chain's first certificate isn't the signer's")
	}
	ders := make([][]byte, len(chain))
	for i, c := range chain {
		ders[i] = c.Raw
	}
	return ders, nil
}

// CheckX5C is Check for a Status List Token that carries its signer's
// certificate chain in its x5c header (IssueTokenX5C, HAIP 1.0): the
// chain must verify to one of roots, and its leaf must not be
// self-signed; the leaf's key then validates the token.
func CheckX5C(token string, roots *x509.CertPool, ref StatusListRef, opts VerifyOptions) (StatusType, TokenClaims, error) {
	header, _, err := jose.DecodeUnverifiedMax(token, maxTokenBytes)
	if err != nil {
		return 0, TokenClaims{}, fmt.Errorf("statuslist: decode token: %w", err)
	}
	chain, err := certchain.X5CDERsFromHeader(header)
	if err != nil {
		return 0, TokenClaims{}, fmt.Errorf("statuslist: token signer: %w", err)
	}
	leaf, err := certchain.VerifyLeafWithPolicy(chain, roots, opts.LeafPolicy)
	if err != nil {
		return 0, TokenClaims{}, fmt.Errorf("statuslist: token signer: %w", err)
	}
	var alg jose.Alg
	switch leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		alg = jose.ES256
	case ed25519.PublicKey:
		alg = jose.EdDSA
	default:
		return 0, TokenClaims{}, fmt.Errorf("statuslist: token signer: unsupported key type %T", leaf.PublicKey)
	}
	return Check(token, leaf.PublicKey, alg, ref, opts)
}

// CheckCWTX5Chain is CheckX5C for a Status List Token in CWT format
// carrying its signer's certificate chain in an x5chain header
// (IssueTokenCWTX5Chain) — protected or, as RFC 9360 allows,
// unprotected; tagged or untagged.
func CheckCWTX5Chain(token []byte, roots *x509.CertPool, ref StatusListRef, opts VerifyOptions) (StatusType, TokenClaims, error) {
	decode := cose.DecodeUnverified
	if len(token) > 0 && token[0] == coseSign1TagByte {
		decode = cose.DecodeUnverifiedTagged
	}
	protected, unprotected, _, err := decode(token)
	if err != nil {
		return 0, TokenClaims{}, fmt.Errorf("statuslist: decode token: %w", err)
	}
	chain := protected.X5Chain
	if len(chain) == 0 {
		chain = unprotected.X5Chain
	}
	leaf, err := certchain.VerifyLeafWithPolicy(chain, roots, opts.LeafPolicy)
	if err != nil {
		return 0, TokenClaims{}, fmt.Errorf("statuslist: token signer: %w", err)
	}
	var alg cose.Alg
	switch leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		alg = cose.ES256
	case ed25519.PublicKey:
		alg = cose.EdDSA
	default:
		return 0, TokenClaims{}, fmt.Errorf("statuslist: token signer: unsupported key type %T", leaf.PublicKey)
	}
	return CheckCWT(token, leaf.PublicKey, alg, ref, opts)
}
