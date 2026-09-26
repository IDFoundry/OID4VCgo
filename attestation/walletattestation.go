package attestation

import (
	"crypto"
	"encoding/json"
	"fmt"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// WalletAttestationTypHeader is the required JOSE "typ" header of a
// Wallet Attestation JWT — the same value the base attestation draft
// uses (OID4VCI 1.0 Appendix E: "The Wallet Attestation format follows
// Section 5.1 'Client Attestation JWT' of
// [I-D.ietf-oauth-attestation-based-client-auth]"; that section
// requires "typ": "oauth-client-attestation+jwt", unchanged by
// Appendix E's own additional claims).
const WalletAttestationTypHeader = "oauth-client-attestation+jwt"

// WalletAttestationExtraClaims is the OID4VCI-specific claims Appendix
// E adds on top of the base Client Attestation JWT (whose iss/sub/exp/
// cnf/iat/nbf claims and signature verification are FAPIgo's
// responsibility — see the package doc comment). All three are
// OPTIONAL.
type WalletAttestationExtraClaims struct {
	// WalletName is a human-readable name of the Wallet.
	WalletName string

	// WalletLink is a URL with further information about the Wallet
	// and its Wallet Provider.
	WalletLink string

	// Status is the Wallet Attestation's own status mechanism — see
	// statuslist.StatusListRef.Claim/ParseStatusClaim, the same shape
	// credential/sdjwtvc's Claims.Status uses.
	Status map[string]any
}

// ParseWalletAttestationClaims extracts wallet_name/wallet_link/status
// from a Wallet Attestation JWT's payload, given the same compact JWT
// string presented as the OAuth-Client-Attestation header — without
// checking its signature. This is not a substitute for FAPIgo's
// server-side verification (server.authenticateClientViaAttestation,
// via internal/clientattestation): call it only on a Wallet Attestation
// the caller already knows was verified through that path — for
// example, after a successful FAPIgo-authenticated request, when the
// embedder additionally wants the extra claims FAPIgo's own
// clientattestation.VerifiedAttestation doesn't surface — and never to
// make an authentication decision on its own.
func ParseWalletAttestationClaims(compact string) (WalletAttestationExtraClaims, error) {
	header, payload, err := jose.DecodeUnverified(compact)
	if err != nil {
		return WalletAttestationExtraClaims{}, fmt.Errorf("attestation: %w", err)
	}
	if typ, _ := header["typ"].(string); typ != WalletAttestationTypHeader {
		return WalletAttestationExtraClaims{}, fmt.Errorf("attestation: typ is %q, want %q", typ, WalletAttestationTypHeader)
	}

	var wire struct {
		WalletName string         `json:"wallet_name,omitempty"`
		WalletLink string         `json:"wallet_link,omitempty"`
		Status     map[string]any `json:"status,omitempty"`
	}
	if err := json.Unmarshal(payload, &wire); err != nil {
		return WalletAttestationExtraClaims{}, fmt.Errorf("attestation: unmarshal claims: %w", err)
	}
	return WalletAttestationExtraClaims{WalletName: wire.WalletName, WalletLink: wire.WalletLink, Status: wire.Status}, nil
}

// WalletAttestationClaims is a Wallet Attestation JWT's claims set, as
// a Wallet Provider issues it: the base Client Attestation JWT claims
// (draft-ietf-oauth-attestation-based-client-auth-07 §5.1) plus
// OID4VCI Appendix E's extra claims.
type WalletAttestationClaims struct {
	// Issuer ("iss") identifies the Wallet Provider. REQUIRED — the
	// Authorization Server matches it against the client's registered
	// expected attester issuer.
	Issuer string

	// Subject ("sub") is the Wallet's own client_id. REQUIRED.
	Subject string

	// InstanceKey is the Wallet instance's own public key, carried as
	// "cnf"."jwk" (RFC 7800). The Wallet proves possession of its
	// private half on every request via a Client Attestation PoP JWT.
	// REQUIRED. P-256 EC or Ed25519, the key types internal/jose
	// supports.
	InstanceKey crypto.PublicKey

	// IssuedAt ("iat") and ExpiresAt ("exp") are Unix times. ExpiresAt
	// is REQUIRED; IssuedAt and NotBefore ("nbf") are OPTIONAL (zero
	// omits them).
	IssuedAt  int64
	ExpiresAt int64
	NotBefore int64

	// Extra carries Appendix E's OPTIONAL wallet_name, wallet_link and
	// status claims.
	Extra WalletAttestationExtraClaims
}

type wireWalletAttestationClaims struct {
	Issuer     string                     `json:"iss"`
	Subject    string                     `json:"sub"`
	IssuedAt   int64                      `json:"iat,omitempty"`
	ExpiresAt  int64                      `json:"exp"`
	NotBefore  int64                      `json:"nbf,omitempty"`
	CNF        map[string]json.RawMessage `json:"cnf"`
	WalletName string                     `json:"wallet_name,omitempty"`
	WalletLink string                     `json:"wallet_link,omitempty"`
	Status     map[string]any             `json:"status,omitempty"`
}

// IssueWalletAttestation builds and signs a Wallet Attestation JWT
// (OID4VCI 1.0 Appendix E) — the Wallet Provider's side of
// Attestation-Based Client Authentication. The Wallet presents the
// result as its OAuth-Client-Attestation header (for fapigo/client,
// via Dependencies.Attestation); verifying it is the Authorization
// Server's job (fapigo/server). header's KeyID/X5C/TrustChain convey
// the Wallet Provider's own key, the same way they do for Issue.
func IssueWalletAttestation(signer crypto.Signer, alg jose.Alg, header Header, claims WalletAttestationClaims) (string, error) {
	if claims.Issuer == "" {
		return "", fmt.Errorf("attestation: WalletAttestationClaims.Issuer is required")
	}
	if claims.Subject == "" {
		return "", fmt.Errorf("attestation: WalletAttestationClaims.Subject is required")
	}
	if claims.InstanceKey == nil {
		return "", fmt.Errorf("attestation: WalletAttestationClaims.InstanceKey is required")
	}
	if claims.ExpiresAt == 0 {
		return "", fmt.Errorf("attestation: WalletAttestationClaims.ExpiresAt is required")
	}
	if claims.IssuedAt != 0 && claims.ExpiresAt <= claims.IssuedAt {
		return "", fmt.Errorf("attestation: WalletAttestationClaims.ExpiresAt must be after IssuedAt")
	}
	instanceJWK, err := marshalJWK(claims.InstanceKey)
	if err != nil {
		return "", err
	}

	payload, err := json.Marshal(wireWalletAttestationClaims{
		Issuer: claims.Issuer, Subject: claims.Subject,
		IssuedAt: claims.IssuedAt, ExpiresAt: claims.ExpiresAt, NotBefore: claims.NotBefore,
		CNF:        map[string]json.RawMessage{"jwk": instanceJWK},
		WalletName: claims.Extra.WalletName, WalletLink: claims.Extra.WalletLink, Status: claims.Extra.Status,
	})
	if err != nil {
		return "", fmt.Errorf("attestation: marshal claims: %w", err)
	}
	compact, err := jose.Sign(alg, signer, joseHeader(WalletAttestationTypHeader, header), payload)
	if err != nil {
		return "", fmt.Errorf("attestation: sign: %w", err)
	}
	return compact, nil
}
