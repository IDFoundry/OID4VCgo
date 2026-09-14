package attestation

import (
	"encoding/json"
	"fmt"

	"github.com/idfoundry/oid4vcigo/internal/jose"
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
