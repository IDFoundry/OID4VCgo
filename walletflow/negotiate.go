package walletflow

import (
	"errors"
	"fmt"
	"slices"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// IssuanceProfile is the profile a Wallet's issuance follows. It doesn't
// affect presentation.
type IssuanceProfile int

const (
	// ProfileOpenID4VCI follows the issuer's and Authorization Server's
	// metadata, as OpenID4VCI 1.0 has a Wallet do: it authenticates with
	// a Wallet Attestation where the Authorization Server takes one, and
	// redeems a pre-authorized code anonymously where it allows that
	// instead (§12.3); it sends a key attestation where the issuer
	// requires one (key_attestations_required, §12.2.4), and plain jwt
	// proofs otherwise; it does without a nonce endpoint the issuer
	// doesn't have (§7), and takes a Bearer access token the
	// Authorization Server issues (§13.2). It doesn't receive a
	// credential bound to no key (ErrProofUnsupported). It's the default.
	ProfileOpenID4VCI IssuanceProfile = iota
	// ProfileHAIP also refuses, with ErrProfileViolation, an issuer that
	// doesn't follow HAIP 1.0 §4: one whose Authorization Server takes
	// no Wallet Attestation (§4.4.1: "Wallets MUST use ... an OAuth2
	// Client authentication mechanism"), a credential with no scope
	// (§4.2), one bound to a key with no nonce endpoint (§4.1), and an
	// access token that isn't DPoP-bound (§4, FAPI 2.0's
	// sender-constrained tokens). It prefers the attestation proof type
	// where the issuer offers it. It doesn't refuse an issuer that asks
	// for no key attestation: a Wallet must support them (§4.5.1), and
	// whether one is needed is the issuer's to say.
	ProfileHAIP
)

// String is the profile's name: "openid4vci" or "haip".
func (p IssuanceProfile) String() string {
	switch p {
	case ProfileOpenID4VCI:
		return "openid4vci"
	case ProfileHAIP:
		return "haip"
	default:
		return fmt.Sprintf("IssuanceProfile(%d)", int(p))
	}
}

var (
	// ErrProfileViolation is wrapped by StartIssuance, RedeemPreAuthorizedCode,
	// CompleteAuthorization and RefreshCredential, under ProfileHAIP, for
	// an issuer that doesn't follow HAIP 1.0.
	ErrProfileViolation = errors.New("walletflow: the issuer doesn't follow the issuance profile")
	// ErrClientAuthUnsupported is wrapped by StartIssuance for an offer
	// the wallet can't redeem: its Authorization Server takes neither a
	// Wallet Attestation the wallet can give (no Dependencies.Provider,
	// or a method or algorithm the wallet lacks) nor, for a
	// pre-authorized code, a request with no client authentication.
	ErrClientAuthUnsupported = errors.New("walletflow: the authorization server takes no client authentication the wallet supports")
	// ErrProofUnsupported is wrapped by StartIssuance, for a credential
	// the wallet can't hold — one bound to no key, which it doesn't
	// receive, or by a binding method other than jwk or cose_key — and by
	// RequestCredentials for one whose issuer takes no proof the wallet
	// can give: none signed with ES256, or a key attestation without
	// Dependencies.Provider.
	ErrProofUnsupported = errors.New("walletflow: the issuer takes no proof the wallet can give")
)

// clientAuth is how a token request authenticates the wallet.
type clientAuth int

const (
	// clientAuthAttestation is a Wallet Attestation
	// (draft-ietf-oauth-attestation-based-client-auth-07).
	clientAuthAttestation clientAuth = iota
	// clientAuthNone is no client authentication: a pre-authorized code
	// redeemed anonymously (OpenID4VCI 1.0 §12.3), or a public client's
	// refresh.
	clientAuthNone
)

// attestationAlg is the algorithm the wallet signs its Client
// Attestation PoP and proofs with.
const attestationAlg = oid4vci.ES256

// chooseClientAuth is how the wallet authenticates at asMeta's token
// endpoint for grant: a Wallet Attestation where the server takes one
// and the wallet can give it, else, for a pre-authorized code, none
// where the server allows that. Where both would do, the default
// profile takes none: a Wallet Attestation tells the server which
// wallet, from which provider, the holder uses. Under ProfileHAIP only
// a Wallet Attestation will do (HAIP 1.0 §4.4.1).
func (w *Wallet) chooseClientAuth(asMeta wallet.AuthorizationServerMetadata, grant Grant) (clientAuth, error) {
	attest := w.deps.Provider != nil && w.cfg.ClientID != "" && takesAttestation(asMeta)
	anonymous := grant == GrantPreAuthorizedCode && asMeta.PreAuthorizedGrantAnonymousAccessSupported
	switch {
	case w.cfg.IssuanceProfile == ProfileHAIP && !attest:
		return 0, fmt.Errorf("%w: its authorization server takes no Wallet Attestation this wallet can give (HAIP 1.0 §4.4.1)", ErrProfileViolation)
	case w.cfg.IssuanceProfile == ProfileHAIP:
		return clientAuthAttestation, nil
	case anonymous:
		return clientAuthNone, nil
	case attest:
		return clientAuthAttestation, nil
	default:
		return 0, ErrClientAuthUnsupported
	}
}

// takesAttestation reports whether asMeta may take a Wallet Attestation
// with an ES256 PoP. A server that lists no token endpoint auth methods
// is given the benefit of the doubt, as HAIP issuers that predate
// attest_jwt_client_auth's registration were before metadata was
// negotiated, and so is one listing the method but no PoP algorithms;
// its token endpoint has the last word.
func takesAttestation(asMeta wallet.AuthorizationServerMetadata) bool {
	switch {
	case len(asMeta.TokenEndpointAuthMethodsSupported) == 0:
		return true
	case !slices.Contains(asMeta.TokenEndpointAuthMethodsSupported, wallet.AttestJWTClientAuth):
		return false
	default:
		return len(asMeta.ClientAttestationPoPSigningAlgValuesSupported) == 0 || asMeta.SupportsAttestationAuth(attestationAlg)
	}
}

// proofPlan is how to prove possession of the keys a credential is
// bound to: jwt proofs (Appendix F.1), or a key attestation (Appendix
// F.3).
type proofPlan int

const (
	proofJWT proofPlan = iota
	proofAttestation
)

// chooseProof is the proof the wallet sends for conf, a credential
// bound to a key (checkBindable). The proof is signed with ES256, which
// the proof type must take. The default profile sends a plain jwt
// proof unless the issuer requires a key attestation with it
// (key_attestations_required), when it sends the attestation proof type
// instead: a key attestation the issuer didn't ask for tells it more
// about the holder's device than it needs. ProfileHAIP prefers the
// attestation proof type wherever the issuer offers it.
func (w *Wallet) chooseProof(conf oid4vci.CredentialConfigurationMetadata) (proofPlan, error) {
	if err := checkBindable(conf); err != nil {
		return 0, err
	}
	usable := func(pt string) (oid4vci.ProofTypeConfiguration, bool) {
		c, ok := conf.ProofTypesSupported[pt]
		return c, ok && slices.Contains(c.ProofSigningAlgValuesSupported, attestationAlg)
	}
	jwt, hasJWT := usable(oid4vci.ProofTypeJWT)
	_, hasAttestation := usable(oid4vci.ProofTypeAttestation)
	hasAttestation = hasAttestation && w.deps.Provider != nil
	switch {
	case w.cfg.IssuanceProfile == ProfileHAIP && hasAttestation:
		return proofAttestation, nil
	case hasJWT && jwt.KeyAttestationsRequired == nil:
		return proofJWT, nil
	case hasAttestation:
		return proofAttestation, nil
	case hasJWT:
		// A key attestation in a jwt proof's header (Appendix F.1) isn't
		// supported: the attestation proof type carries one alone.
		return 0, fmt.Errorf("%w: it requires a key attestation in a jwt proof", ErrProofUnsupported)
	default:
		return 0, fmt.Errorf("%w: no proof type it takes is signed with %s, or carries a key attestation without a Wallet Provider", ErrProofUnsupported, attestationAlg)
	}
}

// supportsBinding reports whether the wallet can bind conf to a key it
// holds: a P-256 key as a JWK for an SD-JWT VC, as a COSE_Key for an
// mdoc (§12.2.4, Appendix A).
func supportsBinding(conf oid4vci.CredentialConfigurationMetadata) bool {
	return slices.Contains(conf.CryptographicBindingMethodsSupported, "jwk") ||
		slices.Contains(conf.CryptographicBindingMethodsSupported, "cose_key")
}

// checkProfile reports what about the issuer, under ProfileHAIP, HAIP
// 1.0 §4 doesn't allow, for the configurations configIDs it's asked for:
// each needs a scope, and the issuer a nonce endpoint.
func (w *Wallet) checkProfile(metadata oid4vci.Metadata, configIDs []string) error {
	if w.cfg.IssuanceProfile != ProfileHAIP {
		return nil
	}
	for _, id := range configIDs {
		conf := metadata.CredentialConfigurationsSupported[id]
		switch {
		case conf.Scope == "":
			return fmt.Errorf("%w: credential %q has no scope (HAIP 1.0 §4.2)", ErrProfileViolation, id)
		case metadata.NonceEndpoint == nil:
			return fmt.Errorf("%w: the issuer has no nonce endpoint (HAIP 1.0 §4.1)", ErrProfileViolation)
		}
	}
	return nil
}

// tokenType is a Token Response's token_type, as wallet.TokenTypeDPoP
// or wallet.TokenTypeBearer. A Bearer token is refused under
// ProfileHAIP.
func (w *Wallet) tokenType(got string) (string, error) {
	t, err := wallet.CanonicalTokenType(got)
	if err != nil {
		return "", fmt.Errorf("walletflow: %w", err)
	}
	if t == wallet.TokenTypeBearer && w.cfg.IssuanceProfile == ProfileHAIP {
		return "", fmt.Errorf("%w: the access token isn't DPoP-bound (HAIP 1.0 §4)", ErrProfileViolation)
	}
	return t, nil
}
