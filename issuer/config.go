package issuer

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"
	"strings"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// Endpoints are this Credential Issuer's own endpoint URLs — what
// Metadata advertises. Credential is required: §12.2.4 requires
// credential_endpoint in every Credential Issuer's metadata. Mount
// CredentialHandler at it.
type Endpoints struct {
	// Credential is this issuer's Credential Endpoint (§8). Required.
	Credential fapi.URL

	// Nonce is this issuer's Nonce Endpoint (§7). Zero means this
	// issuer has no Nonce Endpoint at all — Metadata then omits
	// nonce_endpoint, and RequestNonce always fails.
	Nonce fapi.URL

	// DeferredCredential is this issuer's Deferred Credential Endpoint
	// (§9). Zero means this issuer never defers issuance — Metadata
	// then omits deferred_credential_endpoint, and
	// RequestDeferredCredential always fails.
	DeferredCredential fapi.URL

	// Notification is this issuer's Notification Endpoint (§11). Zero
	// means this issuer never accepts notifications — Metadata then
	// omits notification_endpoint, RequestCredential never sets
	// oid4vci.CredentialResponse.NotificationID, and RequestNotification
	// always fails.
	Notification fapi.URL
}

// Limits bounds durations this issuer enforces. None have an implicit
// default — New rejects a zero value, the same "no implicit defaults"
// stance FAPIgo's own server.Limits takes.
type Limits struct {
	// NonceLifetime bounds how long an issued c_nonce remains valid.
	// Required only when Endpoints.Nonce is set; at most an hour under
	// AssuranceProduction, since a c_nonce is a proof's only freshness.
	NonceLifetime time.Duration

	// CredentialOfferLifetime bounds how long a by-reference Credential
	// Offer (§4.1.3) remains fetchable. Required only when
	// CredentialOfferEndpoint is set.
	CredentialOfferLifetime time.Duration

	// DeferredIssuancePollInterval is the minimum time this issuer asks
	// a Wallet to wait before polling the Deferred Credential Endpoint
	// again (§9.2's own "interval" member, in whole seconds: a fraction
	// is rounded up). At least one second, and required only when
	// Endpoints.DeferredCredential is set.
	DeferredIssuancePollInterval time.Duration

	// DeferredTransactionLifetime bounds how long a transaction
	// RequestCredential defers stays answerable (§9). Required only
	// when Endpoints.DeferredCredential is set.
	DeferredTransactionLifetime time.Duration

	// AccessTokenLifetime bounds how long an access token
	// ExchangePreAuthorizedCode issues remains valid. Required only
	// when Dependencies.PreAuthorizedCodes is set.
	AccessTokenLifetime time.Duration

	// MaxDPoPProofAge bounds how old (relative to Now) a DPoP proof's
	// own "iat" may be before ExchangePreAuthorizedCode rejects it
	// (RFC 9449 §4.3). Required only when Dependencies.PreAuthorizedCodes
	// is set.
	MaxDPoPProofAge time.Duration

	// MaxTxCodeAttempts bounds how many consecutive incorrect tx_code
	// guesses ExchangePreAuthorizedCode tolerates against one
	// pre-authorized_code before permanently invalidating it (via
	// PreAuthorizedCodeStore.Invalidate) rather than leaving it
	// retryable forever — see PreAuthorizedCodeStore.Consume's own
	// wrongAttempts for why an unbounded retry window is a real
	// tx_code-guessing risk for a low-entropy PIN. Required only when
	// Dependencies.PreAuthorizedCodes is set — REQUIRED (must be
	// positive) in that case, the same "no implicit weakening" pattern
	// this package's own AuthorizedRequest.ClientIdentity uses. Under
	// AssuranceProduction it must be at most MaxProductionTxCodeAttempts:
	// MinProductionTxCodeLength only keeps a Transaction Code hard to
	// guess while the number of guesses is small too.
	MaxTxCodeAttempts int

	// MaxDPoPClockSkew bounds how far in the future (relative to Now) a
	// DPoP proof's own "iat" may be before ExchangePreAuthorizedCode
	// rejects it. Zero means no tolerance for a future-dated proof —
	// matching internal/dpop.VerifyRequest's own zero-value meaning, no
	// separate "required" check. Under AssuranceProduction, where this
	// issuer verifies the proof itself, it must be from 10 to 60 seconds:
	// FAPI 2.0 has a token endpoint accept a JWT up to 10 seconds in the
	// future, and refuse one more than 60.
	MaxDPoPClockSkew time.Duration

	// MaxProofAge bounds how far a jwt proof's "iat" may be from Now,
	// in either direction, when there is no Nonce Endpoint to date the
	// proof instead (OID4VCI 1.0 Appendix F.4: the key proof's creation
	// time, "as determined by either the issuance time, or a server
	// managed timestamp via the nonce claim, is within an acceptable
	// window"). Required only when Endpoints.Nonce is not set; with one,
	// the consumed c_nonce's own lifetime (NonceLifetime) is that window.
	MaxProofAge time.Duration

	// DPoPNonceLifetime bounds how long a DPoP nonce
	// ExchangePreAuthorizedCode issues (RFC 9449 §8) remains valid, for
	// any number of proofs. The Issuer hands out one current nonce and
	// replaces it once half this lifetime has passed, so a Wallet's
	// nonce is valid for at least half of it after the Wallet last
	// received it. Required only when Dependencies.DPoPNonces is a store
	// (not nil or NoDPoPNonces{}); under AssuranceProduction it must
	// then be at most 15 minutes, as fapigo/server requires of its own.
	// Five minutes suits most deployments.
	DPoPNonceLifetime time.Duration

	// NotificationLifetime, if positive, bounds how long a
	// notification_id IssueNotificationID hands out is accepted by
	// RequestNotification (NotificationRecord.ExpiresAt), so a store
	// can drop its record afterwards. Zero means a notification_id
	// never expires. A Wallet notifies once it has stored or discarded
	// the Credential (§11), so a lifetime of days is ample. It runs from
	// when the notification_id is issued, which for a deferred issuance
	// is when the transaction is resolved (IssueDeferredCredential), so
	// keep it longer than DeferredTransactionLifetime.
	NotificationLifetime time.Duration
}

// Config is this issuer's immutable configuration.
type Config struct {
	// Assurance gates how strict New's own validation is — see
	// AssuranceLevel's own doc comment. REQUIRED: New rejects the Go
	// zero value, forcing every caller to make an explicit choice
	// rather than silently getting AssuranceDevelopment's weaker
	// checks by omission.
	Assurance AssuranceLevel

	// PreAuthorizedCodeClientAuthentication is how ExchangePreAuthorizedCode
	// authenticates the client redeeming a pre-authorized_code:
	// VerifiedPreAuthorizedCode, by its Wallet Attestation, verified with
	// the DPoP proof by the Authorization Server sharing the Token
	// Endpoint, as HAIP 1.0 §4.4.1 requires ("Issuers MUST require an
	// OAuth2 Client authentication mechanism at ... Token Endpoints"), or
	// AnonymousPreAuthorizedCode{}, no client authentication, which
	// OID4VCI §6.1 allows but HAIP doesn't. REQUIRED under
	// AssuranceProduction when Dependencies.PreAuthorizedCodes is set,
	// so a production issuer chooses explicitly; nil means anonymous
	// under AssuranceDevelopment.
	PreAuthorizedCodeClientAuthentication PreAuthorizedCodeClientAuthentication

	// Issuer is this Credential Issuer's identifier (§12.2.1) — the
	// value Metadata's own credential_issuer member echoes, and an SD-JWT
	// VC's iss where Prepare sets none.
	Issuer fapi.URL

	// AllowAttestationProofType lets a Credential Configuration take the
	// attestation proof type (oid4vci.ProofTypeAttestation, Appendix
	// F.3) under AssuranceProduction, which otherwise refuses it. A key
	// attestation names no audience, and its nonce is a c_nonce anyone
	// can fetch from this issuer's Nonce Endpoint: another issuer the
	// same Wallets use can fetch one, hand it to a Wallet as its own,
	// and redeem here the key attestation the Wallet returns, in a jwt
	// proof's key_attestation header or as this proof type alike, for a
	// Credential about whoever that issuer's access token names, bound
	// to the Wallet's keys. A jwt proof names this issuer in its aud,
	// so taking only jwt proofs, with a key attestation in their
	// key_attestation header where one is required
	// (haip.RecommendedJWTKeyAttestationProofType), rules that out.
	AllowAttestationProofType bool

	// AuthorizationServers are the OAuth 2.0 Authorization Servers
	// (their issuer identifiers) this Credential Issuer relies on,
	// advertised as Metadata's authorization_servers (§12.2.4).
	// OPTIONAL: leave empty when this Credential Issuer is its own
	// Authorization Server (for example, paired with a fapigo/server at
	// the same identifier — see authorization_server.go). With more
	// than one, a Credential Offer grant may name which to use via its
	// authorization_server, which must then be one of these (§4.1.1);
	// otherwise a grant must not set it.
	AuthorizationServers []fapi.URL

	Endpoints Endpoints
	Limits    Limits

	// CredentialConfigurationsSupported describes every Credential this
	// issuer supports issuing (§12.2.4's credential_configurations_supported),
	// keyed by its Credential Configuration ID. Required — Metadata has
	// no meaningful default for this.
	CredentialConfigurationsSupported map[string]CredentialConfiguration

	// CredentialOfferEndpoint is the base URL this issuer hosts
	// by-reference Credential Offers under (§4.1.3): GetCredentialOffer's
	// caller serves each offer at this URL plus "/" plus the reference
	// CreateCredentialOffer returned. Unlike Endpoints, this is never
	// advertised in Credential Issuer Metadata — §12.2.4 defines no such
	// member, since the Wallet learns a specific offer's URL only from
	// the credential_offer_uri value itself, never from discovery. Zero
	// means this issuer never issues Credential Offers by reference;
	// CreateCredentialOffer then only supports embedding the offer by
	// value.
	CredentialOfferEndpoint fapi.URL

	// NoAttestationStatusCheck declares that this issuer deliberately
	// checks no key attestation's revocation status (its Wallet
	// Providers publish none, say). Under AssuranceProduction, New needs
	// either it or Dependencies.AttestationStatus whenever
	// Dependencies.AttestationVerifier is set.
	NoAttestationStatusCheck bool

	// RequestEncryption declares this issuer's own support for
	// encrypted Credential/Deferred Credential Requests (§10, published
	// as Metadata's own credential_request_encryption). Nil means this
	// issuer never accepts one — DecryptRequestBody then rejects any
	// request claiming to be encrypted.
	RequestEncryption *RequestEncryptionSupport

	// ResponseEncryption declares this issuer's own support for
	// encrypting Credential/Deferred Credential Responses (§10,
	// published as Metadata's own credential_response_encryption). Nil
	// means this issuer never encrypts a Response, even if a Wallet
	// asks — EncryptResponseBody then rejects the request.
	ResponseEncryption *ResponseEncryptionSupport

	// Display is this Credential Issuer's own OPTIONAL display metadata
	// (§12.2.4's top-level "display"), one entry per locale. Empty means
	// Metadata omits display entirely.
	Display []oid4vci.Display

	// BatchCredentialIssuance declares this issuer's own OPTIONAL
	// support for batch issuance (§12.2.4's "batch_credential_issuance")
	// — see oid4vci.BatchCredentialIssuance's own doc comment for what
	// setting this does and doesn't change. Nil means Metadata omits
	// batch_credential_issuance entirely.
	BatchCredentialIssuance *oid4vci.BatchCredentialIssuance
}

// Clock supplies the current time — a plain function value satisfies
// it (e.g. Clock(time.Now)), or a fixed-time fake in tests.
type Clock interface {
	Now() time.Time
}

// ClockFunc adapts a function to Clock.
type ClockFunc func() time.Time

// Now implements Clock.
func (f ClockFunc) Now() time.Time { return f() }

// SDJWTSigner configures how this issuer signs
// credential/sdjwtvc.CredentialFormat ("dc+sd-jwt") credentials.
type SDJWTSigner struct {
	Signer crypto.Signer

	// Alg is the JOSE algorithm Signer signs with. Set it from the
	// root oid4vci package's own ES256/EdDSA constants rather than a
	// bare string literal — jose.Alg itself lives in an unexported
	// internal package, so those are the only named, typo-checked
	// values an external caller has to reference.
	Alg oid4vci.JOSEAlg

	// KeyID optionally sets the JOSE "kid" header on issued credentials.
	KeyID string

	// IssuerCertificate, if set, becomes the issued credential's own
	// "x5c" header entry — see
	// credential/sdjwtvc.IssueOptions.IssuerCertificate's own doc
	// comment for why HAIP's SD-JWT VC trust model needs this (a CA-
	// signed leaf, not a self-signed one — confirmed live against the
	// OpenID Foundation conformance suite's own two checks on this
	// exact requirement). Optional: MdocSigner's own X5Chain has always
	// been required-in-practice for "mso_mdoc"; this field brings
	// "dc+sd-jwt" issuance to the same standing, added once a real
	// need (this conformance suite check) confirmed it, matching this
	// package's own "extend only when a real need arises" discipline.
	// New checks its key is Signer's, and under AssuranceProduction
	// that it isn't self-signed (HAIP 1.0 §6.1.1).
	IssuerCertificate *x509.Certificate

	// IssuerIntermediates are the CA certificates between
	// IssuerCertificate and the trust anchor, in order, the anchor left
	// out: they follow it in x5c (credential/sdjwtvc.IssueOptions.
	// IssuerIntermediates), so a Verifier holding only the anchor can
	// build the path. Requires IssuerCertificate.
	IssuerIntermediates []*x509.Certificate

	// Decoys, if set, adds decoy digests to each issued credential's
	// top-level _sd array (RFC 9901 §4.2.5: they hide how many claims
	// are selectively disclosable), as credential/sdjwtvc.IssueOptions.
	// Decoys does. Nil adds none.
	Decoys *DecoyRange

	// NestedDecoys, if set, adds decoy digests to every _sd array below
	// the top level — of an object in the claims (address, say) or in
	// a disclosed value — with a count drawn afresh for each array, as
	// credential/sdjwtvc.IssueOptions.NestedDecoys does: it hides how
	// many of each such object's claims are selectively disclosable,
	// as Decoys does for the top level's. Nil adds none, beyond any
	// credential/sdjwtvc.WithDecoys in the claims.
	NestedDecoys *DecoyRange
}

// DecoyRange is how many decoy digests SDJWTSigner.Decoys adds: a
// number from Min to Max, inclusive, drawn afresh for each credential
// from Dependencies.Random (for SDJWTSigner.NestedDecoys, for each
// nested _sd array; for MdocSigner.Decoys, for each namespace). A fixed count would let a Verifier
// subtract it from the _sd array's length and learn the real number of
// selectively disclosable claims after all. 0 <= Min <= Max, and Max
// is at least 1 and at most credential/sdjwtvc.MaxDecoys
// (credential/mdoc.MaxDecoys for MdocSigner.Decoys).
type DecoyRange struct {
	Min, Max int
}

// validate checks d, the field named field, against most, the most
// decoys its format allows.
func (d *DecoyRange) validate(field string, most int) error {
	if d == nil {
		return nil
	}
	if d.Min < 0 || d.Max < 1 || d.Min > d.Max || d.Max > most {
		return fmt.Errorf("%s must have 0 <= min <= max, 1 <= max <= %d; got min %d, max %d", field, most, d.Min, d.Max)
	}
	return nil
}

// count draws how many decoys one credential gets.
func (d *DecoyRange) count(random io.Reader) (int, error) {
	if d == nil {
		return 0, nil
	}
	n, err := rand.Int(random, big.NewInt(int64(d.Max-d.Min+1)))
	if err != nil {
		return 0, fmt.Errorf("draw decoy count: %w", err)
	}
	return d.Min + int(n.Int64()), nil
}

func (s *SDJWTSigner) validate(assurance AssuranceLevel) error {
	if s == nil {
		return fmt.Errorf("sdjwt_signer is required when a credential_configurations_supported entry uses format %q", sdjwtvc.CredentialFormat)
	}
	if s.Signer == nil {
		return fmt.Errorf("sdjwt_signer.signer is required")
	}
	if s.Alg == "" {
		return fmt.Errorf("sdjwt_signer.alg is required")
	}
	if !jose.IsSupported(s.Alg) {
		return fmt.Errorf("sdjwt_signer.alg %q is not supported", s.Alg)
	}
	if err := s.Decoys.validate("sdjwt_signer.decoys", sdjwtvc.MaxDecoys); err != nil {
		return err
	}
	if err := s.NestedDecoys.validate("sdjwt_signer.nested_decoys", sdjwtvc.MaxDecoys); err != nil {
		return err
	}
	if s.IssuerCertificate == nil {
		if len(s.IssuerIntermediates) > 0 {
			return fmt.Errorf("sdjwt_signer.issuer_intermediates needs issuer_certificate")
		}
		if assurance == AssuranceProduction {
			// HAIP 1.0 §6.1.1: "The SD-JWT VC MUST contain the credential
			// issuer's signing certificate along with a trust chain in the
			// x5c JOSE header".
			return fmt.Errorf("sdjwt_signer.issuer_certificate is required under AssuranceProduction (HAIP 1.0 §6.1.1)")
		}
		return nil
	}
	if err := checkSignerCertificate("sdjwt_signer", s.Signer, s.IssuerCertificate, s.IssuerIntermediates, assurance); err != nil {
		return err
	}
	return nil
}

// checkSignerCertificate checks a signer's certificate before any
// credential is issued with it: its key is signer's, the chain after it
// is in order without the trust anchor, and, under AssuranceProduction,
// it isn't self-signed (HAIP 1.0 §6.1.1, ISO/IEC 18013-5 §9.3.1: issued
// by a CA). A mismatch would otherwise surface as a failed Credential
// Request.
func checkSignerCertificate(field string, signer crypto.Signer, leaf *x509.Certificate, intermediates []*x509.Certificate, assurance AssuranceLevel) error {
	comparableKey, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return fmt.Errorf("%s.signer's public key type %T can't be compared with the certificate's", field, signer.Public())
	}
	if !comparableKey.Equal(leaf.PublicKey) {
		return fmt.Errorf("%s: the certificate's public key isn't the signer's", field)
	}
	if len(intermediates) > 0 {
		if err := certchain.CheckPresentedChain(leaf, intermediates); err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
	}
	if assurance == AssuranceProduction && certchain.IsSelfSigned(leaf) {
		return fmt.Errorf("%s: the certificate is self-signed, which AssuranceProduction refuses: verifiers need it issued by a CA they trust", field)
	}
	return nil
}

// MdocSigner configures how this issuer signs
// credential/mdoc.CredentialFormat ("mso_mdoc") credentials.
type MdocSigner struct {
	Signer crypto.Signer
	Alg    oid4vci.COSEAlg

	// X5Chain is the issuer's certificate (DER), followed by any
	// intermediates, leaf first — see credential/mdoc.IssueOptions.X5Chain.
	X5Chain [][]byte

	// KeyID optionally sets the COSE "kid" header on issued credentials.
	KeyID []byte

	// Decoys, if set, adds decoy digests to each namespace's
	// valueDigests in each issued credential's MSO, a count drawn
	// afresh for each namespace, on top of any the claims' own
	// credential/mdoc.Claims.Decoys asks for: the MSO goes to every
	// reader in full, and they hide how many data elements each
	// namespace really holds. Max is at most credential/mdoc.MaxDecoys,
	// which also bounds the two counts together. Nil adds none.
	Decoys *DecoyRange
}

func (s *MdocSigner) validate(assurance AssuranceLevel) error {
	if s == nil {
		return fmt.Errorf("mdoc_signer is required when a credential_configurations_supported entry uses format %q", mdoc.CredentialFormat)
	}
	if s.Signer == nil {
		return fmt.Errorf("mdoc_signer.signer is required")
	}
	if s.Alg == 0 {
		return fmt.Errorf("mdoc_signer.alg is required")
	}
	if !cose.IsSupportedSigningAlg(s.Alg) {
		return fmt.Errorf("mdoc_signer.alg %d is not supported", s.Alg)
	}
	if err := s.Decoys.validate("mdoc_signer.decoys", mdoc.MaxDecoys); err != nil {
		return err
	}
	if len(s.X5Chain) == 0 {
		return fmt.Errorf("mdoc_signer.x5chain must include at least one certificate")
	}
	chain := make([]*x509.Certificate, len(s.X5Chain))
	for i, der := range s.X5Chain {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("mdoc_signer.x5chain[%d]: %w", i, err)
		}
		chain[i] = c
	}
	return checkSignerCertificate("mdoc_signer", s.Signer, chain[0], chain[1:], assurance)
}

// AttestationVerifier resolves the trusted public key (and its JOSE
// algorithm) to verify a parsed Key Attestation JWT's signature with —
// entirely this issuer's own trust policy for which attestation
// providers it accepts, the same "resolving trust is the caller's job"
// split attestation.Verify itself draws.
//
// An error refuses the attestation as untrusted (invalid_proof, and a
// deferred transaction's re-check denies the transaction), unless it
// says trust couldn't be decided now: it wraps
// certrevocation.ErrNoCurrentCRL, or context.Canceled or
// context.DeadlineExceeded, and not certrevocation.ErrRevoked. That
// is answered with a server error (500) instead, and leaves a deferred
// transaction pending (ErrDeferredAttestationStatusUnknown).
// X5CAttestationVerifier reports any error from its Revocation other
// than certrevocation.ErrRevoked that way.
type AttestationVerifier interface {
	ResolveAttestationKey(ctx context.Context, a attestation.KeyAttestation) (crypto.PublicKey, oid4vci.JOSEAlg, error)
}

// ProofBindingKeyResolver resolves a jwt-type key proof's own "kid" or
// "x5c" JOSE header (Appendix F.1) to the public key it identifies,
// and the JOSE algorithm that key is trusted to sign with — entirely
// this issuer's own trust policy for what either one means (a DID URL
// into a DID Document for kid; an x5c chain's own trust anchor for
// x5c; a private key registry; ...), the same "resolving trust is the
// caller's job" split AttestationVerifier already draws for a Key
// Attestation's own kid/x5c/trust_chain. header is the proof JWT's raw
// decoded JOSE header (jose.DecodeUnverified's own return shape) —
// exactly one of its "kid"/"x5c" entries is present, whichever this
// proof actually conveys.
//
// The algorithm is returned by this resolver, not read back out of
// header's own "alg" member by the caller, matching every sibling
// resolver in this repo (AttestationVerifier, verifier's own
// SDJWTVCIssuerKeyResolver/MdocIssuerKeyResolver): an algorithm must
// travel with the key it was actually vetted for, never be picked
// from the same untrusted header a resolver only just finished
// inspecting. Before this returned an algorithm, callers had no
// choice but to trust header's own "alg" outright (bounded only by the
// configured ProofSigningAlgValuesSupported allow-list) — harmless
// today only because internal/jose's own type-safe per-algorithm
// dispatch happens to reject any key whose type doesn't match the
// claimed algorithm, not because the resolver contract made it safe.
type ProofBindingKeyResolver interface {
	ResolveProofBindingKey(ctx context.Context, header map[string]any) (crypto.PublicKey, oid4vci.JOSEAlg, error)
}

// CredentialDPoPNonceIssuer issues a DPoP nonce the Credential Endpoint
// will accept. fapigo/resource's *Verifier implements it
// (IssueDPoPNonce, FAPIgo v0.60.0 or later), returning "" when it
// doesn't use DPoP nonces.
type CredentialDPoPNonceIssuer interface {
	IssueDPoPNonce(ctx context.Context) (string, error)
}

// Dependencies are this issuer's external collaborators.
//
// Credential Issuers may share a backend for Nonces, PreAuthorizedCodes,
// DeferredTransactions and Notifications: every record an Issuer saves
// there carries its Config.Issuer as its Owner, and each honours only
// its own, so none redeems another's pre-authorized code or c_nonce, or
// answers another's transaction_id or notification_id. A store must
// persist Owner for that to hold. CredentialOffers, DPoPNonces and
// DPoPReplay records aren't scoped that way: an offer's reference is an
// unguessable lookup key whose offer names its Credential Issuer, and
// DPoP nonces and jti records are shared freshness state.
type Dependencies struct {
	// Nonces persists issued c_nonce values. Required when
	// Config.Endpoints.Nonce is set.
	Nonces NonceStore

	// CredentialDPoPNonces, if set, issues the DPoP nonce RequestNonce
	// returns alongside the c_nonce, for the Nonce Response's DPoP-Nonce
	// header (§7.2: "The Credential Issuer MAY provide a DPoP nonce"),
	// which the Wallet then uses at the Credential Endpoint. Pass the
	// Credential Endpoint's own fapigo/resource.Verifier: the nonce has
	// to come from the store that Verifier checks, or the Credential
	// Request carrying it is challenged anyway. Not DPoPNonces, which is
	// the Token Endpoint's, for ExchangePreAuthorizedCode. Nil sends no
	// DPoP nonce.
	CredentialDPoPNonces CredentialDPoPNonceIssuer

	// Clock supplies the current time.
	Clock Clock

	// Random is the source of cryptographically secure randomness for
	// generating c_nonce values — ordinarily crypto/rand.Reader.
	Random io.Reader

	// SDJWTSigner signs issued dc+sd-jwt credentials. Required when any
	// Config.CredentialConfigurationsSupported entry uses
	// credential/sdjwtvc.CredentialFormat.
	SDJWTSigner *SDJWTSigner

	// MdocSigner signs issued mso_mdoc credentials. Required when any
	// Config.CredentialConfigurationsSupported entry uses
	// credential/mdoc.CredentialFormat.
	MdocSigner *MdocSigner

	// AttestationVerifier resolves the trust key for a Key Attestation
	// JWT's signature. Required when any
	// Config.CredentialConfigurationsSupported entry supports the
	// "attestation" proof type. X5CAttestationVerifier verifies HAIP's
	// x5c; with anchors that certify more than one Wallet Provider, set
	// its IssuerBinding, or any of them can attest in another's name.
	//
	// An attestation-type proof is signed by the attester, not by the
	// keys it attests, and carries no audience: its only freshness is
	// the c_nonce it contains, which anyone can fetch, so it isn't bound
	// to this issuer either (see Config.AllowAttestationProofType).
	// Without a Nonce Endpoint there's no c_nonce, so a key attestation
	// a Wallet sent to one issuer can be replayed to another until it
	// expires. Under AssuranceProduction, New therefore requires
	// Config.AllowAttestationProofType and Config.Endpoints.Nonce
	// whenever the attestation proof type is supported.
	AttestationVerifier AttestationVerifier

	// AttestationStatus, if set, checks each key attestation — an
	// attestation-type proof's, or a jwt proof's key_attestation header —
	// for revocation (its "status" claim, OID4VCI Appendix D.1) after its
	// signature verifies, and refuses the proof when it returns an
	// error; IssueDeferredCredential checks a deferred request's again.
	// It's given the attestation's signer, to bind the Status List
	// Token's signer to (see AttestationStatusChecker). Without it, a key attestation its Wallet
	// Provider has since revoked is accepted until it expires: under
	// AssuranceProduction, New requires it whenever AttestationVerifier
	// is set, unless Config.NoAttestationStatusCheck says the issuer
	// deliberately checks none.
	AttestationStatus AttestationStatusChecker

	// ProofBindingKeys resolves a jwt-type key proof's own "kid" or
	// "x5c" header to a public key (Appendix F.1). Optional: a jwt-type
	// proof conveying "jwk" (the common case) never needs it; required
	// only when a Credential Request actually presents a kid- or
	// x5c-conveyed proof, which is otherwise rejected as unsupported.
	ProofBindingKeys ProofBindingKeyResolver

	// CredentialOffers persists Credential Offers issued by reference
	// (§4.1.3). Required when Config.CredentialOfferEndpoint is set.
	CredentialOffers CredentialOfferStore

	// DeferredTransactions persists Deferred Issuance transactions
	// (§9). Required when Config.Endpoints.DeferredCredential is set.
	DeferredTransactions DeferredTransactionStore

	// Notifications persists notification_id values issued to Wallets
	// (§11). Required when Config.Endpoints.Notification is set.
	Notifications NotificationStore

	// NotificationHandler reacts to a validated Notification Request's
	// event — entirely this deployment's own business logic; this
	// package has none of its own (§11: "These events enable the
	// Credential Issuer to take subsequent actions after issuance").
	// OPTIONAL even when Config.Endpoints.Notification is set:
	// RequestNotification still succeeds with a nil NotificationHandler,
	// since a Wallet is never guaranteed to send a notification at all.
	NotificationHandler NotificationHandler

	// PreAuthorizedCodes persists pre-authorized_code values issued as
	// part of a Credential Offer and lets ExchangePreAuthorizedCode
	// redeem one exactly once. Setting this is what opts an Issuer into
	// the Pre-Authorized Code Flow's own Token Request/Response
	// (§6.1/§6.2) at all — there's no Config.Endpoints field for it,
	// since (unlike the Credential/Nonce/Deferred Credential/Notification
	// Endpoints) the Token Endpoint itself belongs to whichever
	// Authorization Server this issuer is paired with, not to this
	// package. Required, along with DPoPReplay and AccessTokens below,
	// exactly when a caller wants to call ExchangePreAuthorizedCode.
	PreAuthorizedCodes PreAuthorizedCodeStore

	// DPoPReplay detects DPoP proof replay by "jti" for
	// ExchangePreAuthorizedCode's own Token Request (RFC 9449 §11.1).
	// Required when PreAuthorizedCodes is set.
	DPoPReplay DPoPReplayChecker

	// AccessTokens mints the access token ExchangePreAuthorizedCode
	// returns on success. Required when PreAuthorizedCodes is set,
	// unless PreAuthorizedCodeClientAuthentication is
	// VerifiedPreAuthorizedCode: an Authorization Server that issues the
	// token itself redeems codes with RedeemPreAuthorizedCode instead.
	AccessTokens AccessTokenIssuer

	// DPoPNonces enables RFC 9449 §8's own DPoP nonce-challenge flow for
	// ExchangePreAuthorizedCode — see DPoPNonceStore's own doc comment.
	// Config.Limits.DPoPNonceLifetime is required whenever this is a
	// store. NoDPoPNonces{} declines nonces, as nil does.
	//
	// Under AssuranceDevelopment, nil disables nonces entirely. Under
	// AssuranceProduction, New refuses nil when PreAuthorizedCodes is
	// set and PreAuthorizedCodeClientAuthentication isn't
	// VerifiedPreAuthorizedCode, where this issuer verifies the Token
	// Request's DPoP proof and issues the access token itself: pass a
	// durable store that declares StoreAssurance (Durable; Lookup is a
	// plain read, so AtomicConsume isn't needed) and passes
	// issuertest.TestDPoPNonceStoreContract, or NoDPoPNonces{} to
	// decline. Under VerifiedPreAuthorizedCode the Authorization Server
	// verifies the proof, and its own nonces apply.
	DPoPNonces DPoPNonceStore

	// Audit records the outcome of every ExchangePreAuthorizedCode/
	// RequestCredential/RequestDeferredCredential call — see
	// AuditSink's own doc comment. Optional under AssuranceDevelopment
	// (nil disables auditing entirely); REQUIRED under
	// AssuranceProduction, the same requirement FAPIgo's own
	// server.AssuranceProduction places on server.Dependencies.Audit.
	Audit AuditSink
}

// Issuer is this Credential Issuer's own role implementation — the
// OID4VCgo analog of fapigo/server.Server, built on top of it.
type Issuer struct {
	cfg  Config
	deps Dependencies

	// dpopNonces is the DPoP nonce this Issuer currently hands out (see
	// currentDPoPNonce).
	dpopNonces dpopNonceRotator

	// preAuthorizedOwner, deferredOwner and notificationOwner record
	// whether each store has kept a saved record's Owner
	// (checkOwnerKept).
	preAuthorizedOwner, deferredOwner, notificationOwner ownerReadBack
}

// New validates cfg and deps and returns a ready-to-use Issuer.
func New(cfg Config, deps Dependencies) (*Issuer, error) {
	var err error
	if cfg.PreAuthorizedCodeClientAuthentication, err = normalizeClientAuthentication(cfg.PreAuthorizedCodeClientAuthentication); err != nil {
		return nil, err
	}
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	if err := validateOptionalEndpointDependencies(cfg, deps); err != nil {
		return nil, err
	}
	if err := validatePreAuthorizedCodeDependencies(cfg, deps); err != nil {
		return nil, err
	}
	// declinedDPoPNonces is kept for checkProductionAssurance, which
	// tells a decline apart from nil; every other nonce check tests
	// deps.DPoPNonces against nil.
	declinedDPoPNonces := dpopNoncesDeclined(deps.DPoPNonces)
	if declinedDPoPNonces {
		deps.DPoPNonces = nil
	}
	if deps.DPoPNonces != nil && cfg.Limits.DPoPNonceLifetime <= 0 {
		return nil, fmt.Errorf("issuer: config: limits.dpop_nonce_lifetime must be positive when dependencies.dpop_nonces is set")
	}
	if deps.Clock == nil {
		return nil, fmt.Errorf("issuer: dependencies: clock is required")
	}
	if deps.Random == nil {
		return nil, fmt.Errorf("issuer: dependencies: random is required")
	}

	if err := validateSignerDependencies(cfg, deps); err != nil {
		return nil, fmt.Errorf("issuer: dependencies: %w", err)
	}
	if err := validateAttestationVerifier(deps.AttestationVerifier); err != nil {
		return nil, fmt.Errorf("issuer: dependencies: %w", err)
	}
	if err := validateProofBindingKeys(deps.ProofBindingKeys); err != nil {
		return nil, fmt.Errorf("issuer: dependencies: %w", err)
	}

	if err := cfg.RequestEncryption.validate(); err != nil {
		return nil, fmt.Errorf("issuer: config: request_encryption: %w", err)
	}
	if err := cfg.ResponseEncryption.validate(); err != nil {
		return nil, fmt.Errorf("issuer: config: response_encryption: %w", err)
	}
	// §8.2: "Credential Request encryption MUST be used if the
	// credential_response_encryption parameter is included", so an
	// issuer offering encrypted responses must take encrypted requests.
	if cfg.ResponseEncryption != nil && cfg.RequestEncryption == nil {
		return nil, fmt.Errorf("issuer: config: response_encryption needs request_encryption (OpenID4VCI §8.2: an encrypted response is asked for in an encrypted request)")
	}

	if cfg.Assurance == AssuranceProduction {
		if err := checkProductionAssurance(cfg, deps, declinedDPoPNonces); err != nil {
			return nil, fmt.Errorf("issuer: %w", err)
		}
	}

	return &Issuer{cfg: cfg, deps: deps}, nil
}

// validateConfig checks cfg's own self-contained fields — no
// Dependencies involved — split out of New purely to keep it under the
// linter's own cognitive complexity ceiling.
func validateConfig(cfg Config) error {
	if cfg.Assurance != AssuranceDevelopment && cfg.Assurance != AssuranceProduction {
		return fmt.Errorf("issuer: config: assurance level is invalid")
	}
	if cfg.Issuer.IsZero() {
		return fmt.Errorf("issuer: config: issuer is required")
	}
	// OpenID4VCI §12.2.1: an identifier with "no query or fragment
	// components". Wallets build the metadata URL from it (§12.2.2),
	// which a query would land in the middle of.
	if u := cfg.Issuer.URL(); u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return fmt.Errorf("issuer: config: issuer must have no query or fragment (OpenID4VCI §12.2.1)")
	}
	if err := validateAuthorizationServers(cfg.AuthorizationServers); err != nil {
		return err
	}
	if cfg.Endpoints.Credential.IsZero() {
		return fmt.Errorf("issuer: config: endpoints.credential is required")
	}
	if len(cfg.CredentialConfigurationsSupported) == 0 {
		return fmt.Errorf("issuer: config: credential_configurations_supported must not be empty")
	}
	for id, c := range cfg.CredentialConfigurationsSupported {
		if err := c.validate(); err != nil {
			return fmt.Errorf("issuer: config: credential_configurations_supported[%q]: %w", id, err)
		}
	}
	if err := oid4vci.ValidateDisplays(cfg.Display); err != nil {
		return fmt.Errorf("issuer: config: %w", err)
	}
	if cfg.BatchCredentialIssuance != nil {
		if err := cfg.BatchCredentialIssuance.Validate(); err != nil {
			return fmt.Errorf("issuer: config: batch_credential_issuance: %w", err)
		}
	}
	return nil
}

// validateOptionalEndpointDependencies checks that Dependencies carries
// whichever store each optional endpoint (Nonce/CredentialOffer/
// DeferredCredential/Notification) needs once cfg actually enables it
// — split out of New purely to keep it under the linter's own
// cognitive complexity ceiling. Each endpoint's own pair of checks is
// further split into its own helper for the same reason: three
// same-shaped "if enabled { check limit; check dependency }" blocks
// side by side were still enough nesting to trip the same ceiling.
func validateOptionalEndpointDependencies(cfg Config, deps Dependencies) error {
	if err := validateNonceEndpointDependencies(cfg, deps); err != nil {
		return err
	}
	if err := validateCredentialOfferEndpointDependencies(cfg, deps); err != nil {
		return err
	}
	if err := validateDeferredCredentialEndpointDependencies(cfg, deps); err != nil {
		return err
	}
	if !cfg.Endpoints.Notification.IsZero() && deps.Notifications == nil {
		return fmt.Errorf("issuer: dependencies: notifications is required when endpoints.notification is set")
	}
	if cfg.Limits.NotificationLifetime < 0 {
		return fmt.Errorf("issuer: config: limits.notification_lifetime must not be negative")
	}
	return nil
}

func validateNonceEndpointDependencies(cfg Config, deps Dependencies) error {
	if cfg.Endpoints.Nonce.IsZero() {
		if cfg.Limits.MaxProofAge <= 0 {
			return fmt.Errorf("issuer: config: limits.max_proof_age must be positive when endpoints.nonce is not set")
		}
		return nil
	}
	if cfg.Limits.NonceLifetime <= 0 {
		return fmt.Errorf("issuer: config: limits.nonce_lifetime must be positive when endpoints.nonce is set")
	}
	if deps.Nonces == nil {
		return fmt.Errorf("issuer: dependencies: nonces is required when endpoints.nonce is set")
	}
	return nil
}

func validateCredentialOfferEndpointDependencies(cfg Config, deps Dependencies) error {
	if cfg.CredentialOfferEndpoint.IsZero() {
		return nil
	}
	if cfg.Limits.CredentialOfferLifetime <= 0 {
		return fmt.Errorf("issuer: config: limits.credential_offer_lifetime must be positive when credential_offer_endpoint is set")
	}
	if deps.CredentialOffers == nil {
		return fmt.Errorf("issuer: dependencies: credential_offers is required when credential_offer_endpoint is set")
	}
	return nil
}

func validateDeferredCredentialEndpointDependencies(cfg Config, deps Dependencies) error {
	if cfg.Endpoints.DeferredCredential.IsZero() {
		return nil
	}
	if cfg.Limits.DeferredIssuancePollInterval < time.Second {
		return fmt.Errorf("issuer: config: limits.deferred_issuance_poll_interval must be at least one second when endpoints.deferred_credential is set")
	}
	if cfg.Limits.DeferredTransactionLifetime <= 0 {
		return fmt.Errorf("issuer: config: limits.deferred_transaction_lifetime must be positive when endpoints.deferred_credential is set")
	}
	if deps.DeferredTransactions == nil {
		return fmt.Errorf("issuer: dependencies: deferred_transactions is required when endpoints.deferred_credential is set")
	}
	return nil
}

// validatePreAuthorizedCodeDependencies checks the group of
// Config/Dependencies fields the pre-authorized_code grant needs once
// deps.PreAuthorizedCodes is set — split out of New purely to keep it
// under the linter's own cognitive complexity ceiling.
func validatePreAuthorizedCodeDependencies(cfg Config, deps Dependencies) error {
	if deps.PreAuthorizedCodes == nil {
		return nil
	}
	if cfg.Limits.AccessTokenLifetime <= 0 {
		return fmt.Errorf("issuer: config: limits.access_token_lifetime must be positive when dependencies.pre_authorized_codes is set")
	}
	if cfg.Limits.MaxTxCodeAttempts <= 0 {
		return fmt.Errorf("issuer: config: limits.max_tx_code_attempts must be positive when dependencies.pre_authorized_codes is set")
	}
	// The DPoP proof is the Authorization Server's to verify under
	// VerifiedPreAuthorizedCode, and this issuer's otherwise; so is the
	// access token, if it issues it (RedeemPreAuthorizedCode).
	if _, ok := cfg.PreAuthorizedCodeClientAuthentication.(VerifiedPreAuthorizedCode); ok {
		return nil
	}
	if deps.AccessTokens == nil {
		return fmt.Errorf("issuer: dependencies: access_tokens is required when dependencies.pre_authorized_codes is set")
	}
	if cfg.Limits.MaxDPoPProofAge <= 0 {
		return fmt.Errorf("issuer: config: limits.max_dpop_proof_age must be positive when dependencies.pre_authorized_codes is set")
	}
	// Unlike MaxDPoPProofAge, zero is MaxDPoPClockSkew's own legitimate
	// strictest value (see its own doc comment) — but a negative one
	// isn't just meaningless, it's actively destructive:
	// internal/dpop.Verify checks iat.After(Now.Add(MaxClockSkew)), so
	// a negative skew moves that threshold into the past and rejects
	// every fresh proof (iat ≈ Now) as "in the future," a near-total
	// denial of service on ExchangePreAuthorizedCode — found in a
	// repo-wide integrator-misconfiguration scan, confirmed with a
	// runnable check. Every sibling freshness-bound duration in this
	// repo (MaxDPoPProofAge above, sdjwtvc.KeyBindingCheck.MaxAge)
	// already rejects a non-positive value outright; this is the one
	// exception, because unlike those, zero itself is meaningful here.
	if cfg.Limits.MaxDPoPClockSkew < 0 {
		return fmt.Errorf("issuer: config: limits.max_dpop_clock_skew must not be negative when dependencies.pre_authorized_codes is set")
	}
	if deps.DPoPReplay == nil {
		return fmt.Errorf("issuer: dependencies: dpop_replay is required when dependencies.pre_authorized_codes is set")
	}
	return nil
}

// validateSignerDependencies checks that Dependencies carries whichever
// of SDJWTSigner/MdocSigner/AttestationVerifier the configured
// credentials actually need — each is otherwise optional, so an issuer
// that only issues one format doesn't have to configure the other.
func validateSignerDependencies(cfg Config, deps Dependencies) error {
	for id, c := range cfg.CredentialConfigurationsSupported {
		switch c.Format {
		case sdjwtvc.CredentialFormat:
			if err := deps.SDJWTSigner.validate(cfg.Assurance); err != nil {
				return fmt.Errorf("credential_configurations_supported[%q]: %w", id, err)
			}
		case mdoc.CredentialFormat:
			if err := deps.MdocSigner.validate(cfg.Assurance); err != nil {
				return fmt.Errorf("credential_configurations_supported[%q]: %w", id, err)
			}
		default:
			return fmt.Errorf("credential_configurations_supported[%q]: format %q isn't one this issuer issues (%q, %q)", id, c.Format, sdjwtvc.CredentialFormat, mdoc.CredentialFormat)
		}
		if err := checkIssuable(c, deps); err != nil {
			return fmt.Errorf("credential_configurations_supported[%q]: %w", id, err)
		}
		if jwt, ok := c.ProofTypesSupported[oid4vci.ProofTypeJWT]; ok && jwt.KeyAttestationsRequired != nil && deps.AttestationVerifier == nil {
			// A jwt proof's key_attestation header (Appendix F.1) is
			// verified by AttestationVerifier.
			return fmt.Errorf("credential_configurations_supported[%q]: attestation_verifier is required when the %q proof type has key_attestations_required", id, oid4vci.ProofTypeJWT)
		}
		if _, ok := c.ProofTypesSupported[oid4vci.ProofTypeAttestation]; ok && deps.AttestationVerifier == nil {
			return fmt.Errorf("credential_configurations_supported[%q]: attestation_verifier is required when proof_types_supported includes %q", id, oid4vci.ProofTypeAttestation)
		}
	}
	return nil
}

// validateAuthorizationServers rejects an unset or repeated
// authorization_servers entry.
func validateAuthorizationServers(servers []fapi.URL) error {
	seen := make(map[string]bool, len(servers))
	for i, u := range servers {
		if u.IsZero() {
			return fmt.Errorf("issuer: config: authorization_servers[%d] is unset", i)
		}
		if seen[u.String()] {
			return fmt.Errorf("issuer: config: authorization_servers lists %s more than once", u)
		}
		seen[u.String()] = true
	}
	return nil
}

// normalizeClientAuthentication is a, a pointer to either choice taken
// as the choice itself: every check of it (redemption, production
// assurance, haip.ValidateIssuerConfig) asks for the value type, and
// &VerifiedPreAuthorizedCode{} would otherwise redeem codes with no
// client authentication while passing them all.
func normalizeClientAuthentication(a PreAuthorizedCodeClientAuthentication) (PreAuthorizedCodeClientAuthentication, error) {
	switch v := a.(type) {
	case *VerifiedPreAuthorizedCode:
		if v == nil {
			return nil, fmt.Errorf("issuer: config: pre_authorized_code_client_authentication is a nil *VerifiedPreAuthorizedCode")
		}
		return VerifiedPreAuthorizedCode{}, nil
	case *AnonymousPreAuthorizedCode:
		if v == nil {
			return nil, fmt.Errorf("issuer: config: pre_authorized_code_client_authentication is a nil *AnonymousPreAuthorizedCode")
		}
		return AnonymousPreAuthorizedCode{}, nil
	}
	return a, nil
}

// checkIssuable refuses a configuration this issuer advertises but can
// never issue, or would issue as something other than it says:
//   - one binding no key (every request for it is refused: credentials
//     here are always bound), or by a method its format doesn't use
//     (§12.2.4: jwk for an SD-JWT VC, cose_key for an mdoc);
//   - credential_signing_alg_values_supported not listing the signer's
//     algorithm, so Wallets would expect another;
//   - a signer certificate not valid now, whose credentials every
//     Verifier would refuse.
func checkIssuable(c CredentialConfiguration, deps Dependencies) error {
	if err := checkBindingMethods(c); err != nil {
		return err
	}
	var now time.Time
	if deps.Clock != nil {
		now = deps.Clock.Now()
	}
	leaf, err := signerLeaf(c, deps)
	if err != nil {
		return err
	}
	if leaf != nil && !now.IsZero() && (now.Before(leaf.NotBefore) || now.After(leaf.NotAfter)) {
		return fmt.Errorf("the signer's certificate isn't valid now (%s to %s)", leaf.NotBefore.Format(time.RFC3339), leaf.NotAfter.Format(time.RFC3339))
	}
	return nil
}

// checkBindingMethods refuses a configuration binding no key, or by a
// method its format doesn't use.
func checkBindingMethods(c CredentialConfiguration) error {
	if len(c.CryptographicBindingMethodsSupported) == 0 {
		return errors.New("cryptographic_binding_methods_supported is empty: this issuer issues only key-bound credentials")
	}
	for _, m := range c.CryptographicBindingMethodsSupported {
		switch {
		case c.Format == sdjwtvc.CredentialFormat && (m == "jwk" || strings.HasPrefix(m, "did:")):
		case c.Format == mdoc.CredentialFormat && m == "cose_key":
		default:
			return fmt.Errorf("cryptographic_binding_methods_supported %q isn't a binding method for %q", m, c.Format)
		}
	}
	return nil
}

// signerLeaf refuses a configuration whose
// credential_signing_alg_values_supported doesn't list its format's
// signer's algorithm, and returns that signer's certificate, if any.
func signerLeaf(c CredentialConfiguration, deps Dependencies) (*x509.Certificate, error) {
	var leaf *x509.Certificate
	switch c.Format {
	case sdjwtvc.CredentialFormat:
		if algs := c.CredentialSigningAlgValuesSupported; len(algs) > 0 && !slices.Contains(algs, string(deps.SDJWTSigner.Alg)) {
			return nil, fmt.Errorf("credential_signing_alg_values_supported %v doesn't list the signer's %q", algs, deps.SDJWTSigner.Alg)
		}
		leaf = deps.SDJWTSigner.IssuerCertificate
	case mdoc.CredentialFormat:
		if algs := c.CredentialSigningAlgValuesSupportedCOSE; len(algs) > 0 && !slices.Contains(algs, deps.MdocSigner.Alg) {
			return nil, fmt.Errorf("credential_signing_alg_values_supported %v doesn't list the signer's %d", algs, deps.MdocSigner.Alg)
		}
		if len(deps.MdocSigner.X5Chain) > 0 {
			leaf, _ = x509.ParseCertificate(deps.MdocSigner.X5Chain[0])
		}
	}
	return leaf, nil
}
