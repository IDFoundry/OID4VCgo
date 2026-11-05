package statuslist

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwtdate"
	"github.com/idfoundry/oid4vcgo/internal/strictjson"
)

// TokenTyp is the required JOSE "typ" header of a Status List Token in
// JWT format (draft-14 §5.1).
const TokenTyp = "statuslist+jwt" //nolint:gosec // a JOSE "typ" header value, not a credential

// TokenMediaType is the media type a Status List Token in JWT format
// is served and requested as (draft-14 §8.1, §8.2).
const TokenMediaType = "application/statuslist+jwt"

// TokenClaims is a Status List Token's JWT Claims Set (draft-14 §5.1).
type TokenClaims struct {
	Sub        string // REQUIRED: the URI this Status List Token is served at
	Iat        int64  // REQUIRED
	Exp        *int64
	TTL        *int64 // seconds
	StatusList StatusList

	Additional map[string]any
}

// IssueToken signs claims into a Status List Token in JWT format
// (draft-14 §5.1). keyID sets the JOSE "kid" header, if non-empty.
func IssueToken(signer crypto.Signer, alg oid4vci.JOSEAlg, claims TokenClaims, keyID string) (string, error) {
	header := map[string]any{"typ": TokenTyp}
	if keyID != "" {
		header["kid"] = keyID
	}
	return issueToken(signer, alg, claims, header)
}

// issueToken signs claims into a Status List Token in JWT format with
// the given JOSE header.
func issueToken(signer crypto.Signer, alg jose.Alg, claims TokenClaims, header map[string]any) (string, error) {
	if err := claims.validate(); err != nil {
		return "", err
	}
	return signToken(signer, alg, claims, header)
}

// signToken is issueToken without its checks on claims.
func signToken(signer crypto.Signer, alg jose.Alg, claims TokenClaims, header map[string]any) (string, error) {
	payload := make(map[string]any, len(claims.Additional)+5)
	for k, v := range claims.Additional {
		payload[k] = v
	}
	payload["sub"] = claims.Sub
	payload["iat"] = claims.Iat
	if claims.Exp != nil {
		payload["exp"] = *claims.Exp
	}
	if claims.TTL != nil {
		payload["ttl"] = *claims.TTL
	}
	payload["status_list"] = claims.StatusList

	raw, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("statuslist: marshal token claims: %w", err)
	}

	return jose.Sign(alg, signer, header, raw)
}

// VerifyOptions configures VerifyToken.
type VerifyOptions struct {
	// Now is the time the token's iat, nbf and exp, and its signer's
	// certificates (CheckX5C, CheckCWTX5Chain), are checked at, read
	// once per check; it defaults to time.Now.
	Now func() time.Time

	// MaxAge, if set, refuses a token issued longer ago (its iat): a
	// signed list from before a revocation stays valid until its exp,
	// so anyone who can serve bytes at the status URI (a cache, a
	// mirror) could replay it until then. Zero leaves freshness to exp
	// for a token that has one, and refuses a token without exp issued
	// more than DefaultMaxAgeWithoutExp ago. Negative is an error, not
	// "no limit".
	MaxAge time.Duration

	// MaxClockSkew is how far in the future a token's iat and nbf may
	// be; zero means a minute.
	MaxClockSkew time.Duration

	// RequireExp refuses a token without exp. draft-14 leaves exp
	// optional; ISO/IEC 18013-5 §12.3.6.3 has it present in an mdoc's
	// revocation list ("The exp claim shall be present").
	// Checker.Check sets it for the CWT form.
	RequireExp bool

	// X5ChainProtectedOnly has CheckCWTX5Chain read the signer's
	// x5chain from the protected header alone, as ISO/IEC 18013-5
	// §12.3.6.3 has an mdoc's revocation list carry it. Unset, an
	// unprotected x5chain is accepted too, as RFC 9360 allows.
	// Checker.Check sets it for the CWT form.
	X5ChainProtectedOnly bool

	// LeafPolicy, used by CheckX5C/CheckCWTX5Chain only, is run on the
	// token signer's chain-verified certificate and its verified paths,
	// and can refuse it. Chain validation accepts any certificate under
	// the roots, whatever its role, and nothing ties the status list's
	// signer to the Referenced Token's issuer: use it to require that
	// tie, or the signer's role (an extended key usage, a certificate
	// policy), where the roots are shared.
	LeafPolicy func(leaf *x509.Certificate, chains [][]*x509.Certificate) error

	// Revocation, used by CheckX5C/CheckCWTX5Chain only, checks the
	// token signer's certificate chain for revocation: the token is
	// accepted only through a verified path LeafPolicy approves and
	// Revocation passes, and one signed by a revoked certificate is
	// refused with an error wrapping certrevocation.ErrRevoked.
	// Checker.Check asks it with its own context, CheckX5C and
	// CheckCWTX5Chain with context.Background(). nil checks no
	// revocation; see certrevocation.
	Revocation certrevocation.Checker

	// Issuer, if set, is the Referenced Token's issuer: its iss, or
	// the URI its signing certificate names. CheckX5C then refuses a
	// Status List Token another issuer under the same Roots signed: its
	// signer must hold IssuerKey, the key that signed the Referenced
	// Token (the same-key arrangement draft-ietf-oauth-status-list §11.3
	// recommends where the Issuer is its own Status Issuer), or have a
	// certificate naming Issuer (the rule certchain.CheckIssuerName
	// applies). It also refuses a token whose own iss claim is another
	// issuer's. For the CWT form (an mdoc's), leave it empty: an mdoc
	// issuer has no such name, and its status lists are bound by Roots,
	// which the MSO's status reference can name.
	//
	// With neither Issuer nor IssuerKey set, CheckX5C, CheckCWTX5Chain
	// and Checker refuse the check unless UnboundSigner decides the
	// signer.
	Issuer string

	// IssuerKey is the public key that signed the Referenced Token: a
	// Status List Token signed with the same key is the issuer's own,
	// whatever names the certificates carry. Set without Issuer, it's
	// the only signer CheckX5C accepts, as for a Referenced Token with
	// no issuer name (draft-ietf-oauth-status-list §11.3's same-key
	// arrangement); a separate Status Issuer is then the caller's
	// LeafPolicy to accept.
	IssuerKey crypto.PublicKey

	// UnboundSigner decides the token's signer, for CheckX5C,
	// CheckCWTX5Chain and Checker, when neither Issuer nor IssuerKey
	// binds it to the Referenced Token's issuer: run, as LeafPolicy is
	// and before it, on a signer that chains to the roots, nil to accept
	// it, an error to refuse. Nil refuses every such check, since any CA
	// under the roots could otherwise sign a list that says another
	// issuer's credential is valid. Bind it here where the issuer is
	// known some other way — an mdoc's, through
	// credential/mdoc.StatusTrust's LeafPolicy. AnyListSigner accepts
	// every signer under the roots: set it only where every CA they
	// anchor may decide every Referenced Token's status — roots of one
	// issuer alone, or the one certificate an MSO's status names.
	UnboundSigner func(leaf *x509.Certificate, chains [][]*x509.Certificate) error

	// MaxTokenBytes is the largest token VerifyToken, VerifyTokenCWT,
	// CheckX5C and CheckCWTX5Chain parse; zero means
	// DefaultMaxTokenBytes. Checker uses its Fetcher's MaxBytes when this
	// is zero. Over MaxTokenBytesLimit is an error.
	MaxTokenBytes int
}

// AnyListSigner is a VerifyOptions.UnboundSigner accepting every Status
// List Token signer under the roots.
func AnyListSigner(*x509.Certificate, [][]*x509.Certificate) error { return nil }

// errUnboundSigner refuses a check that nothing ties the token's signer
// to the Referenced Token's issuer for.
var errUnboundSigner = errors.New("statuslist: the token's signer can't be bound to the referenced token's issuer: set VerifyOptions.Issuer or IssuerKey, or UnboundSigner (AnyListSigner accepts every signer under the roots)")

// signerPolicy is the policy a token's chain-verified signer must
// meet: LeafPolicy, after UnboundSigner when neither Issuer nor
// IssuerKey binds the signer, or an error when nothing does.
func (o VerifyOptions) signerPolicy() (func(*x509.Certificate, [][]*x509.Certificate) error, error) {
	if o.Issuer != "" || o.IssuerKey != nil {
		return o.LeafPolicy, nil
	}
	if o.UnboundSigner == nil {
		return nil, errUnboundSigner
	}
	return certchain.BothPolicies(o.UnboundSigner, o.LeafPolicy), nil
}

// DefaultMaxTokenBytes is the largest Status List Token this package
// parses unless VerifyOptions.MaxTokenBytes says otherwise: 1 MiB. A
// token embeds a population-sized compressed bit array, and is fetched
// from a URI a credential names, which may point at a compromised or
// malicious issuer. A 1-bit list of 8 million entries, 5% of them
// revoked at random, makes a JWT of about 600 KiB; one of 16 million
// doesn't fit, so a Relying Party that reads lists that large raises
// MaxTokenBytes (and its Fetcher's MaxBytes).
const DefaultMaxTokenBytes = 1 << 20

// MaxTokenBytesLimit is the most VerifyOptions.MaxTokenBytes may be: 32
// MiB, past what the 16 MiB a list may decompress to
// (maxDecompressedSize) needs, base64url-encoded in a JWT.
const MaxTokenBytesLimit = 32 << 20

// maxTokenBytes is o.MaxTokenBytes's effective value.
func (o VerifyOptions) maxTokenBytes() (int, error) {
	switch {
	case o.MaxTokenBytes < 0 || o.MaxTokenBytes > MaxTokenBytesLimit:
		return 0, fmt.Errorf("statuslist: VerifyOptions.MaxTokenBytes is %d, not between 0 and %d", o.MaxTokenBytes, MaxTokenBytesLimit)
	case o.MaxTokenBytes == 0:
		return DefaultMaxTokenBytes, nil
	}
	return o.MaxTokenBytes, nil
}

// VerifyToken verifies a Status List Token's signature and typ header,
// and rejects an expired token (draft-14 §5.1 rule 2-3, §8.3 step 4c).
// It does not check sub against a specific Referenced Token — that's
// Check's job, since it needs the StatusListRef to compare against.
func VerifyToken(token string, pub crypto.PublicKey, alg oid4vci.JOSEAlg, opts VerifyOptions) (TokenClaims, error) {
	parsed, err := verifyToken(token, pub, alg, opts)
	if err != nil {
		return TokenClaims{}, err
	}
	return parsed.claims, nil
}

// parsedClaims are a Status List Token's claims as read from its
// payload, before they're checked against VerifyOptions: they depend on
// the token's bytes alone, so a Cache can keep them (tokenMemo).
type parsedClaims struct {
	claims TokenClaims
	iss    string
	nbf    *int64
}

// verifyToken is VerifyToken, with the claims as parsed.
func verifyToken(token string, pub crypto.PublicKey, alg oid4vci.JOSEAlg, opts VerifyOptions) (parsedClaims, error) {
	limit, err := opts.maxTokenBytes()
	if err != nil {
		return parsedClaims{}, err
	}
	header, raw, err := jose.VerifyMax(alg, pub, token, limit)
	if err != nil {
		return parsedClaims{}, fmt.Errorf("statuslist: verify token signature: %w", err)
	}
	// typ is a media type (RFC 7515 §4.1.9): matched case-insensitively,
	// with "application/" implied when it has no "/".
	typ, _ := header["typ"].(string)
	if !jose.TypeIs(typ, TokenMediaType) {
		return parsedClaims{}, fmt.Errorf("statuslist: token typ is %q, want %q", typ, TokenTyp)
	}
	return parseChecked(raw, parseJWTClaims, opts)
}

// parseChecked is raw parsed, once checked against opts.
func parseChecked(raw []byte, parse func([]byte) (parsedClaims, error), opts VerifyOptions) (parsedClaims, error) {
	parsed, err := parse(raw)
	if err != nil {
		return parsedClaims{}, err
	}
	if err := parsed.check(opts); err != nil {
		return parsedClaims{}, err
	}
	return parsed, nil
}

// parseJWTClaims reads a JWT Status List Token's verified payload.
func parseJWTClaims(raw []byte) (parsedClaims, error) {
	// NumericDates may be fractional (RFC 7519 §2), so they're read as
	// numbers; member names must match exactly (strictjson).
	var decoded struct {
		Iss        string     `json:"iss"`
		Sub        string     `json:"sub"`
		Iat        *float64   `json:"iat"`
		Exp        *float64   `json:"exp"`
		Nbf        *float64   `json:"nbf"`
		TTL        *int64     `json:"ttl"`
		StatusList StatusList `json:"status_list"`
	}
	if err := strictjson.Unmarshal(raw, &decoded); err != nil {
		return parsedClaims{}, fmt.Errorf("statuslist: unmarshal token claims: %w", err)
	}
	var times [3]*int64
	for i, v := range []*float64{decoded.Iat, decoded.Exp, decoded.Nbf} {
		if v == nil {
			continue
		}
		at, err := jwtdate.FromFloat(*v)
		if err != nil {
			return parsedClaims{}, fmt.Errorf("statuslist: token %s: %w", [3]string{"iat", "exp", "nbf"}[i], err)
		}
		unix := at.Unix()
		times[i] = &unix
	}
	var iat int64
	if times[0] != nil {
		iat = *times[0]
	}
	if decoded.Sub == "" {
		return parsedClaims{}, fmt.Errorf("statuslist: token is missing the required sub claim")
	}
	if decoded.TTL != nil && *decoded.TTL <= 0 {
		return parsedClaims{}, fmt.Errorf("statuslist: token ttl must be positive")
	}
	if !decoded.StatusList.Bits.valid() {
		return parsedClaims{}, fmt.Errorf("statuslist: token's status_list.bits is invalid")
	}
	return parsedClaims{
		claims: TokenClaims{
			Sub:        decoded.Sub,
			Iat:        iat,
			Exp:        times[1],
			TTL:        decoded.TTL,
			StatusList: decoded.StatusList,
		},
		iss: decoded.Iss,
		nbf: times[2],
	}, nil
}

// check checks p against opts: a token naming another issuer isn't
// this one's, and its times must hold at opts's Now.
func (p parsedClaims) check(opts VerifyOptions) error {
	if p.iss != "" && opts.Issuer != "" && p.iss != opts.Issuer {
		return fmt.Errorf("statuslist: token iss %q isn't the referenced token's issuer %q", p.iss, opts.Issuer)
	}
	return checkTokenTimes(p.claims.Iat, p.claims.Exp, p.nbf, opts)
}

// DefaultMaxAgeWithoutExp bounds how long ago a Status List Token with
// no exp may have been issued, when VerifyOptions.MaxAge is unset.
const DefaultMaxAgeWithoutExp = jwtdate.DefaultMaxAgeWithoutExp

// checkTokenTimes checks a Status List Token's iat, which draft-14
// §5.1 requires, exp and nbf, against opts at Now (jwtdate.Window).
func checkTokenTimes(iat int64, exp, nbf *int64, opts VerifyOptions) error {
	window := jwtdate.Window{MaxAge: opts.MaxAge, MaxClockSkew: opts.MaxClockSkew, RequireExp: opts.RequireExp}
	if err := window.Check(iat, exp, nbf, opts.now()); err != nil {
		return fmt.Errorf("statuslist: %w", err)
	}
	return nil
}

func (o VerifyOptions) now() time.Time {
	if o.Now == nil {
		return time.Now()
	}
	return o.Now()
}

// atOneInstant is opts with Now read once, so a token's times and its
// signer's certificates are checked at the same instant.
func (o VerifyOptions) atOneInstant() VerifyOptions {
	now := o.now()
	o.Now = func() time.Time { return now }
	return o
}

// validate refuses claims a Relying Party would refuse (draft-14 §5.1,
// §6.1): sub and iat are REQUIRED, ttl "MUST be a positive number",
// exp is after iat, and bits is 1, 2, 4 or 8.
func (claims TokenClaims) validate() error {
	switch {
	case claims.Sub == "":
		return fmt.Errorf("statuslist: TokenClaims.Sub is required")
	case claims.Iat <= 0:
		return fmt.Errorf("statuslist: TokenClaims.Iat is required")
	case claims.TTL != nil && *claims.TTL <= 0:
		return fmt.Errorf("statuslist: TokenClaims.TTL must be positive")
	case claims.Exp != nil && *claims.Exp <= claims.Iat:
		return fmt.Errorf("statuslist: TokenClaims.Exp must be after Iat")
	case !claims.StatusList.Bits.valid():
		return fmt.Errorf("statuslist: TokenClaims.StatusList.Bits is invalid")
	}
	return nil
}
