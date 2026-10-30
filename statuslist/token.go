package statuslist

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/certrevocation"
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
	Issuer string

	// IssuerKey is the public key that signed the Referenced Token: a
	// Status List Token signed with the same key is the issuer's own,
	// whatever names the certificates carry. Set without Issuer, it's
	// the only signer CheckX5C accepts, as for a Referenced Token with
	// no issuer name (draft-ietf-oauth-status-list §11.3's same-key
	// arrangement); a separate Status Issuer is then the caller's
	// LeafPolicy to accept.
	IssuerKey crypto.PublicKey
}

// maxTokenBytes is this package's own ceiling on the compact JWS
// jose.VerifyMax will parse, in place of jose.MaxCompactBytes's own
// smaller default — a Status List Token's payload embeds a
// population-sized compressed bit array (see bits.go's own
// maxDecompressedSize doc comment: even a 2^20-entry list decompresses
// to only 128 KiB, so its compressed, base64url-encoded form fits
// comfortably within this), and the token is fetched from a URI a
// credential names, which may point at a compromised or malicious
// issuer.
const maxTokenBytes = 1 << 20 // 1 MiB

// VerifyToken verifies a Status List Token's signature and typ header,
// and rejects an expired token (draft-14 §5.1 rule 2-3, §8.3 step 4c).
// It does not check sub against a specific Referenced Token — that's
// Check's job, since it needs the StatusListRef to compare against.
func VerifyToken(token string, pub crypto.PublicKey, alg oid4vci.JOSEAlg, opts VerifyOptions) (TokenClaims, error) {
	header, raw, err := jose.VerifyMax(alg, pub, token, maxTokenBytes)
	if err != nil {
		return TokenClaims{}, fmt.Errorf("statuslist: verify token signature: %w", err)
	}
	// typ is a media type (RFC 7515 §4.1.9): matched case-insensitively,
	// with "application/" implied when it has no "/".
	typ, _ := header["typ"].(string)
	if !jose.TypeIs(typ, TokenMediaType) {
		return TokenClaims{}, fmt.Errorf("statuslist: token typ is %q, want %q", typ, TokenTyp)
	}

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
		return TokenClaims{}, fmt.Errorf("statuslist: unmarshal token claims: %w", err)
	}
	var times [3]*int64
	for i, v := range []*float64{decoded.Iat, decoded.Exp, decoded.Nbf} {
		if v == nil {
			continue
		}
		at, err := jwtdate.FromFloat(*v)
		if err != nil {
			return TokenClaims{}, fmt.Errorf("statuslist: token %s: %w", [3]string{"iat", "exp", "nbf"}[i], err)
		}
		unix := at.Unix()
		times[i] = &unix
	}
	var iat int64
	if times[0] != nil {
		iat = *times[0]
	}
	if decoded.Sub == "" {
		return TokenClaims{}, fmt.Errorf("statuslist: token is missing the required sub claim")
	}
	if decoded.Iss != "" && opts.Issuer != "" && decoded.Iss != opts.Issuer {
		return TokenClaims{}, fmt.Errorf("statuslist: token iss %q isn't the referenced token's issuer %q", decoded.Iss, opts.Issuer)
	}
	if decoded.TTL != nil && *decoded.TTL <= 0 {
		return TokenClaims{}, fmt.Errorf("statuslist: token ttl must be positive")
	}
	if !decoded.StatusList.Bits.valid() {
		return TokenClaims{}, fmt.Errorf("statuslist: token's status_list.bits is invalid")
	}

	if err := checkTokenTimes(iat, times[1], times[2], opts); err != nil {
		return TokenClaims{}, err
	}

	return TokenClaims{
		Sub:        decoded.Sub,
		Iat:        iat,
		Exp:        times[1],
		TTL:        decoded.TTL,
		StatusList: decoded.StatusList,
	}, nil
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
