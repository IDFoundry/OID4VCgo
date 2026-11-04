package statuslist

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/idfoundry/oid4vcgo/internal/strictcbor"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/b64url"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jwtdate"
)

// CWTTokenMediaType is the media type a Status List Token in CWT format
// is served and requested as, and its COSE protected "typ" header
// value (label 16, RFC 9596) — draft-14 §5.2.
const CWTTokenMediaType = "application/statuslist+cwt" //nolint:gosec // a content-type/typ value, not a credential

// CWT claim keys (draft-14 §5.2, §6.3). sub/iat/exp are RFC 8392's
// standard CWT claims; ttl/statusList/status are this draft's own —
// "TBD (requested assignment ...)" in the IANA CWT Claims Registry as
// of this draft (§14.3.1), not yet a finalized registration. Update
// these if IANA assigns different values before this package is relied
// on in production.
const (
	cwtClaimIss        = 1
	cwtClaimSub        = 2
	cwtClaimExp        = 4
	cwtClaimNbf        = 5
	cwtClaimIat        = 6
	cwtClaimTTL        = 65534
	cwtClaimStatusList = 65533
)

// CWTClaimStatus is §6.3's CWT claim key for a Referenced Token's
// "status" claim ("TBD (requested assignment 65535)" — see the note
// above). Exported since a Referenced Token's own CWT claims set is
// built by its issuer (a future credential/mdoc or OID4VP CWT-format
// consumer), not by this package — StatusListRef.CWTStatusClaim gives
// that caller the claim's value; they assign it under this key
// themselves alongside whatever other claims their token carries.
const CWTClaimStatus = 65535

// cwtStatusList is draft-14 §4.3's StatusList CBOR structure — the same
// logical fields as StatusList, but Lst is a raw byte string rather
// than JSON's base64url-encoded text (§4.3 vs §4.1/§4.2).
type cwtStatusList struct {
	Bits           Bits   `cbor:"bits"`
	Lst            []byte `cbor:"lst"`
	AggregationURI string `cbor:"aggregation_uri,omitempty"`
}

func toCWTStatusList(sl StatusList) (cwtStatusList, error) {
	raw, err := b64url.Encoding{}.DecodeString(sl.Lst)
	if err != nil {
		return cwtStatusList{}, fmt.Errorf("statuslist: decode lst: %w", err)
	}
	return cwtStatusList{Bits: sl.Bits, Lst: raw, AggregationURI: sl.AggregationURI}, nil
}

func fromCWTStatusList(c cwtStatusList) StatusList {
	return StatusList{
		Bits:           c.Bits,
		Lst:            base64.RawURLEncoding.EncodeToString(c.Lst),
		AggregationURI: c.AggregationURI,
	}
}

// IssueTokenCWT signs claims into a Status List Token in CWT format
// (draft-14 §5.2), as COSE_Sign1_Tagged (RFC 8392's CWT example uses
// the tagged form — see internal/cose.SignTagged; draft-14 requires
// neither form, and VerifyTokenCWT accepts both). keyID sets the COSE
// "kid" header, if non-empty.
func IssueTokenCWT(signer crypto.Signer, alg oid4vci.COSEAlg, claims TokenClaims, keyID []byte) ([]byte, error) {
	return issueTokenCWT(signer, alg, claims, cose.Headers{Typ: CWTTokenMediaType, KID: keyID})
}

// issueTokenCWT signs claims into a Status List Token in CWT format with
// the given protected header.
func issueTokenCWT(signer crypto.Signer, alg cose.Alg, claims TokenClaims, protected cose.Headers) ([]byte, error) {
	if err := claims.validate(); err != nil {
		return nil, err
	}

	cwtSL, err := toCWTStatusList(claims.StatusList)
	if err != nil {
		return nil, err
	}

	payload := make(map[int]interface{}, len(claims.Additional)+4)
	payload[cwtClaimSub] = claims.Sub
	payload[cwtClaimIat] = claims.Iat
	if claims.Exp != nil {
		payload[cwtClaimExp] = *claims.Exp
	}
	if claims.TTL != nil {
		payload[cwtClaimTTL] = *claims.TTL
	}
	payload[cwtClaimStatusList] = cwtSL

	raw, err := cbor.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("statuslist: marshal CWT claims: %w", err)
	}

	sign1, err := cose.SignTagged(
		alg, signer,
		protected, cose.Headers{},
		raw, nil,
	)
	if err != nil {
		return nil, fmt.Errorf("statuslist: sign CWT: %w", err)
	}
	return sign1, nil
}

// VerifyTokenCWT verifies a Status List Token in CWT format's signature
// and typ header, and rejects an expired token — the CWT counterpart to
// VerifyToken. It does not check sub against a specific Referenced
// Token — that's Check's job.
func VerifyTokenCWT(token []byte, pub crypto.PublicKey, alg oid4vci.COSEAlg, opts VerifyOptions) (TokenClaims, error) {
	parsed, err := verifyTokenCWT(token, pub, alg, opts, nil)
	if err != nil {
		return TokenClaims{}, err
	}
	return parsed.claims, nil
}

// verifyTokenCWT is VerifyTokenCWT, given the claims parsed from the
// same token's bytes before when memo isn't nil, as verifyToken is for
// a JWT.
func verifyTokenCWT(token []byte, pub crypto.PublicKey, alg oid4vci.COSEAlg, opts VerifyOptions, memo *parsedClaims) (parsedClaims, error) {
	// COSE_Sign1, tagged (#6.18) or untagged; nothing else in front of
	// it, so a CWT tag (61) is refused. Draft-14 §5.2, which HAIP pins,
	// requires neither form, and its own example is untagged; draft-21
	// §5.2 requires COSE_Sign1_Tagged and forbids the CWT tag. Issuing
	// tagged meets both; verifying accepts what draft-14 allows, short
	// of the CWT tag, which no draft-14 example uses.
	// As large as a JWT Status List Token may be: a CWT list grows with
	// the credentials it covers just the same.
	limit, err := opts.maxTokenBytes()
	if err != nil {
		return parsedClaims{}, err
	}
	protected, _, raw, err := cose.VerifyMax(alg, pub, token, nil, limit)
	if err != nil {
		return parsedClaims{}, fmt.Errorf("statuslist: verify CWT signature: %w", err)
	}
	if !strings.EqualFold(protected.Typ, CWTTokenMediaType) {
		return parsedClaims{}, fmt.Errorf("statuslist: CWT typ is %q, want %q", protected.Typ, CWTTokenMediaType)
	}
	return parsedOrMemo(raw, memo, parseCWTPayload, opts)
}

// parseCWTPayload reads a CWT Status List Token's verified payload.
func parseCWTPayload(raw []byte) (parsedClaims, error) {
	var decoded map[int]interface{}
	if err := cwtDecMode.Unmarshal(raw, &decoded); err != nil {
		return parsedClaims{}, fmt.Errorf("statuslist: unmarshal CWT claims: %w", err)
	}

	claims, err := parseCWTClaims(decoded)
	if err != nil {
		return parsedClaims{}, err
	}
	if !claims.StatusList.Bits.valid() {
		return parsedClaims{}, fmt.Errorf("statuslist: token's status_list.bits is invalid")
	}
	// As for the JWT form, a token naming another issuer isn't this
	// one's (parsedClaims.check).
	parsed := parsedClaims{claims: claims}
	if v, ok := decoded[cwtClaimIss]; ok {
		iss, isString := v.(string)
		if !isString {
			return parsedClaims{}, fmt.Errorf("statuslist: CWT iss claim isn't a text string")
		}
		parsed.iss = iss
	}
	if v, ok := decoded[cwtClaimNbf]; ok {
		n, err := toNumericDateClaim(v)
		if err != nil {
			return parsedClaims{}, fmt.Errorf("statuslist: nbf claim: %w", err)
		}
		parsed.nbf = &n
	}
	return parsed, nil
}

func parseCWTClaims(decoded map[int]interface{}) (TokenClaims, error) {
	sub, ok := decoded[cwtClaimSub].(string)
	if !ok || sub == "" {
		return TokenClaims{}, fmt.Errorf("statuslist: CWT is missing the required sub claim")
	}
	iat, err := toNumericDateClaim(decoded[cwtClaimIat])
	if err != nil {
		return TokenClaims{}, fmt.Errorf("statuslist: iat claim: %w", err)
	}

	var exp *int64
	if v, ok := decoded[cwtClaimExp]; ok {
		i, err := toNumericDateClaim(v)
		if err != nil {
			return TokenClaims{}, fmt.Errorf("statuslist: exp claim: %w", err)
		}
		exp = &i
	}
	var ttl *int64
	if v, ok := decoded[cwtClaimTTL]; ok {
		i, err := toInt64Claim(v)
		if err != nil {
			return TokenClaims{}, fmt.Errorf("statuslist: ttl claim: %w", err)
		}
		if i <= 0 {
			return TokenClaims{}, fmt.Errorf("statuslist: ttl claim must be positive")
		}
		ttl = &i
	}

	slRaw, ok := decoded[cwtClaimStatusList]
	if !ok {
		return TokenClaims{}, fmt.Errorf("statuslist: CWT is missing the required status_list claim")
	}
	var sl cwtStatusList
	if err := decodeCBORValue(slRaw, &sl); err != nil {
		return TokenClaims{}, err
	}

	return TokenClaims{Sub: sub, Iat: iat, Exp: exp, TTL: ttl, StatusList: fromCWTStatusList(sl)}, nil
}

// decodeCBORValue re-encodes v — as cbor.Unmarshal into a
// map[int]interface{} or map[string]interface{} leaves a nested value,
// a generic map/slice rather than a concrete Go type — and decodes the
// result into out, to reuse fxamacker/cbor's own struct-tag matching
// rather than hand-walking the generic value.
func decodeCBORValue(v interface{}, out interface{}) error {
	raw, err := cbor.Marshal(v)
	if err != nil {
		return fmt.Errorf("statuslist: re-marshal CBOR value: %w", err)
	}
	if err := cwtDecMode.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("statuslist: unmarshal CBOR value: %w", err)
	}
	return nil
}

// toNumericDateClaim reads a CWT NumericDate (RFC 8392 §2: an integer
// or a floating-point number of seconds), dropping any fraction.
func toNumericDateClaim(v interface{}) (int64, error) {
	at, err := jwtdate.FromCBOR(v)
	if err != nil {
		return 0, err
	}
	return at.Unix(), nil
}

func toInt64Claim(v interface{}) (int64, error) {
	switch n := v.(type) {
	case int64:
		return n, nil
	case uint64:
		if n > 1<<62 {
			return 0, fmt.Errorf("integer %d is out of range", n)
		}
		return int64(n), nil
	default:
		return 0, fmt.Errorf("expected an integer, got %T", v)
	}
}

// cwtDecMode decodes a Status List Token's CWT claims: duplicate map
// keys are refused (RFC 8392 §7.2.1 has claims keys unique, and two
// "status_list" or "exp" entries would let a decoder pick either), a
// struct field matches only its exact key, and nesting is bounded. The
// claims' size is bounded already, by the signed token's.
var cwtDecMode = func() strictcbor.DecMode {
	mode, err := cbor.DecOptions{
		MaxNestedLevels:   16,
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		FieldNameMatching: cbor.FieldNameMatchingCaseSensitive,
	}.DecMode()
	if err != nil {
		panic(fmt.Sprintf("statuslist: build CBOR decoder: %v", err))
	}
	return strictcbor.Wrap(mode)
}()
