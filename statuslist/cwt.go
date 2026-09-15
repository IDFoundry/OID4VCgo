package statuslist

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcigo/internal/cose"
)

// CWTTokenMediaType is the media type a Status List Token in CWT format
// is served and requested as, and its COSE protected "typ" header
// value (label 16, RFC 9596) — draft-12 §5.2.
const CWTTokenMediaType = "application/statuslist+cwt" //nolint:gosec // a content-type/typ value, not a credential

// CWT claim keys (draft-12 §5.2, §6.3). sub/iat/exp are RFC 8392's
// standard CWT claims; ttl/statusList/status are this draft's own —
// "TBD (requested assignment ...)" in the IANA CWT Claims Registry as
// of this draft (§14.3.1), not yet a finalized registration. Update
// these if IANA assigns different values before this package is relied
// on in production.
const (
	cwtClaimSub        = 2
	cwtClaimExp        = 4
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

// cwtStatusList is draft-12 §4.3's StatusList CBOR structure — the same
// logical fields as StatusList, but Lst is a raw byte string rather
// than JSON's base64url-encoded text (§4.3 vs §4.1/§4.2).
type cwtStatusList struct {
	Bits           Bits   `cbor:"bits"`
	Lst            []byte `cbor:"lst"`
	AggregationURI string `cbor:"aggregation_uri,omitempty"`
}

func toCWTStatusList(sl StatusList) (cwtStatusList, error) {
	raw, err := base64.RawURLEncoding.DecodeString(sl.Lst)
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
// (draft-12 §5.2), as COSE_Sign1_Tagged (RFC 8392's CWT example uses
// the tagged form — see internal/cose.SignTagged). keyID sets the COSE
// "kid" header, if non-empty.
func IssueTokenCWT(signer crypto.Signer, alg cose.Alg, claims TokenClaims, keyID []byte) ([]byte, error) {
	if claims.Sub == "" {
		return nil, fmt.Errorf("statuslist: TokenClaims.Sub is required")
	}
	if !claims.StatusList.Bits.valid() {
		return nil, fmt.Errorf("statuslist: TokenClaims.StatusList.Bits is invalid")
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
		cose.Headers{Typ: CWTTokenMediaType, KID: keyID}, cose.Headers{},
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
func VerifyTokenCWT(token []byte, pub crypto.PublicKey, alg cose.Alg, opts VerifyOptions) (TokenClaims, error) {
	protected, _, raw, err := cose.VerifyTagged(alg, pub, token, nil)
	if err != nil {
		return TokenClaims{}, fmt.Errorf("statuslist: verify CWT signature: %w", err)
	}
	if protected.Typ != CWTTokenMediaType {
		return TokenClaims{}, fmt.Errorf("statuslist: CWT typ is %q, want %q", protected.Typ, CWTTokenMediaType)
	}

	var decoded map[int]interface{}
	if err := cbor.Unmarshal(raw, &decoded); err != nil {
		return TokenClaims{}, fmt.Errorf("statuslist: unmarshal CWT claims: %w", err)
	}

	claims, err := parseCWTClaims(decoded)
	if err != nil {
		return TokenClaims{}, err
	}
	if !claims.StatusList.Bits.valid() {
		return TokenClaims{}, fmt.Errorf("statuslist: token's status_list.bits is invalid")
	}

	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	if claims.Exp != nil && now().Unix() > *claims.Exp {
		return TokenClaims{}, fmt.Errorf("statuslist: token is expired")
	}

	return claims, nil
}

func parseCWTClaims(decoded map[int]interface{}) (TokenClaims, error) {
	sub, ok := decoded[cwtClaimSub].(string)
	if !ok || sub == "" {
		return TokenClaims{}, fmt.Errorf("statuslist: CWT is missing the required sub claim")
	}
	iat, err := toInt64Claim(decoded[cwtClaimIat])
	if err != nil {
		return TokenClaims{}, fmt.Errorf("statuslist: iat claim: %w", err)
	}

	var exp *int64
	if v, ok := decoded[cwtClaimExp]; ok {
		i, err := toInt64Claim(v)
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
	if err := cbor.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("statuslist: unmarshal CBOR value: %w", err)
	}
	return nil
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
